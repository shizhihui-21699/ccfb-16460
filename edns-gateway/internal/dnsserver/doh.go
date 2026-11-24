// Package dnsserver 实现 DoH/DoT/DoQ 三个加密 DNS 兼容前端，监听导流目标端口，
// 把解密后的 DNS 查询统一交给内部 Recursor，实现"加密形态进来、内部策略出去"。
package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/enterprise/edns-gateway/internal/resolver"
)

// DoHServer DNS over HTTPS (RFC 8484)。
//
// 端点：
//
//	GET  /dns-query?dns=<base64url wire msg>
//	POST /dns-query  Content-Type: application/dns-message
type DoHServer struct {
	server    *http.Server
	recursor  *resolver.Recursor
	log       *slog.Logger
	certFile  string
	keyFile   string
	tlsConfig *tls.Config
}

// NewDoH 构建 DoH 服务。
func NewDoH(listen, certFile, keyFile string, rec *resolver.Recursor, log *slog.Logger) (*DoHServer, error) {
	s := &DoHServer{recursor: rec, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handle)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// 非 DoH 路径返回 404，避免该端口被当作普通网站探测利用
		http.Error(w, "not found", http.StatusNotFound)
	})

	s.server = &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// 导流场景连接量可能很大，不设全局 IdleTimeout 过短
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    slogToStd(log),
	}
	if certFile != "" {
		// 证书路径在 Run 阶段加载，便于证书热轮换
		s.certFile, s.keyFile = certFile, keyFile
	}
	return s, nil
}

func (s *DoHServer) handle(w http.ResponseWriter, req *http.Request) {
	var wire []byte
	var err error
	switch req.Method {
	case http.MethodGet:
		// RFC 8484 §4.1：dns 参数为 URL-safe base64（无填充）
		wire, err = decodeBase64URL(req.URL.Query().Get("dns"))
	case http.MethodPost:
		if req.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		// RFC 8484 限制单消息 65535 字节，http.MaxBytesReader 防御超大 body
		req.Body = http.MaxBytesReader(w, req.Body, 65535)
		wire, err = io.ReadAll(req.Body)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(wire) == 0 {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}

	clientAddr := addrFromHTTP(req)
	resp, err := s.recursor.Exchange(req.Context(), wire, "doh", clientAddr)
	if err != nil {
		s.log.Warn("DoH 查询转发失败", "err", err, "client", req.RemoteAddr)
		http.Error(w, "resolver failure", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	// ECS 等策略由内部递归决定，前端不做改写
	if _, err := w.Write(resp); err != nil {
		s.log.Debug("DoH 响应写入中断", "err", err)
	}
}

// NewDoHWithTLS 使用外部 TLS 配置（如 pki.Mint 的动态签发配置）构建 DoH 服务。
func NewDoHWithTLS(listen string, tlsConf *tls.Config,
	rec *resolver.Recursor, log *slog.Logger) (*DoHServer, error) {
	s, err := NewDoH(listen, "", "", rec, log)
	if err != nil {
		return nil, err
	}
	s.tlsConfig = tlsConf
	return s, nil
}

// ServeListener 在给定 listener 上提供 HTTPS 服务（测试或透明代理复用端口时使用），
// 阻塞直到 ctx 取消后优雅关闭。
func (s *DoHServer) ServeListener(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("DoH 前端启动", "listen", ln.Addr())
		if s.tlsConfig != nil {
			s.server.TLSConfig = s.tlsConfig
			errCh <- s.server.ServeTLS(ln, "", "")
			return
		}
		if s.certFile != "" {
			errCh <- s.server.ServeTLS(ln, s.certFile, s.keyFile)
			return
		}
		errCh <- s.server.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Run 启动 HTTPS 监听，阻塞直到 ctx 取消后优雅关闭。
func (s *DoHServer) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("DoH 前端启动", "listen", s.server.Addr)
		if s.tlsConfig != nil {
			s.server.TLSConfig = s.tlsConfig
			// ListenAndServeTLS 传空证书名时使用 server.TLSConfig
			errCh <- s.server.ListenAndServeTLS("", "")
			return
		}
		if s.certFile != "" {
			errCh <- s.server.ListenAndServeTLS(s.certFile, s.keyFile)
			return
		}
		// 无证书时退化为 h2c，仅供本地测试；生产必须配置证书
		errCh <- s.server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// 证书字段（certFile/keyFile）支持在 Run 阶段加载，便于证书轮换。
