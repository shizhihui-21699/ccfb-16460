package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/enterprise/edns-gateway/internal/resolver"
)

// DoQServer DNS over QUIC (RFC 9250)。
//
// 线协议：QUIC 双向流内沿用 2 字节长度前缀的 DNS 分帧；每个查询一个流。
// ALPN 固定 "doq"，TLS 强制 1.3。
type DoQServer struct {
	listen    string
	certFile  string
	keyFile   string
	tlsConfig *tls.Config
	recursor  *resolver.Recursor
	log       *slog.Logger
	maxMsg    int

	listener *quic.Listener
	ready    chan struct{} // listener 就绪后关闭，避免读 listener 的数据竞争
}

// Ready 返回 listener 就绪信号通道。
func (s *DoQServer) Ready() <-chan struct{} { return s.ready }

// NewDoQ 构建 DoQ 服务（静态证书文件模式）。
func NewDoQ(listen, certFile, keyFile string, maxMsg int,
	rec *resolver.Recursor, log *slog.Logger) *DoQServer {
	if maxMsg <= 0 {
		maxMsg = 65535
	}
	return &DoQServer{
		listen:   listen,
		certFile: certFile,
		keyFile:  keyFile,
		recursor: rec,
		log:      log,
		maxMsg:   maxMsg,
		ready:    make(chan struct{}),
	}
}

// NewDoQWithConfig 使用外部 TLS 配置（pki.Mint 动态签发）构建 DoQ 服务。
func NewDoQWithConfig(listen string, tlsConf *tls.Config, maxMsg int,
	rec *resolver.Recursor, log *slog.Logger) *DoQServer {
	if maxMsg <= 0 {
		maxMsg = 65535
	}
	return &DoQServer{
		listen:    listen,
		tlsConfig: tlsConf,
		recursor:  rec,
		log:       log,
		maxMsg:    maxMsg,
		ready:     make(chan struct{}),
	}
}

// Run 加载证书并阻塞服务。
func (s *DoQServer) Run(ctx context.Context) error {
	var tlsConf *tls.Config
	if s.tlsConfig != nil {
		// DoQ 强制 TLS 1.3 与 doq ALPN，即使外部配置也要兜底
		tlsConf = s.tlsConfig.Clone()
		tlsConf.MinVersion = tls.VersionTLS13
		if len(tlsConf.NextProtos) == 0 {
			tlsConf.NextProtos = []string{"doq"}
		}
	} else {
		cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
		if err != nil {
			return err
		}
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13, // DoQ 强制 TLS 1.3
			NextProtos:   []string{"doq"},
		}
	}
	qConf := &quic.Config{
		MaxIdleTimeout:       time.Minute,
		MaxIncomingStreams:   256,
		HandshakeIdleTimeout: 5 * time.Second,
	}
	ln, err := quic.ListenAddr(s.listen, tlsConf, qConf)
	if err != nil {
		return err
	}
	s.listener = ln
	close(s.ready) // 发布 listener，与测试/调用方的 Addr 读取建立 happens-before
	s.log.Info("DoQ 前端启动", "listen", s.listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("DoQ accept 失败", "err", err)
			continue
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *DoQServer) serveConn(ctx context.Context, conn *quic.Conn) {
	remote := conn.RemoteAddr()
	clientAddr := addrFromNet(remote)
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return // 连接关闭
		}
		go func(st *quic.Stream) {
			defer st.Close()
			_ = st.SetReadDeadline(time.Now().Add(30 * time.Second))
			wire, err := readLenPrefixed(io.LimitReader(st, int64(s.maxMsg)))
			if err != nil {
				s.log.Debug("DoQ 读流失败", "err", err, "remote", remote)
				return
			}
			resp, err := s.recursor.Exchange(ctx, wire, "doq", clientAddr)
			if err != nil {
				s.log.Warn("DoQ 查询转发失败", "err", err)
				st.CancelRead(0x2) // DOQ_MALFORMED_DATA 近似处理
				return
			}
			if err := writeLenPrefixed(st, resp); err != nil {
				s.log.Debug("DoQ 写流失败", "err", err)
			}
		}(stream)
	}
}

// 确保 netip 被使用（addrFromNet 在 dot.go 定义，这里仅保留显式引用以防重构）
var _ = netip.Addr{}
