package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/enterprise/edns-gateway/internal/resolver"
)

// DoTServer DNS over TLS (RFC 7858)。
//
// 线协议：TLS 隧道内沿用 DNS over TCP 的 2 字节长度前缀分帧。
// ALPN 通告 "dot"，与客户端 ClientHello 中的识别特征保持一致。
type DoTServer struct {
	listen    string
	certFile  string
	keyFile   string
	tlsConfig *tls.Config
	recursor  *resolver.Recursor
	log       *slog.Logger

	listener net.Listener
	ready    chan struct{}
}

// Ready 返回 listener 就绪信号通道。
func (s *DoTServer) Ready() <-chan struct{} { return s.ready }

// NewDoT 构建 DoT 服务（静态证书文件模式）。
func NewDoT(listen, certFile, keyFile string, rec *resolver.Recursor, log *slog.Logger) *DoTServer {
	return &DoTServer{
		listen:   listen,
		certFile: certFile,
		keyFile:  keyFile,
		recursor: rec,
		log:      log,
		ready:    make(chan struct{}),
	}
}

// NewDoTWithConfig 使用外部 TLS 配置（pki.Mint 动态签发）构建 DoT 服务。
func NewDoTWithConfig(listen string, tlsConf *tls.Config,
	rec *resolver.Recursor, log *slog.Logger) *DoTServer {
	return &DoTServer{
		listen:    listen,
		tlsConfig: tlsConf,
		recursor:  rec,
		log:       log,
		ready:     make(chan struct{}),
	}
}

// Run 加载证书并阻塞服务，直到 ctx 取消。
func (s *DoTServer) Run(ctx context.Context) error {
	var tlsConf *tls.Config
	if s.tlsConfig != nil {
		tlsConf = s.tlsConfig
	} else {
		cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
		if err != nil {
			return err
		}
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"dot"},
		}
	}
	ln, err := tls.Listen("tcp", s.listen, tlsConf)
	if err != nil {
		return err
	}
	s.listener = ln
	close(s.ready) // 发布 listener，与调用方 Addr 读取建立 happens-before
	s.log.Info("DoT 前端启动", "listen", s.listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("DoT accept 失败", "err", err)
			continue
		}
		go s.serve(conn)
	}
}

func (s *DoTServer) serve(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	// 显式握手以便记录 SNI 与握手失败
	if err := tlsConn.Handshake(); err != nil {
		s.log.Debug("DoT 握手失败", "remote", conn.RemoteAddr(), "err", err)
		return
	}

	clientAddr := addrFromNet(conn.RemoteAddr())
	// 一条连接上可能承载多个查询（RFC 7858 允许复用），循环读分帧
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		wire, err := readLenPrefixed(conn)
		if err != nil {
			if err != io.EOF {
				s.log.Debug("DoT 读帧结束", "err", err)
			}
			return
		}
		resp, err := s.recursor.Exchange(context.Background(), wire, "dot", clientAddr)
		if err != nil {
			s.log.Warn("DoT 查询转发失败", "err", err)
			return
		}
		if err := writeLenPrefixed(conn, resp); err != nil {
			return
		}
	}
}

// readLenPrefixed 读取 DNS over TCP 的 2 字节长度前缀报文。
func readLenPrefixed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeLenPrefixed(w io.Writer, msg []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func addrFromNet(addr net.Addr) netip.Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr()
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.AddrPort().Addr()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}
	}
	a, _ := netip.ParseAddr(host)
	return a
}
