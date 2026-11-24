package dnsserver

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/resolver"
)

func TestDoQ_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCert(t, dir)
	rec := resolver.New(config.ResolverConfig{
		Upstream: stubUpstream(t), Timeout: config.Duration{Duration: 2 * time.Second},
	})
	srv := NewDoQ("127.0.0.1:0", certPath, keyPath, 65535, rec, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("DoQ listener 未就绪")
	}

	addr := srv.listener.Addr().String()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("DoQ 拨号失败: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if state := conn.ConnectionState().TLS; state.NegotiatedProtocol != "doq" {
		t.Errorf("ALPN=%q，期望 doq", state.NegotiatedProtocol)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	wire, _ := q.Pack()
	if err := writeLenPrefixed(stream, wire); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	respWire, err := readLenPrefixed(io.LimitReader(stream, 65535))
	if err != nil {
		t.Fatalf("读 DoQ 响应失败: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) == 0 || resp.Answer[0].(*dns.A).A.String() != "198.51.100.42" {
		t.Errorf("DoQ 响应异常: %+v", resp.Answer)
	}
}
