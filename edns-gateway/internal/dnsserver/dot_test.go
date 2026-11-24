package dnsserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/resolver"
)

// writeTestCert 生成自签名证书并落盘，返回 cert/key 路径。
func writeTestCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "edge-dns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"edge-dns.test", "dns.google"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = cf.Close()
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_ = kf.Close()
	return certPath, keyPath
}

// stubUpstream 本地明文 DNS 桩。
func stubUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 198.51.100.42")
		resp.Answer = append(resp.Answer, rr)
		_ = w.WriteMsg(resp)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDoT_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCert(t, dir)
	rec := resolver.New(config.ResolverConfig{
		Upstream: stubUpstream(t), Timeout: config.Duration{Duration: 2 * time.Second},
	})
	srv := NewDoT("127.0.0.1:0", certPath, keyPath, rec, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("DoT listener 未就绪")
	}

	// 通过 Ready 通道同步后再读取实际监听地址
	addr := srv.listener.Addr().String()
	conf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatalf("DoT 拨号失败: %v", err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "dot" {
		t.Errorf("ALPN 协商=%q，期望 dot", conn.ConnectionState().NegotiatedProtocol)
	}

	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	wire, _ := q.Pack()
	if err := writeLenPrefixed(conn, wire); err != nil {
		t.Fatal(err)
	}
	respWire, err := readLenPrefixed(conn)
	if err != nil {
		t.Fatal(err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) == 0 || resp.Answer[0].(*dns.A).A.String() != "198.51.100.42" {
		t.Errorf("DoT 响应异常: %+v", resp.Answer)
	}
}
