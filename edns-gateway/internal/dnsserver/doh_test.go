package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/resolver"
)

func TestDoH_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCert(t, dir)
	rec := resolver.New(config.ResolverConfig{
		Upstream: stubUpstream(t), Timeout: config.Duration{Duration: 2 * time.Second},
	})

	// 监听随机端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewDoH(ln.Addr().String(), certPath, keyPath, rec, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeListener(ctx, ln) }()
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	wire, _ := q.Pack()

	// POST 方式（RFC 8484）
	url := "https://" + ln.Addr().String() + "/dns-query"
	resp, err := client.Post(url, "application/dns-message", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("DoH POST 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DoH 状态码=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("Content-Type=%q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answer) == 0 {
		t.Error("DoH POST 未返回答案")
	}

	// GET 方式（base64url dns 参数）
	getURL := url + "?dns=" + base64.RawURLEncoding.EncodeToString(wire)
	gresp, err := client.Get(getURL)
	if err != nil {
		t.Fatalf("DoH GET 失败: %v", err)
	}
	defer gresp.Body.Close()
	if gresp.StatusCode != http.StatusOK {
		t.Fatalf("DoH GET 状态码=%d", gresp.StatusCode)
	}
	gbody, _ := io.ReadAll(gresp.Body)
	gmsg := new(dns.Msg)
	if err := gmsg.Unpack(gbody); err != nil {
		t.Fatal(err)
	}
	if len(gmsg.Answer) == 0 {
		t.Error("DoH GET 未返回答案")
	}
}

func TestDoH_RejectsBadContentType(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCert(t, dir)
	rec := resolver.New(config.ResolverConfig{
		Upstream: stubUpstream(t), Timeout: config.Duration{Duration: 2 * time.Second},
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv, _ := NewDoH(ln.Addr().String(), certPath, keyPath, rec, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeListener(ctx, ln) }()
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Post("https://"+ln.Addr().String()+"/dns-query",
		"text/plain", bytes.NewReader([]byte{1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("错误 Content-Type 应返回 415，实际 %d", resp.StatusCode)
	}
}
