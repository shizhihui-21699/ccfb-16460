package resolver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enterprise/edns-gateway/internal/config"
)

// startStubUpstream 启动一个本地明文 DNS 服务，模拟企业内部递归。
func startStubUpstream(t *testing.T, blockDomain string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		if q.Name == blockDomain+"." {
			// 模拟内部恶意域名拦截：返回 NXDOMAIN
			resp.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(resp)
			return
		}
		rr, err := dns.NewRR(q.Name + " 60 IN A 192.0.2.55")
		if err != nil {
			t.Fatal(err)
		}
		resp.Answer = append(resp.Answer, rr)
		_ = w.WriteMsg(resp)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestRecursor_ForwardAndBlock(t *testing.T) {
	upstream := startStubUpstream(t, "malicious.example")
	rec := New(config.ResolverConfig{
		Upstream: upstream,
		Timeout:  config.Duration{Duration: 2 * time.Second},
	})

	// 正常域名应解析到桩地址
	q := new(dns.Msg)
	q.SetQuestion("allowed.example.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	respWire, err := rec.Exchange(context.Background(), wire, "doh", netip.MustParseAddr("10.0.0.10"))
	if err != nil {
		t.Fatalf("转发失败: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Errorf("正常查询应成功且带答案，rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}

	// 恶意域名应被上游拦截为 NXDOMAIN
	q2 := new(dns.Msg)
	q2.SetQuestion("malicious.example.", dns.TypeA)
	wire2, _ := q2.Pack()
	respWire2, err := rec.Exchange(context.Background(), wire2, "dot", netip.MustParseAddr("10.0.0.10"))
	if err != nil {
		t.Fatal(err)
	}
	resp2 := new(dns.Msg)
	_ = resp2.Unpack(respWire2)
	if resp2.Rcode != dns.RcodeNameError {
		t.Errorf("恶意域名应返回 NXDOMAIN，实际 rcode=%d", resp2.Rcode)
	}

	queries, _, blocked, _ := rec.Snapshot()
	if queries != 2 {
		t.Errorf("查询计数=%d，期望 2", queries)
	}
	if blocked != 1 {
		t.Errorf("拦截计数=%d，期望 1", blocked)
	}
}

func TestRecursor_RejectsMalformedDNS(t *testing.T) {
	rec := New(config.ResolverConfig{
		Upstream: "127.0.0.1:1", Timeout: config.Duration{Duration: time.Second},
	})
	if _, err := rec.Exchange(context.Background(), []byte{0, 1, 2}, "doh", netip.Addr{}); err == nil {
		t.Error("畸形 DNS 报文应返回错误")
	}
}
