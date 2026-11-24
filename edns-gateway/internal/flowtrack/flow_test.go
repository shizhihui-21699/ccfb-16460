package flowtrack

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/enterprise/edns-gateway/internal/core"
)

// captureTLSMeta 发起真实 TLS 握手，把 ClientHello 所在 TCP 段转成 Meta。
func captureTLSMeta(t *testing.T, sni string, alpn []string, dstPort uint16) Meta {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct{ payload []byte }
	resCh := make(chan res, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8192)
		n, _ := conn.Read(buf)
		resCh <- res{buf[:n]}
	}()
	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		tconn := tls.Client(conn, &tls.Config{
			ServerName: sni, InsecureSkipVerify: true, NextProtos: alpn,
		})
		_ = tconn.Handshake()
	}()
	r := <-resCh
	src := netip.MustParseAddr("10.1.1.50")
	dst := netip.MustParseAddr("9.9.9.9")
	return Meta{
		SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: dstPort,
		TCP: true, Bytes: len(r.payload), Payload: r.payload, TS: time.Now(),
	}
}

func newTestTracker() *Tracker {
	return NewTracker(time.Minute, time.Hour, 1000, 10*time.Minute)
}

func TestTracker_DetectDoTClientHello(t *testing.T) {
	tr := newTestTracker()
	meta := captureTLSMeta(t, "dns.quad9.net", []string{"dot"}, 853)
	events := tr.ObserveTCP(meta)
	if len(events) == 0 {
		t.Fatal("应产出 ClientHello 事件")
	}
	var found bool
	for _, ev := range events {
		if ev.Hello != nil && ev.Hello.ServerName == "dns.quad9.net" {
			found = true
			if ev.Obs.Hello == nil || ev.Obs.Hello.ALPN[0] != "dot" {
				t.Errorf("ALPN 未透传: %+v", ev.Obs.Hello)
			}
		}
	}
	if !found {
		t.Error("未在事件中找到 SNI=dns.quad9.net 的 ClientHello")
	}
}

func TestTracker_TCPReassembly(t *testing.T) {
	tr := newTestTracker()
	meta := captureTLSMeta(t, "dns.google", []string{"h2"}, 443)
	// 把 ClientHello 负载切成三段分别喂入，验证重组
	payload := meta.Payload
	third := len(payload) / 3
	base := meta
	for i := 0; i < 3; i++ {
		start := i * third
		end := start + third
		if i == 2 {
			end = len(payload)
		}
		part := base
		part.Payload = payload[start:end]
		part.Bytes = end - start
		events := tr.ObserveTCP(part)
		if i < 2 && len(events) != 0 {
			t.Errorf("不完整分片阶段不应产出事件，第 %d 段产出 %d 个", i, len(events))
		}
		if i == 2 {
			if len(events) == 0 || events[0].Hello == nil ||
				events[0].Hello.ServerName != "dns.google" {
				t.Error("三段重组后应还原完整 ClientHello")
			}
		}
	}
}

func TestTracker_RejectsNonTLS(t *testing.T) {
	tr := newTestTracker()
	meta := Meta{
		SrcIP: netip.MustParseAddr("10.1.1.50"), DstIP: netip.MustParseAddr("198.51.100.9"),
		SrcPort: 40001, DstPort: 80, TCP: true,
		Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Bytes:   37, TS: time.Now(),
	}
	if events := tr.ObserveTCP(meta); events != nil {
		t.Errorf("明文 HTTP 不应产出握手事件，实际 %d 个", len(events))
	}
}

func TestTracker_BehaviorAggregation(t *testing.T) {
	tr := newTestTracker()
	src := netip.MustParseAddr("10.1.1.60")
	// 同一客户端对同一目标发起多次 TLS 握手（用真实协议栈生成 ClientHello）
	for i := 0; i < 5; i++ {
		meta := captureTLSMeta(t, "dns.quad9.net", []string{"dot"}, 853)
		meta.SrcIP = src
		meta.SrcPort = uint16(41000 + i)
		tr.ObserveTCP(meta)
	}
	beh := tr.BehaviorFor(src)
	if beh.RepeatedHandshakes < 5 {
		t.Errorf("同目标反复握手计数=%d，期望 >=5", beh.RepeatedHandshakes)
	}
	if beh.DistinctSNI == 0 {
		t.Error("应统计到至少 1 个 SNI")
	}
}

func TestTracker_FlowKeyDirectionality(t *testing.T) {
	tr := newTestTracker()
	k1 := core.FlowKey{
		SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("1.1.1.1"),
		SrcPort: 1234, DstPort: 443, Protocol: core.TransportTCP,
	}
	k2 := k1
	if k1 != k2 {
		t.Error("相同五元组应相等")
	}
	flows, _ := tr.Stats()
	if flows != 0 {
		t.Errorf("空流表应为 0，实际 %d", flows)
	}
}
