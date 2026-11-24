package classify

import (
	"net/netip"
	"testing"

	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/core"
	"github.com/enterprise/edns-gateway/internal/intel"
)

func testEngine(t *testing.T, pol config.PolicyConfig, det config.DetectConfig) *Engine {
	t.Helper()
	store := intel.NewStore(true)
	return NewEngine(store, nil,
		func() *config.DetectConfig { return &det },
		func() *config.PolicyConfig { return &pol })
}

func baseDetect() config.DetectConfig {
	return config.DetectConfig{
		BlockThreshold: 90, RedirectThreshold: 60, ObserveThreshold: 25,
		BehaviorMinSamples: 4, BehaviorShortSNIRatio: 0.8,
	}
}

func basePolicy() config.PolicyConfig {
	return config.PolicyConfig{
		DefaultAction: config.ActionRedirect,
		DohAction:     config.ActionRedirect,
		DotAction:     config.ActionRedirect,
		DoqAction:     config.ActionRedirect,
		UnknownAction: config.ActionObserve,
	}
}

func TestClassify_DoT_ALPN(t *testing.T) {
	e := testEngine(t, basePolicy(), baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP: netip.MustParseAddr("10.0.0.10"), DstIP: netip.MustParseAddr("9.9.9.9"),
			DstPort: 853, Protocol: core.TransportTCP,
		},
		Hello: &core.ClientHelloInfo{SNI: "dns.quad9.net", ALPN: []string{"dot"}},
	}
	v := e.Classify(obs)
	if v.Protocol != core.ProtoDoT {
		t.Errorf("协议 = %s，期望 DoT", v.Protocol)
	}
	if v.Score < 60 {
		t.Errorf("ALPN=dot + 853 + 情报命中应达导流阈值，实际分数 %d", v.Score)
	}
	if v.Action != string(config.ActionRedirect) {
		t.Errorf("动作 = %s，期望 redirect", v.Action)
	}
}

func TestClassify_DoQ(t *testing.T) {
	e := testEngine(t, basePolicy(), baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP:   netip.MustParseAddr("10.0.0.10"),
			DstIP:   netip.MustParseAddr("8.8.8.8"),
			DstPort: 8853, Protocol: core.TransportUDP,
		},
		Hello: &core.ClientHelloInfo{SNI: "dns.google", ALPN: []string{"doq"}, JA4: "q13d1..."},
	}
	v := e.Classify(obs)
	if v.Protocol != core.ProtoDoQ {
		t.Errorf("协议 = %s，期望 DoQ", v.Protocol)
	}
	if v.Action != string(config.ActionRedirect) {
		t.Errorf("动作 = %s，期望 redirect", v.Action)
	}
}

func TestClassify_DoHPath(t *testing.T) {
	e := testEngine(t, basePolicy(), baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP:   netip.MustParseAddr("10.0.0.10"),
			DstIP:   netip.MustParseAddr("1.1.1.1"),
			DstPort: 443, Protocol: core.TransportTCP,
		},
		Hello: &core.ClientHelloInfo{SNI: "cloudflare-dns.com", ALPN: []string{"h2"}},
		HTTP2: &core.HTTP2Info{
			Method: "POST", Path: "/dns-query",
			ContentType: "application/dns-message",
		},
	}
	v := e.Classify(obs)
	if v.Protocol != core.ProtoDoH {
		t.Errorf("协议 = %s，期望 DoH", v.Protocol)
	}
	// :path=/dns-query 是决定性证据，分数应很高
	if v.Score < 90 {
		t.Errorf("DoH 路径坐实应达阻断阈值，实际 %d", v.Score)
	}
}

func TestClassify_AllowlistBypass(t *testing.T) {
	pol := basePolicy()
	pol.AllowSNI = []string{"dns.quad9.net"}
	e := testEngine(t, pol, baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP: netip.MustParseAddr("10.0.0.10"),
			DstIP: netip.MustParseAddr("9.9.9.9"), DstPort: 853,
			Protocol: core.TransportTCP,
		},
		Hello: &core.ClientHelloInfo{SNI: "dns.quad9.net", ALPN: []string{"dot"}},
	}
	v := e.Classify(obs)
	if v.Action != string(config.ActionAllowlist) {
		t.Errorf("白名单 SNI 应豁免，实际动作 %s", v.Action)
	}
}

func TestClassify_AllowlistCIDR(t *testing.T) {
	pol := basePolicy()
	pol.AllowCIDR = []string{"9.9.9.0/24"}
	e := testEngine(t, pol, baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP: netip.MustParseAddr("10.0.0.10"),
			DstIP: netip.MustParseAddr("9.9.9.9"), DstPort: 853,
			Protocol: core.TransportTCP,
		},
		Hello: &core.ClientHelloInfo{SNI: "dns.quad9.net", ALPN: []string{"dot"}},
	}
	v := e.Classify(obs)
	if v.Action != string(config.ActionAllowlist) {
		t.Errorf("白名单 CIDR 应豁免，实际 %s", v.Action)
	}
}

func TestClassify_OrdinaryHTTPSNotFlagged(t *testing.T) {
	e := testEngine(t, basePolicy(), baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP: netip.MustParseAddr("10.0.0.10"),
			DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 443,
			Protocol: core.TransportTCP,
		},
		// 普通网站：非解析器 SNI、无 dot/doq ALPN、无 dns-query 路径
		Hello: &core.ClientHelloInfo{SNI: "www.example.com", ALPN: []string{"h2", "http/1.1"}},
		HTTP2: &core.HTTP2Info{Method: "GET", Path: "/index.html"},
	}
	v := e.Classify(obs)
	if v.Score >= 25 {
		t.Errorf("普通 HTTPS 不应达到观察阈值，分数 %d", v.Score)
	}
	if v.Protocol != core.ProtoUnknown {
		t.Errorf("普通 HTTPS 协议应为 unknown，实际 %s", v.Protocol)
	}
}

func TestClassify_BlockPolicyRespected(t *testing.T) {
	pol := basePolicy()
	pol.DotAction = config.ActionBlock
	e := testEngine(t, pol, baseDetect())
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP: netip.MustParseAddr("10.0.0.10"),
			DstIP: netip.MustParseAddr("9.9.9.9"), DstPort: 853,
			Protocol: core.TransportTCP,
		},
		Hello: &core.ClientHelloInfo{SNI: "dns.quad9.net", ALPN: []string{"dot"}},
	}
	v := e.Classify(obs)
	if v.Action != string(config.ActionBlock) {
		t.Errorf("显式 block 策略应被执行，实际 %s", v.Action)
	}
}
