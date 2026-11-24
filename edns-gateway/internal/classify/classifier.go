// Package classify 将协议解析信号、情报命中与行为特征融合为加密 DNS 判定，
// 输出带置信度的结论和策略动作。
//
// 评分模型（权重可在一处审视与调优）：
//
//	强坐实信号（协议本身声明用途）：ALPN=dot/doq、HTTP/2 :path=/dns-query
//	强环境信号：SNI 命中已知公共解析器域名、853 端口 + TLS
//	辅助信号：目的 IP 情报、JA4 黑名单、ECH、QUIC 无 h3、行为模式
//
// 阈值三档对应 observe / redirect / block，策略动作再按协议与白名单覆盖。
package classify

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/core"
	"github.com/enterprise/edns-gateway/internal/intel"
	"github.com/enterprise/edns-gateway/internal/protocol"
)

// 信号权重表：集中管理，便于审计与调参。
const (
	wALPNDoT        = 45 // ALPN=dot 是协议级自声明
	wALPNDoQ        = 45
	wDoHPath        = 50 // :path=/dns-query 是 DoH 的决定性证据
	wDoHContentType = 15
	wSNIIntel       = 35 // 稳定锚点：解析器域名不随 IP 变
	wIPIntel        = 15 // IP 会变，只作辅助
	wDoTPort        = 20 // 853 是 IANA 分配的 DoT 端口
	wQUICNoH3       = 12
	wECH            = 8 // ECH 隐藏 SNI，可疑但非 DoH 独有
	wBehavior       = 20
	wJA4Block       = 40
	wALPNH2Generic  = 5
)

// Engine 分类引擎。
type Engine struct {
	intel *intel.Store

	mu          sync.RWMutex
	allowSNI    map[string]struct{}
	blockSNI    map[string]struct{}
	allowPrefix []netip.Prefix
	blockPrefix []netip.Prefix
	ja4Block    map[string]struct{}

	behavior BehaviorProvider
	cfg      func() *config.DetectConfig
	policy   func() *config.PolicyConfig
}

// BehaviorProvider 由流表实现，提供每客户端聚合行为。
type BehaviorProvider interface {
	BehaviorFor(src netip.Addr) core.BehaviorSignals
}

// NewEngine 从当前配置构建分类引擎。
func NewEngine(store *intel.Store, beh BehaviorProvider,
	cfg func() *config.DetectConfig, pol func() *config.PolicyConfig) *Engine {
	e := &Engine{
		intel:    store,
		behavior: beh,
		cfg:      cfg,
		policy:   pol,
	}
	e.ReloadLists()
	return e
}

// ReloadLists 配置热更新后重建名单。
func (e *Engine) ReloadLists() {
	pol := e.policy()
	det := e.cfg()
	e.mu.Lock()
	defer e.mu.Unlock()

	e.allowSNI = toSet(pol.AllowSNI)
	e.blockSNI = toSet(pol.BlockSNI)
	e.allowPrefix = parsePrefixes(pol.AllowCIDR)
	e.blockPrefix = parsePrefixes(pol.BlockCIDR)
	e.ja4Block = make(map[string]struct{}, len(det.JA4Blocklist))
	for _, j := range det.JA4Blocklist {
		e.ja4Block[strings.ToLower(j)] = struct{}{}
	}
}

// Classify 对一条流观测执行完整判定。
func (e *Engine) Classify(obs *core.FlowObservation) *core.Verdict {
	signals := make([]core.Signal, 0, 8)
	score := 0
	proto := core.ProtoUnknown

	add := func(kind core.SignalKind, detail string, w int) {
		signals = append(signals, core.Signal{Kind: kind, Detail: detail, Weight: w})
		score += w
	}

	hello := obs.Hello
	isUDP := obs.Key.Protocol == core.TransportUDP

	// ---- 1. 名单前置检查（最高优先级，保证业务软件豁免）----
	if hello != nil {
		if _, ok := e.allowSNI[strings.ToLower(hello.SNI)]; ok {
			return e.verdict(obs, core.ProtoUnknown, 0, signals,
				string(config.ActionAllowlist), "SNI 命中白名单")
		}
		if _, ok := e.blockSNI[strings.ToLower(hello.SNI)]; ok {
			add(core.SigSNIIntel, "block_sni 强制名单: "+hello.SNI, wSNIIntel)
		}
		if _, ok := e.ja4Block[strings.ToLower(hello.JA4)]; ok {
			add(core.SigJA4Block, hello.JA4, wJA4Block)
		}
	}
	if e.matchPrefix(e.allowPrefix, obs.Key.DstIP) {
		return e.verdict(obs, core.ProtoUnknown, 0, signals,
			string(config.ActionAllowlist), "目的 IP 命中白名单 CIDR")
	}
	blockByCIDR := e.matchPrefix(e.blockPrefix, obs.Key.DstIP)
	if blockByCIDR {
		add(core.SigIPIntel, "block_cidr 强制名单", wIPIntel+10)
	}

	// ---- 2. SNI / IP 情报 ----
	if hello != nil && hello.SNI != "" {
		if r, ok := e.intel.LookupDomain(hello.SNI); ok {
			add(core.SigSNIIntel,
				r.Provider+" 解析器域名: "+r.Matched, wSNIIntel)
		}
	}
	if r, ok := e.intel.LookupAddr(obs.Key.DstIP); ok {
		add(core.SigIPIntel, r.Provider+" 解析器 IP: "+r.Matched, wIPIntel)
	}

	// ---- 3. 协议级强信号 ----
	if hello != nil {
		for _, alpn := range hello.ALPN {
			switch alpn {
			case "dot":
				add(core.SigALPDot, "ALPN=dot", wALPNDoT)
				proto = core.ProtoDoT
			case "doq":
				add(core.SigALPDoQ, "ALPN=doq", wALPNDoQ)
				proto = core.ProtoDoQ
			case "h2":
				add(core.SigALPDoH, "ALPN=h2（DoH 承载前提）", wALPNH2Generic)
			}
		}
		if hello.ECHPresent {
			add(core.SigECH, "ECH 外层 SNI: "+hello.ECHOuterSNI, wECH)
		}
	}

	// HTTP/2 路径坐实 DoH
	if obs.HTTP2 != nil {
		if protocol.IsDoHPath(obs.HTTP2.Path) {
			add(core.SigDoHPath, obs.HTTP2.Method+" "+obs.HTTP2.Path, wDoHPath)
			proto = core.ProtoDoH
			if strings.Contains(obs.HTTP2.ContentType, "application/dns-message") {
				add(core.SigDoHContentType, obs.HTTP2.ContentType, wDoHContentType)
			}
		}
	}

	// DoT 端口
	if !isUDP && obs.Key.DstPort == 853 {
		add(core.SigDoTPort, "TCP/853 (DoT IANA 端口)", wDoTPort)
		if proto == core.ProtoUnknown {
			proto = core.ProtoDoT
		}
	}

	// QUIC 但 ALPN 不含 h3：DoQ 客户端的典型形态
	if isUDP && hello != nil && !contains(hello.ALPN, "h3") && len(hello.ALPN) > 0 {
		add(core.SigQUICNoHTTP3, "QUIC ALPN="+strings.Join(hello.ALPN, ","), wQUICNoH3)
		if proto == core.ProtoUnknown {
			proto = core.ProtoDoQ
		}
	}

	// ---- 4. 行为聚合信号 ----
	if e.behavior != nil {
		beh := e.behavior.BehaviorFor(obs.Key.SrcIP)
		det := e.cfg()
		if beh.RepeatedHandshakes >= det.BehaviorMinSamples &&
			beh.ShortSNIProportion >= det.BehaviorShortSNIRatio {
			add(core.SigBehaviorPattern,
				"短连接反复握手: 同目标 "+itoa(beh.RepeatedHandshakes)+
					" 次, 短流占比 "+percent(beh.ShortSNIProportion), wBehavior)
		}
	}

	// ---- 5. 分数封顶与置信度 ----
	if score > 100 {
		score = 100
	}

	// 协议未坐实但分数较高：根据传输形态推断最可能的协议
	if proto == core.ProtoUnknown && score >= e.cfg().ObserveThreshold {
		switch {
		case isUDP:
			proto = core.ProtoDoQ
		case obs.Key.DstPort == 853:
			proto = core.ProtoDoT
		default:
			proto = core.ProtoDoH
		}
	}

	action, reason := e.pickAction(score, proto)
	return e.verdict(obs, proto, score, signals, action, reason)
}

func (e *Engine) pickAction(score int, proto core.Protocol) (string, string) {
	det := e.cfg()
	pol := e.policy()

	var protoAction config.Action
	switch proto {
	case core.ProtoDoH:
		protoAction = pol.DohAction
	case core.ProtoDoT:
		protoAction = pol.DotAction
	case core.ProtoDoQ:
		protoAction = pol.DoqAction
	default:
		protoAction = pol.UnknownAction
	}
	if protoAction == "" {
		protoAction = pol.DefaultAction
	}

	switch {
	case score >= det.BlockThreshold:
		// 高分默认按协议动作；若协议动作只是 observe/redirect，
		// 仍尊重显式策略（业务不能断的诉求优先）
		return string(protoAction), "分数 " + itoa(score) + " 达阻断阈值，按 " +
			string(protoAction) + " 策略执行"
	case score >= det.RedirectThreshold:
		if protoAction == config.ActionBlock {
			return string(config.ActionRedirect), "分数达导流阈值（阻断策略降级为导流，避免误伤）"
		}
		return string(protoAction), "分数 " + itoa(score) + " 达导流阈值"
	case score >= det.ObserveThreshold:
		return string(config.ActionObserve), "分数 " + itoa(score) + " 仅达观察阈值"
	default:
		return string(config.ActionObserve), "分数 " + itoa(score) + " 低于观察阈值，记录不干预"
	}
}

func (e *Engine) verdict(obs *core.FlowObservation, proto core.Protocol,
	score int, signals []core.Signal, action, reason string) *core.Verdict {
	return &core.Verdict{
		Protocol:       proto,
		Score:          score,
		Confidence:     float64(score) / 100.0,
		MatchedSignals: signals,
		Action:         action,
		Reason:         reason,
		Flow:           obs,
	}
}

func (e *Engine) matchPrefix(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func toSet(vs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(vs))
	for _, v := range vs {
		m[strings.ToLower(v)] = struct{}{}
	}
	return m
}

func parsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func contains(vs []string, target string) bool {
	for _, v := range vs {
		if v == target {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func percent(f float64) string {
	return itoa(int(f*100+0.5)) + "%"
}
