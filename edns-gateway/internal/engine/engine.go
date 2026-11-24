// Package engine 把采集、流表、分类、审计、指标与动作执行接线为一条处理管线。
package engine

import (
	"log/slog"
	"sync"
	"time"

	"github.com/enterprise/edns-gateway/internal/audit"
	"github.com/enterprise/edns-gateway/internal/classify"
	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/core"
	"github.com/enterprise/edns-gateway/internal/flowtrack"
	"github.com/enterprise/edns-gateway/internal/intel"
	"github.com/enterprise/edns-gateway/internal/metrics"
)

// Engine 检测管线。
type Engine struct {
	cfg        func() *config.Config
	tracker    *flowtrack.Tracker
	classifier *classify.Engine
	intel      *intel.Store
	audit      *audit.Logger
	metrics    *metrics.Registry
	log        *slog.Logger

	// 已做最终判定的流，避免同一条流重复审计/执行
	mu      sync.Mutex
	decided map[core.FlowKey]string
	// 流级 verdict 缓存：nfqueue 每包都会回调，同流后续报文直接复用首次结论，
	// 保证转发路径上的判定延迟只付一次。
	verdictCache map[core.FlowKey]string

	// 动作回调（nfqueue 模式由 capture 层注入；pcap 模式只记录）
	ActionHook func(verdict *core.Verdict)

	// AuditSink 可选审计旁路；非空时事件同时投递给它（analyze 子命令使用）
	AuditSink func(ev core.AuditEvent)
}

// SetAuditSink 安装额外审计事件接收函数。
func (e *Engine) SetAuditSink(fn func(ev core.AuditEvent)) { e.AuditSink = fn }

// New 构建引擎。
func New(cfg *config.Config, store *intel.Store, tracker *flowtrack.Tracker,
	aud *audit.Logger, reg *metrics.Registry, log *slog.Logger) *Engine {
	e := &Engine{
		tracker:      tracker,
		intel:        store,
		audit:        aud,
		metrics:      reg,
		log:          log,
		decided:      make(map[core.FlowKey]string),
		verdictCache: make(map[core.FlowKey]string),
	}
	e.cfg = func() *config.Config { return config.Load() }
	e.classifier = classify.NewEngine(store, tracker,
		func() *config.DetectConfig { return &config.Load().Detect },
		func() *config.PolicyConfig { return &config.Load().Policy })
	return e
}

// Reload 配置热更新入口。
func (e *Engine) Reload() {
	e.classifier.ReloadLists()
	e.mu.Lock()
	e.decided = make(map[core.FlowKey]string)
	e.verdictCache = make(map[core.FlowKey]string)
	e.mu.Unlock()
	e.log.Info("检测引擎已重载策略")
}

// Decide nfqueue 同步判定入口：输入单包元数据，返回内核动作。
//
// 内部仍走完整流表管线（保证握手状态可累积），但同流后续报文命中缓存直接
// 返回，把每包开销降到一次 map 查询。
//
// 返回："accept" | "drop" | "mark:<n>"
func (e *Engine) Decide(meta flowtrack.Meta) string {
	key := core.FlowKey{
		SrcIP: meta.SrcIP, DstIP: meta.DstIP,
		SrcPort: meta.SrcPort, DstPort: meta.DstPort,
		Protocol: map[bool]core.Transport{true: core.TransportTCP, false: core.TransportUDP}[meta.TCP],
	}
	e.mu.Lock()
	cached, ok := e.verdictCache[key]
	e.mu.Unlock()
	if ok {
		return cached
	}

	var events []flowtrack.Event
	if meta.TCP {
		events = e.tracker.ObserveTCP(meta)
	} else {
		events = e.tracker.ObserveUDP(meta)
	}

	action := "accept"
	for _, ev := range events {
		e.processEvent(ev)
		if v := e.lastAction(ev.Key); v != "" {
			action = e.translateAction(v)
		}
	}
	// 缓存确定动作；普通放行不缓存，以便后续握手出现新信号时升级判定
	if action != "accept" {
		e.mu.Lock()
		e.verdictCache[key] = action
		e.mu.Unlock()
	}
	return action
}

// translateAction 把策略动作翻译为 nfqueue 内核动作：
//
//	block    -> drop（丢弃报文，连接自然失败）
//	redirect -> mark:0xED（打 connmark，nftables 据此 tproxy 到本机加密 DNS 前端）
//	其他     -> accept
func (e *Engine) translateAction(policyAction string) string {
	switch config.Action(policyAction) {
	case config.ActionBlock:
		return "drop"
	case config.ActionRedirect:
		return "mark:237" // 0xED，与 deploy/nftables.rules 中的 mark 约定一致
	default:
		return "accept"
	}
}

func (e *Engine) lastAction(key core.FlowKey) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.decided[key]
}

// HandleMeta 采集层每报文回调（pcap 与 nfqueue 共用入口）。
func (e *Engine) HandleMeta(meta flowtrack.Meta) {
	var events []flowtrack.Event
	if meta.TCP {
		events = e.tracker.ObserveTCP(meta)
	} else {
		events = e.tracker.ObserveUDP(meta)
	}
	for _, ev := range events {
		e.processEvent(ev)
	}
}

func (e *Engine) processEvent(ev flowtrack.Event) {
	obs := ev.Obs
	// HTTP/2 路径事件需要把头部信息并入观测
	if ev.HTTP2 != nil {
		obs.HTTP2 = &core.HTTP2Info{
			Method: ev.HTTP2.Method, Path: ev.HTTP2.Path,
			Scheme: ev.HTTP2.Scheme, Authority: ev.HTTP2.Authority,
			ContentType: ev.HTTP2.ContentType, Accept: ev.HTTP2.Accept,
			UserAgent: ev.HTTP2.UserAgent,
		}
	}

	verdict := e.classifier.Classify(obs)

	// 信号级指标（无论最终动作都计数，用于观察检测面）
	for _, s := range verdict.MatchedSignals {
		e.metrics.IncCounter("edns_signals_total", "kind", string(s.Kind))
	}

	// 低于观察阈值的普通流量不产生审计，避免日志淹没
	cfg := e.cfg()
	if verdict.Score < cfg.Detect.ObserveThreshold && !ev.Closed {
		return
	}

	// 同流去重：Hello 事件先记一次；关闭事件只在动作升级时再记
	e.mu.Lock()
	prev, known := e.decided[ev.Key]
	if known && prev == verdict.Action && !ev.Closed {
		e.mu.Unlock()
		return
	}
	e.decided[ev.Key] = verdict.Action
	if ev.Closed {
		delete(e.decided, ev.Key)
		delete(e.verdictCache, ev.Key)
	}
	e.mu.Unlock()

	e.emitAudit(verdict)
	e.metrics.IncCounter("edns_verdicts_total",
		"protocol", verdict.Protocol.String(), "action", verdict.Action)

	if e.ActionHook != nil && verdict.Action != string(config.ActionObserve) &&
		verdict.Action != string(config.ActionAllowlist) {
		e.ActionHook(verdict)
	}
}

func (e *Engine) emitAudit(v *core.Verdict) {
	ev := core.AuditEvent{
		Time:       time.Now(),
		Action:     v.Action,
		Protocol:   v.Protocol.String(),
		Score:      v.Score,
		Confidence: v.Confidence,
		Src:        v.Flow.Key.SrcIP.String() + ":" + portStr(v.Flow.Key.SrcPort),
		Dst:        v.Flow.Key.DstIP.String() + ":" + portStr(v.Flow.Key.DstPort),
		Reason:     v.Reason,
	}
	if v.Flow.Hello != nil {
		ev.SNI = v.Flow.Hello.SNI
		ev.ALPN = v.Flow.Hello.ALPN
		ev.JA4 = v.Flow.Hello.JA4
	}
	if v.Flow.HTTP2 != nil {
		ev.Path = v.Flow.HTTP2.Path
	}
	for _, s := range v.MatchedSignals {
		ev.Signals = append(ev.Signals, string(s.Kind)+"("+s.Detail+")")
	}
	e.audit.Emit(ev)
	if e.AuditSink != nil {
		e.AuditSink(ev)
	}
}

// Sweep 周期清理流表并输出关闭事件、更新活跃流指标。
func (e *Engine) Sweep() {
	events := e.tracker.Sweep()
	for _, ev := range events {
		e.processEvent(ev)
	}
	flows, _ := e.tracker.Stats()
	e.metrics.SetGauge("edns_active_flows", int64(flows))
	d, i, _ := e.intel.Stats()
	e.metrics.SetGauge("edns_intel_domains", int64(d))
	e.metrics.SetGauge("edns_intel_ips", int64(i))
}

func portStr(p uint16) string {
	// 避免引入 strconv 造成的循环观感；简单转换
	if p == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}
