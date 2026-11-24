// Package flowtrack 维护网关转发面上的有状态流表：TCP 字节流重组、UDP/QUIC
// 数据报关联、每客户端的行为聚合，并驱动协议解析器产出观测事件。
package flowtrack

import (
	"net/netip"
	"sync"
	"time"

	"github.com/enterprise/edns-gateway/internal/core"
	"github.com/enterprise/edns-gateway/internal/protocol"
)

// Meta 从抓包层抽象出来的 L3/L4 元数据，使流表不依赖具体抓包实现。
type Meta struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	TCP     bool // true=TCP, false=UDP
	Bytes   int  // L4 payload 长度
	Payload []byte
	TS      time.Time
	FIN     bool
	RST     bool
	SYN     bool
}

// Event 流表向上层（分类器）输出的观测事件。
type Event struct {
	Key    core.FlowKey
	Obs    *core.FlowObservation
	Hello  *protocol.ParsedClientHello
	HTTP2  *protocol.ParsedHTTP2Stream
	QUIC   *protocol.QUICParseResult
	Closed bool // 流已结束（FIN/RST/超时），需要做最终分类
}

type flowState struct {
	key       core.FlowKey
	start     time.Time
	lastSeen  time.Time
	bytesUp   uint64
	bytesDown uint64
	pktsUp    uint64
	pktsDown  uint64

	// TCP 重组
	tlsReader *protocol.TLSRecordReader
	hello     *protocol.ParsedClientHello
	h2        *protocol.HTTP2Parser
	sawHTTP2  bool
	// 未完成的 ClientHello 分片缓存（TLS record 已切出但 handshake 跨 record）
	hsBuf []byte

	// QUIC
	quicParsed bool
	quicResult *protocol.QUICParseResult

	// 行为
	recordSizes []int
	closed      bool
}

// clientAgg 同一客户端（源 IP）在行为窗口内的聚合统计。
type clientAgg struct {
	windowStart      time.Time
	totalFlows       int
	shortLived       int
	distinctSNI      map[string]struct{}
	handshakePerDest map[string]int
}

// Tracker 全局流表。
type Tracker struct {
	mu       sync.RWMutex
	flows    map[core.FlowKey]*flowState
	clients  map[netip.Addr]*clientAgg
	cryptoRA *protocol.CryptoReassembler

	idleTimeout time.Duration
	maxLifetime time.Duration
	maxEntries  int
	window      time.Duration
	now         func() time.Time // 可注入时钟，便于测试
}

// NewTracker 创建流表。
func NewTracker(idle, maxLife time.Duration, maxEntries int, window time.Duration) *Tracker {
	return &Tracker{
		flows:       make(map[core.FlowKey]*flowState),
		clients:     make(map[netip.Addr]*clientAgg),
		cryptoRA:    protocol.NewCryptoReassembler(65536),
		idleTimeout: idle,
		maxLifetime: maxLife,
		maxEntries:  maxEntries,
		window:      window,
		now:         time.Now,
	}
}

// ObserveTCP 处理一个 TCP 报文的负载，返回需要分类的事件（0 或多个）。
func (t *Tracker) ObserveTCP(m Meta) []Event {
	key := core.FlowKey{
		SrcIP: m.SrcIP, DstIP: m.DstIP, SrcPort: m.SrcPort, DstPort: m.DstPort,
		Protocol: core.TransportTCP,
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.flows[key]
	if st == nil {
		if len(t.flows) >= t.maxEntries {
			t.evictOldestLocked()
		}
		st = &flowState{
			key:       key,
			start:     m.TS,
			tlsReader: &protocol.TLSRecordReader{},
			h2:        protocol.NewHTTP2Parser(64),
		}
		t.flows[key] = st
	}
	st.lastSeen = m.TS
	st.bytesUp += uint64(m.Bytes)
	st.pktsUp++

	if m.Bytes == 0 {
		if m.FIN || m.RST {
			return t.closeLocked(st, m.TS)
		}
		return nil
	}

	var events []Event
	records, err := st.tlsReader.Feed(m.Payload)
	if err != nil && err != protocol.ErrNeedMoreData {
		// 非 TLS 流（如明文 HTTP）：放弃协议解析，流仍保留做行为统计
		return nil
	}
	for _, rec := range records {
		st.recordSizes = append(st.recordSizes, len(rec.Data))
		switch rec.ContentType {
		case protocol.TLSContentTypeHS:
			ev := t.handleHandshakeLocked(st, rec.Data, m.TS)
			if ev != nil {
				events = append(events, *ev)
			}
		case protocol.TLSContentTypeApp:
			if st.sawHTTP2 {
				streams, err := st.h2.Feed(rec.Data)
				if err == nil {
					for _, s := range streams {
						events = append(events, t.makeEvent(st, m.TS, s))
					}
				}
			}
		}
	}

	if m.FIN || m.RST {
		events = append(events, t.closeLocked(st, m.TS)...)
	}
	return events
}

func (t *Tracker) handleHandshakeLocked(st *flowState, data []byte, now time.Time) *Event {
	if st.hello != nil {
		return nil // 只解析首个 ClientHello
	}
	st.hsBuf = append(st.hsBuf, data...)
	hello, err := protocol.ParseTLSClientHello(st.hsBuf)
	if err != nil {
		if len(st.hsBuf) > 65536 {
			st.hsBuf = st.hsBuf[:0] // 异常大的握手，放弃
		}
		return nil
	}
	st.hsBuf = nil
	st.hello = hello
	for _, alpn := range hello.ALPN {
		if alpn == "h2" {
			st.sawHTTP2 = true
		}
	}
	t.aggregateHandshake(st, hello.ServerName)
	return t.makeHelloEvent(st, now)
}

// ObserveUDP 处理 UDP 报文；仅 QUIC Initial 能产出事件。
func (t *Tracker) ObserveUDP(m Meta) []Event {
	if len(m.Payload) < 7 || m.Payload[0]&0x80 == 0 {
		return nil // 短头或非 QUIC
	}
	key := core.FlowKey{
		SrcIP: m.SrcIP, DstIP: m.DstIP, SrcPort: m.SrcPort, DstPort: m.DstPort,
		Protocol: core.TransportUDP,
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.flows[key]
	if st == nil {
		if len(t.flows) >= t.maxEntries {
			t.evictOldestLocked()
		}
		st = &flowState{key: key, start: m.TS, lastSeen: m.TS}
		t.flows[key] = st
	}
	st.lastSeen = m.TS
	st.bytesUp += uint64(m.Bytes)
	st.pktsUp++

	if st.quicParsed {
		return nil
	}
	// 逐包解密并把 CRYPTO 帧喂给重组器，解决大 ClientHello 跨 Initial 包。
	frames, err := protocol.DecryptQUICInitial(m.Payload)
	if err != nil {
		return nil
	}
	dcidKey := string(frames.DCID) // []byte 可直接作 map key 的字符串
	var assembled []byte
	for _, f := range frames.Frames {
		if buf, ok := t.cryptoRA.Add(dcidKey, f.Offset, f.Data); ok {
			assembled = buf
		}
	}
	if assembled == nil {
		// 起始分片尚未到达，等待后续数据包
		return nil
	}
	hello, err := protocol.ParseTLSClientHello(assembled)
	if err != nil {
		// 已连续但仍不完整（极端大握手）：保留缓冲等更多分片，暂不产出事件
		return nil
	}
	protocol.MarkQUICJA4(hello)
	t.cryptoRA.Drop(dcidKey)

	res := &protocol.QUICParseResult{
		Version: frames.Version, DCID: frames.DCID, SCID: frames.SCID,
		Token: frames.Token, Hello: hello, ALPN: hello.ALPN,
	}
	st.quicParsed = true
	st.quicResult = res
	t.aggregateHandshake(st, hello.ServerName)
	obs := t.buildObservation(st)
	return []Event{{
		Key:   key,
		Obs:   obs,
		QUIC:  res,
		Hello: hello,
	}}
}

func (t *Tracker) aggregateHandshake(st *flowState, sni string) {
	agg := t.clients[st.key.SrcIP]
	if agg == nil || t.now().Sub(agg.windowStart) > t.window {
		agg = &clientAgg{
			windowStart:      t.now(),
			distinctSNI:      make(map[string]struct{}),
			handshakePerDest: make(map[string]int),
		}
		t.clients[st.key.SrcIP] = agg
	}
	agg.totalFlows++
	if sni != "" {
		agg.distinctSNI[sni] = struct{}{}
	}
	agg.handshakePerDest[st.key.DstIP.String()]++
}

// markShortLived 由 Sweep 在流被判定为短生命周期时调用。
func (t *Tracker) markShortLivedLocked(st *flowState) {
	agg := t.clients[st.key.SrcIP]
	if agg != nil {
		agg.shortLived++
	}
}

func (t *Tracker) makeHelloEvent(st *flowState, now time.Time) *Event {
	obs := t.buildObservation(st)
	return &Event{Key: st.key, Obs: obs, Hello: st.hello}
}

func (t *Tracker) makeEvent(st *flowState, now time.Time, h2s *protocol.ParsedHTTP2Stream) Event {
	obs := t.buildObservation(st)
	return Event{Key: st.key, Obs: obs, HTTP2: h2s}
}

func (t *Tracker) buildObservation(st *flowState) *core.FlowObservation {
	obs := &core.FlowObservation{
		Key:         st.key,
		Start:       st.start,
		LastSeen:    st.lastSeen,
		BytesUp:     st.bytesUp,
		BytesDown:   st.bytesDown,
		PacketsUp:   st.pktsUp,
		PacketsDown: st.pktsDown,
	}
	if st.hello != nil {
		obs.Hello = &core.ClientHelloInfo{
			Version:         st.hello.Version,
			SNI:             st.hello.ServerName,
			ALPN:            st.hello.ALPN,
			CipherSuites:    st.hello.CipherSuites,
			Extensions:      st.hello.Extensions,
			SupportedGroups: st.hello.SupportedGroups,
			SignatureAlgos:  st.hello.SignatureAlgos,
			ECHPresent:      st.hello.ECHPresent,
			ECHOuterSNI:     st.hello.ECHOuterSNI,
			JA3:             st.hello.JA3,
			JA4:             st.hello.JA4,
		}
	}
	if st.quicResult != nil && st.quicResult.Hello != nil {
		obs.Hello = &core.ClientHelloInfo{
			Version:    st.quicResult.Hello.Version,
			SNI:        st.quicResult.Hello.ServerName,
			ALPN:       st.quicResult.Hello.ALPN,
			ECHPresent: st.quicResult.Hello.ECHPresent,
			JA3:        st.quicResult.Hello.JA3,
			JA4:        st.quicResult.Hello.JA4,
		}
	}
	return obs
}

// BehaviorFor 返回某源 IP 当前窗口的行为信号，供分类器加权。
func (t *Tracker) BehaviorFor(src netip.Addr) core.BehaviorSignals {
	t.mu.RLock()
	defer t.mu.RUnlock()
	agg := t.clients[src]
	if agg == nil || agg.totalFlows == 0 {
		return core.BehaviorSignals{}
	}
	shortRatio := float64(agg.shortLived) / float64(agg.totalFlows)
	repeated := 0
	for _, n := range agg.handshakePerDest {
		if n > repeated {
			repeated = n
		}
	}
	return core.BehaviorSignals{
		DistinctSNI:        len(agg.distinctSNI),
		ShortSNIProportion: shortRatio,
		RepeatedHandshakes: repeated,
	}
}

func (t *Tracker) closeLocked(st *flowState, now time.Time) []Event {
	if st.closed {
		return nil
	}
	st.closed = true
	st.lastSeen = now
	// 短生命周期判定：有握手且总上行负载很小（典型 DoT/DoQ 一问一答）
	if st.hello != nil && st.bytesUp < 2048 {
		t.markShortLivedLocked(st)
	}
	obs := t.buildObservation(st)
	ev := Event{Key: st.key, Obs: obs, Closed: true}
	if st.hello != nil {
		ev.Hello = st.hello
	}
	if st.quicResult != nil {
		ev.QUIC = st.quicResult
	}
	delete(t.flows, st.key)
	return []Event{ev}
}

func (t *Tracker) evictOldestLocked() {
	var oldest core.FlowKey
	var oldestTime time.Time
	for k, st := range t.flows {
		if oldestTime.IsZero() || st.lastSeen.Before(oldestTime) {
			oldest, oldestTime = k, st.lastSeen
		}
	}
	if oldestTime.IsZero() {
		return
	}
	st := t.flows[oldest]
	t.markShortLivedLocked(st)
	delete(t.flows, oldest)
}

// Sweep 清理超时流并滚动客户端聚合窗口，返回被清理流的关闭事件。
// 调用方应周期性调用（如每 30s）。
func (t *Tracker) Sweep() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var events []Event
	for k, st := range t.flows {
		if now.Sub(st.lastSeen) > t.idleTimeout || now.Sub(st.start) > t.maxLifetime {
			events = append(events, t.closeLocked(st, now)...)
			_ = k
		}
	}
	for ip, agg := range t.clients {
		if now.Sub(agg.windowStart) > t.window {
			delete(t.clients, ip)
		}
	}
	return events
}

// Stats 流表规模指标。
func (t *Tracker) Stats() (flows, clients int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows), len(t.clients)
}
