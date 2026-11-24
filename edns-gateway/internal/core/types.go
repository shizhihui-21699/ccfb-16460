// Package core 定义各子系统共享的观测对象与协议枚举。
package core

import (
	"net/netip"
	"time"
)

// Protocol 加密解析协议判定结果。
type Protocol uint8

const (
	ProtoUnknown Protocol = iota
	ProtoDoH              // DNS over HTTPS (RFC 8484)
	ProtoDoT              // DNS over TLS (RFC 7858)
	ProtoDoQ              // DNS over QUIC (RFC 9250)
)

func (p Protocol) String() string {
	switch p {
	case ProtoDoH:
		return "DoH"
	case ProtoDoT:
		return "DoT"
	case ProtoDoQ:
		return "DoQ"
	default:
		return "unknown"
	}
}

// Transport 流的传输层。
type Transport uint8

const (
	TransportTCP Transport = iota
	TransportUDP           // QUIC
)

// FlowKey 五元组（方向以发起方为 src）。
type FlowKey struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol Transport
}

// ClientHelloInfo TLS/QUIC 握手层提取到的全部明文特征。
type ClientHelloInfo struct {
	Version             uint16   // 0x0303(TLS1.2)/0x0304(TLS1.3)
	SNI                 string   // server_name 扩展
	ALPN                []string // ALPN 扩展，按线序
	CipherSuites        []uint16
	Extensions          []uint16 // 含 GREASE 原值
	SupportedGroups     []uint16
	SignatureAlgos      []uint16
	ECHOuterSNI         string // ECH 外层 SNI（加密 ClientHello 场景）
	ECHPresent          bool
	JA3                 string // 标准 JA3 指纹
	JA4                 string // JA4 风格指纹（见 tls 包注释，与官方工具存在已知偏差）
	QuicTransportParams []byte // QUIC 场景下的 transport parameters 原始字节（保留）
}

// HTTP2Info 加密流内 HTTP/2 头部帧解析结果。
type HTTP2Info struct {
	Method      string
	Path        string // :path，DoH 判定核心
	Scheme      string
	Authority   string // :authority
	ContentType string
	Accept      string
	UserAgent   string
}

// BehaviorSignals 行为层信号（单流维度 + 聚合维度）。
type BehaviorSignals struct {
	// 单流
	SmallRecords bool // TLS record 长度集中在 2 段以内、payload 极小（DNS 消息特征）
	ShortLived   bool // 握手后少量数据即关闭
	NoHTTPFrames bool // TLS 上未观察到 HTTP/2 前导/帧
	// 聚合（同一客户端在 BehaviorWindow 内）
	DistinctSNI        int     // 不同 SNI 数
	ShortSNIProportion float64 // 短生命周期流占比
	RepeatedHandshakes int     // 对同一目的 IP 反复新建 TLS/QUIC 连接
}

// FlowObservation 协议解析器向分类器输出的完整观测。
type FlowObservation struct {
	Key         FlowKey
	Start       time.Time
	LastSeen    time.Time
	BytesUp     uint64
	BytesDown   uint64
	PacketsUp   uint64
	PacketsDown uint64

	Hello    *ClientHelloInfo
	HTTP2    *HTTP2Info
	Behavior BehaviorSignals

	// 解析阶段产出的命中信号，分类器据此打分
	Signals []Signal
}

// SignalKind 信号类型。
type SignalKind string

const (
	SigSNIIntel        SignalKind = "sni_intel"   // SNI 命中已知公共解析器域名
	SigIPIntel         SignalKind = "ip_intel"    // 目的 IP 命中解析器情报
	SigALPDoH          SignalKind = "alpn_h2_doh" // h2 + 后续 dns-query 路径
	SigALPDot          SignalKind = "alpn_dot"    // ALPN=dot
	SigALPDoQ          SignalKind = "alpn_doq"    // ALPN=doq
	SigDoHPath         SignalKind = "http2_dns_query_path"
	SigDoHContentType  SignalKind = "doh_content_type"
	SigDoTPort         SignalKind = "dot_wellknown_port" // 853
	SigQUICNoHTTP3     SignalKind = "quic_without_h3"    // QUIC 但 ALPN 不含 h3
	SigECH             SignalKind = "ech_enabled"        // 加密 ClientHello
	SigBehaviorPattern SignalKind = "behavior_pattern"   // 行为聚合命中
	SigJA4Block        SignalKind = "ja4_blocklist"
)

// Signal 带权重的命中信号；权重集中在 classify 包统一管理，这里只记录事实。
type Signal struct {
	Kind   SignalKind
	Detail string
	Weight int
}

// Verdict 分类器最终结论。
type Verdict struct {
	Protocol       Protocol
	Score          int
	Confidence     float64 // 0~1
	MatchedSignals []Signal
	Action         string // config.Action 的字符串形式
	Reason         string
	Flow           *FlowObservation
}

// AuditEvent 写入审计日志的一条记录。
type AuditEvent struct {
	Time       time.Time `json:"time"`
	Action     string    `json:"action"`
	Protocol   string    `json:"protocol"`
	Score      int       `json:"score"`
	Confidence float64   `json:"confidence"`
	Src        string    `json:"src"`
	Dst        string    `json:"dst"`
	SNI        string    `json:"sni,omitempty"`
	ALPN       []string  `json:"alpn,omitempty"`
	Path       string    `json:"path,omitempty"`
	JA4        string    `json:"ja4,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Signals    []string  `json:"signals,omitempty"`
}
