// Package config 定义网关的全部配置结构、默认值与 YAML 加载/热更新。
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Action 策略动作。
type Action string

const (
	ActionObserve   Action = "observe"   // 仅审计，不干预
	ActionRedirect  Action = "redirect"  // 导流到内部加密解析服务
	ActionBlock     Action = "block"     // 阻断
	ActionAllowlist Action = "allowlist" // 白名单豁免，直接放行
)

// Config 根配置。
type Config struct {
	Capture  CaptureConfig  `yaml:"capture"`
	Detect   DetectConfig   `yaml:"detect"`
	Intel    IntelConfig    `yaml:"intel"`
	Policy   PolicyConfig   `yaml:"policy"`
	Redirect RedirectConfig `yaml:"redirect"`
	Resolver ResolverConfig `yaml:"resolver"`
	Logging  LoggingConfig  `yaml:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics"`
}

type CaptureConfig struct {
	// Mode: pcap(离线文件/网卡) | nfqueue(Linux 内核队列)
	Mode          string `yaml:"mode"`
	Interface     string `yaml:"interface"`
	PcapFile      string `yaml:"pcap_file"`
	BPFFilter     string `yaml:"bpf_filter"`
	SnapLen       int32  `yaml:"snap_len"`
	NfqueueID     uint16 `yaml:"nfqueue_id"`
	NfqueueFamily string `yaml:"nfqueue_family"` // ipv4 | ipv6
	NfqueueLen    uint32 `yaml:"nfqueue_len"`
}

type DetectConfig struct {
	// 判定阈值，0 表示用默认值
	BlockThreshold    int `yaml:"block_threshold"`
	RedirectThreshold int `yaml:"redirect_threshold"`
	ObserveThreshold  int `yaml:"observe_threshold"`
	// 流表超时
	FlowIdleTimeout  Duration `yaml:"flow_idle_timeout"`
	FlowMaxLifetime  Duration `yaml:"flow_max_lifetime"`
	FlowCacheEntries int      `yaml:"flow_cache_entries"`
	// 行为检测窗口
	BehaviorWindow        Duration `yaml:"behavior_window"`
	BehaviorMinSamples    int      `yaml:"behavior_min_samples"`
	BehaviorShortSNIRatio float64  `yaml:"behavior_short_sni_ratio"`
	// JA4 黑名单（命中即高置信）
	JA4Blocklist []string `yaml:"ja4_blocklist"`
}

type IntelConfig struct {
	// 静态内置之外的外部情报源
	Feeds        []FeedConfig `yaml:"feeds"`
	RefreshEvery Duration     `yaml:"refresh_every"`
	CacheFile    string       `yaml:"cache_file"`
	// 内置公共解析器情报开关（代码内 defaultresolvers.go）
	UseBuiltin bool `yaml:"use_builtin"`
}

type FeedConfig struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // url（每行 IP/CIDR）| local（本地文件）
	Path     string `yaml:"path"`
	Category string `yaml:"category"` // doh | dot | doq
}

type PolicyConfig struct {
	// 默认动作与各协议的独立动作覆盖
	DefaultAction Action `yaml:"default_action"`
	DohAction     Action `yaml:"doh_action"`
	DotAction     Action `yaml:"dot_action"`
	DoqAction     Action `yaml:"doq_action"`
	UnknownAction Action `yaml:"unknown_action"` // 仅行为可疑、协议未坐实时
	// 白名单
	AllowSNI  []string `yaml:"allow_sni"`
	AllowCIDR []string `yaml:"allow_cidr"`
	// 强制阻断名单（即使协议未完全坐实也阻断，用于确认恶意的解析器）
	BlockSNI  []string `yaml:"block_sni"`
	BlockCIDR []string `yaml:"block_cidr"`
}

type RedirectConfig struct {
	// 内部加密解析服务监听地址（导流目标）
	DoHListen string `yaml:"doh_listen"`
	DoTListen string `yaml:"dot_listen"`
	DoQListen string `yaml:"doq_listen"`
	// 证书；DoT/DoQ/DoH 共用。企业内网需通过组策略下发 CA 信任
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// 导流方式：
	// tproxy  —— 网关本机透明接管（推荐，nftables tproxy 到本机端口）
	// nat     —— DNAT 重定向（仅 IP，SNI 不匹配时客户端证书校验可能失败）
	// answer  —— 不接管连接，由内部解析器对后续明文 DNS 返回解析器同 IP 的 A/AAAA（引导模式）
	Mode string `yaml:"mode"`
	// answer 模式下，向客户端宣告的内部 DoH/DoT/DoQ 服务 IP
	ServiceIPv4 string `yaml:"service_ipv4"`
	ServiceIPv6 string `yaml:"service_ipv6"`
}

type ResolverConfig struct {
	// 内部递归 DNS（明文 53），所有被导流的加密查询最终转发到这里，
	// 由它执行既有的恶意域名拦截策略，保证策略一致
	Upstream string `yaml:"upstream"`
	// 兜底上游（内部递归不可用时），留空则拒绝
	Fallback string   `yaml:"fallback"`
	Timeout  Duration `yaml:"timeout"`
	// DoQ 单条消息最大字节（RFC 9250: 65535）
	DoQMaxUDPPayload int `yaml:"doq_max_udp_payload"`
}

type LoggingConfig struct {
	AuditFile  string `yaml:"audit_file"` // 留空写 stdout
	JSON       bool   `yaml:"json"`
	Level      string `yaml:"level"` // debug | info | warn | error
	RotateSize int64  `yaml:"rotate_size_mb"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"` // 例如 127.0.0.1:9100，留空不启动
	Path   string `yaml:"path"`
}

// Duration 包装 time.Duration，支持 "30s" / "5m" 这类 YAML 字符串。
type Duration struct{ time.Duration }

func (d Duration) MarshalYAML() (interface{}, error) { return d.Duration.String(), nil }

// UnmarshalYAML 实现 yaml.v3 Unmarshaler 接口。
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	v, err := time.ParseDuration(node.Value)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// snapshot 用 atomic.Pointer 支持无锁热更新。
type snapshot struct{ v atomic.Pointer[Config] }

// Store 全局配置仓库，供各包读取当前生效配置。
var Store snapshot

// Load 返回当前生效配置（只读，调用方不得修改）。
func Load() *Config { return Store.v.Load() }

// Replace 原子替换生效配置。
func Replace(c *Config) { Store.v.Store(c) }

// Default 返回带默认值的配置。
func Default() *Config {
	return &Config{
		Capture: CaptureConfig{
			Mode:          "pcap",
			SnapLen:       65535,
			NfqueueID:     170,
			NfqueueFamily: "ipv4",
			NfqueueLen:    4096,
		},
		Detect: DetectConfig{
			BlockThreshold:        90,
			RedirectThreshold:     60,
			ObserveThreshold:      25,
			FlowIdleTimeout:       Duration{5 * time.Minute},
			FlowMaxLifetime:       Duration{time.Hour},
			FlowCacheEntries:      200000,
			BehaviorWindow:        Duration{10 * time.Minute},
			BehaviorMinSamples:    4,
			BehaviorShortSNIRatio: 0.8,
		},
		Intel: IntelConfig{UseBuiltin: true, RefreshEvery: Duration{time.Hour}},
		Policy: PolicyConfig{
			DefaultAction: ActionRedirect,
			DohAction:     ActionRedirect,
			DotAction:     ActionRedirect,
			DoqAction:     ActionRedirect,
			UnknownAction: ActionObserve,
		},
		Redirect: RedirectConfig{
			DoHListen: "0.0.0.0:8443",
			DoTListen: "0.0.0.0:8853",
			DoQListen: "0.0.0.0:8853",
			Mode:      "tproxy",
		},
		Resolver: ResolverConfig{
			Upstream:         "10.0.0.53:53",
			Timeout:          Duration{3 * time.Second},
			DoQMaxUDPPayload: 65535,
		},
		Logging: LoggingConfig{JSON: true, Level: "info", RotateSize: 100},
		Metrics: MetricsConfig{Listen: "127.0.0.1:9100", Path: "/metrics"},
	}
}

// LoadFile 读取 YAML 并叠加默认值后校验。
func LoadFile(path string) (*Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate 检查配置合法性并预解析 CIDR 白名单（CIDR 在 policy 包再解析）。
func (c *Config) Validate() error {
	switch c.Capture.Mode {
	case "pcap", "nfqueue":
	default:
		return fmt.Errorf("capture.mode 必须是 pcap 或 nfqueue，实际 %q", c.Capture.Mode)
	}
	if c.Capture.Mode == "pcap" && c.Capture.Interface == "" && c.Capture.PcapFile == "" {
		return errors.New("pcap 模式必须指定 interface 或 pcap_file")
	}
	if c.Detect.BlockThreshold < c.Detect.RedirectThreshold ||
		c.Detect.RedirectThreshold < c.Detect.ObserveThreshold {
		return errors.New("阈值需要满足 block >= redirect >= observe")
	}
	for _, a := range []Action{c.Policy.DefaultAction, c.Policy.DohAction, c.Policy.DotAction,
		c.Policy.DoqAction, c.Policy.UnknownAction} {
		switch a {
		case ActionObserve, ActionRedirect, ActionBlock, ActionAllowlist, "":
		default:
			return fmt.Errorf("未知动作 %q", a)
		}
	}
	for _, cidr := range append(append([]string{}, c.Policy.AllowCIDR...), c.Policy.BlockCIDR...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("非法 CIDR %q: %w", cidr, err)
		}
	}
	switch c.Redirect.Mode {
	case "tproxy", "nat", "answer":
	default:
		return fmt.Errorf("redirect.mode 必须是 tproxy/nat/answer，实际 %q", c.Redirect.Mode)
	}
	if c.Resolver.Upstream == "" {
		return errors.New("resolver.upstream 不能为空")
	}
	if _, _, err := net.SplitHostPort(c.Resolver.Upstream); err != nil {
		return fmt.Errorf("resolver.upstream 需是 host:port 形式: %w", err)
	}
	return nil
}
