// Package intel 维护公共加密解析服务的情报库：域名(SNI)、IP/CIDR、ALPN 与特征。
//
// 设计原则：解析器 IP 经常变化，因此域名/SNI 情报是稳定锚点，IP 情报只作为
// 辅助加权信号并支持外部 feed 热更新。所有匹配均区分协议类别。
package intel

import (
	"net/netip"
	"strings"
	"sync"
)

// Category 情报类别。
type Category uint8

const (
	CatDoH Category = 1 << iota
	CatDoT
	CatDoQ
)

// Entry 一条情报。
type Entry struct {
	Key      string // 域名（小写）或 IP/CIDR 字符串
	Provider string // 厂商，便于审计展示
	Cat      Category
	IsDomain bool
	prefix   netip.Prefix // Key 为 CIDR/IP 时预解析
}

// builtinEntries 内置基线情报（2025 年主流公共解析服务）。
// IP 仅作辅助：任播地址相对稳定但并非保证，判定权重低于 SNI/ALPN。
var builtinEntries = []Entry{
	// ---- Google Public DNS ----
	{Key: "dns.google", Provider: "Google", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "dns.google.com", Provider: "Google", Cat: CatDoH, IsDomain: true},
	{Key: "8.8.8.8", Provider: "Google", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "8.8.4.4", Provider: "Google", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "2001:4860:4860::8888", Provider: "Google", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "2001:4860:4860::8844", Provider: "Google", Cat: CatDoH | CatDoT | CatDoQ},

	// ---- Cloudflare 1.1.1.1 ----
	{Key: "cloudflare-dns.com", Provider: "Cloudflare", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "one.one.one.one", Provider: "Cloudflare", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "security.cloudflare-dns.com", Provider: "Cloudflare-Family", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "family.cloudflare-dns.com", Provider: "Cloudflare-Family", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "1.1.1.1", Provider: "Cloudflare", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "1.0.0.1", Provider: "Cloudflare", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "2606:4700:4700::1111", Provider: "Cloudflare", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "2606:4700:4700::1001", Provider: "Cloudflare", Cat: CatDoH | CatDoT | CatDoQ},

	// ---- Quad9 ----
	{Key: "dns.quad9.net", Provider: "Quad9", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "dns10.quad9.net", Provider: "Quad9", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "9.9.9.9", Provider: "Quad9", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "149.112.112.112", Provider: "Quad9", Cat: CatDoH | CatDoT},
	{Key: "2620:fe::fe", Provider: "Quad9", Cat: CatDoH | CatDoT | CatDoQ},

	// ---- OpenDNS / Cisco ----
	{Key: "doh.opendns.com", Provider: "OpenDNS", Cat: CatDoH, IsDomain: true},
	{Key: "dns.opendns.com", Provider: "OpenDNS", Cat: CatDoT, IsDomain: true},
	{Key: "208.67.222.222", Provider: "OpenDNS", Cat: CatDoH | CatDoT},
	{Key: "208.67.220.220", Provider: "OpenDNS", Cat: CatDoH | CatDoT},

	// ---- AdGuard ----
	{Key: "dns.adguard-dns.com", Provider: "AdGuard", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "unfiltered.adguard-dns.com", Provider: "AdGuard", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "94.140.14.14", Provider: "AdGuard", Cat: CatDoH | CatDoT},
	{Key: "94.140.15.15", Provider: "AdGuard", Cat: CatDoH | CatDoT},

	// ---- NextDNS（每个租户独立子域名，用后缀匹配覆盖）----
	{Key: "dns.nextdns.io", Provider: "NextDNS", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "dns1.nextdns.io", Provider: "NextDNS", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "dns2.nextdns.io", Provider: "NextDNS", Cat: CatDoH | CatDoT, IsDomain: true},

	// ---- 国内公共解析（国内企业场景常见）----
	{Key: "doh.pub", Provider: "DNSPod", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "dot.pub", Provider: "DNSPod", Cat: CatDoT, IsDomain: true},
	{Key: "1.12.12.12", Provider: "DNSPod", Cat: CatDoH | CatDoT},
	{Key: "120.53.53.53", Provider: "DNSPod", Cat: CatDoH | CatDoT},
	{Key: "dns.alidns.com", Provider: "AliDNS", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "223.5.5.5", Provider: "AliDNS", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "223.6.6.6", Provider: "AliDNS", Cat: CatDoH | CatDoT | CatDoQ},
	{Key: "2400:3200::1", Provider: "AliDNS", Cat: CatDoH | CatDoT},
	{Key: "doh.360.cn", Provider: "360DNS", Cat: CatDoH, IsDomain: true},
	{Key: "dot.360.cn", Provider: "360DNS", Cat: CatDoT, IsDomain: true},

	// ---- 其他国际服务 ----
	{Key: "dns.mullvad.net", Provider: "Mullvad", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: "doh.cleanbrowsing.org", Provider: "CleanBrowsing", Cat: CatDoH, IsDomain: true},
	{Key: "doth.dnscrypt.info", Provider: "DNSCrypt", Cat: CatDoT, IsDomain: true},
	{Key: "dns9.quad9.net", Provider: "Quad9", Cat: CatDoH | CatDoT, IsDomain: true},
	{Key: "dns11.quad9.net", Provider: "Quad9", Cat: CatDoH | CatDoT, IsDomain: true},
}

// suffixEntries 需要按域名后缀匹配的情报（如 *.nextdns.io 多租户）。
var suffixEntries = []Entry{
	{Key: ".nextdns.io", Provider: "NextDNS", Cat: CatDoH | CatDoT | CatDoQ, IsDomain: true},
	{Key: ".dns.nextdns.io", Provider: "NextDNS", Cat: CatDoH | CatDoT, IsDomain: true},
}

// Store 线程安全的情报仓库，支持整体替换实现热更新。
type Store struct {
	mu sync.RWMutex

	domains   map[string]Entry     // 精确域名 -> entry
	suffix    []Entry              // 后缀匹配
	ips       map[netip.Addr]Entry // 单 IP
	prefixes  []netip.Prefix       // CIDR（量小，线性扫描；外部 feed 量大时可换 radix）
	prefixEnt []Entry
}

// NewStore 构建仓库，useBuiltin 控制是否加载内置基线。
func NewStore(useBuiltin bool) *Store {
	s := &Store{
		domains: make(map[string]Entry),
		ips:     make(map[netip.Addr]Entry),
	}
	if useBuiltin {
		for _, e := range builtinEntries {
			s.add(e)
		}
		s.suffix = append(s.suffix, suffixEntries...)
	}
	return s
}

func (s *Store) add(e Entry) {
	if e.IsDomain {
		s.domains[strings.ToLower(e.Key)] = e
		return
	}
	if addr, err := netip.ParseAddr(e.Key); err == nil {
		s.ips[addr] = e
		return
	}
	if pfx, err := netip.ParsePrefix(e.Key); err == nil {
		s.prefixes = append(s.prefixes, pfx)
		s.prefixEnt = append(s.prefixEnt, e)
	}
}

// Merge 合并外部 feed 条目（热更新调用，粒度为追加，不删内置）。
func (s *Store) Merge(entries []Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		s.add(e)
	}
}

// ReplaceAll 用给定条目全量重建（外部 feed 刷新时使用，内置条目按需重新载入）。
func (s *Store) ReplaceAll(entries []Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = make(map[string]Entry)
	s.ips = make(map[netip.Addr]Entry)
	s.prefixes = nil
	s.prefixEnt = nil
	s.suffix = nil
	for _, e := range entries {
		s.add(e)
	}
}

// MatchResult 命中结果。
type MatchResult struct {
	Provider string
	Cat      Category
	Matched  string // 命中的具体情报键，审计用
}

// LookupDomain 按 SNI 域名匹配（精确 + 后缀）。
func (s *Store) LookupDomain(domain string) (MatchResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if e, ok := s.domains[d]; ok {
		return MatchResult{Provider: e.Provider, Cat: e.Cat, Matched: e.Key}, true
	}
	for _, e := range s.suffix {
		if strings.HasSuffix(d, e.Key) {
			return MatchResult{Provider: e.Provider, Cat: e.Cat, Matched: e.Key}, true
		}
	}
	return MatchResult{}, false
}

// LookupAddr 按目的 IP 匹配（精确 + CIDR）。
func (s *Store) LookupAddr(addr netip.Addr) (MatchResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.ips[addr]; ok {
		return MatchResult{Provider: e.Provider, Cat: e.Cat, Matched: e.Key}, true
	}
	for i, pfx := range s.prefixes {
		if pfx.Contains(addr) {
			e := s.prefixEnt[i]
			return MatchResult{Provider: e.Provider, Cat: e.Cat, Matched: e.Key}, true
		}
	}
	return MatchResult{}, false
}

// Stats 返回情报规模（metrics 用）。
func (s *Store) Stats() (domains, ips, prefixes int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.domains), len(s.ips), len(s.prefixes)
}
