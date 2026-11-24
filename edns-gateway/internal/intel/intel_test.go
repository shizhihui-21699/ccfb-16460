package intel

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBuiltinDomainIntel(t *testing.T) {
	s := NewStore(true)
	cases := []struct {
		domain string
		want   bool
	}{
		{"dns.google", true},
		{"cloudflare-dns.com", true},
		{"dns.quad9.net", true},
		{"dns.nextdns.io", true},
		{"random.nextdns.io", true}, // 多租户后缀
		{"abc123.dns.nextdns.io", true},
		{"evil-dns.google.attacker.com", false}, // 后缀仿冒
		{"example.com", false},
	}
	for _, c := range cases {
		_, ok := s.LookupDomain(c.domain)
		if ok != c.want {
			t.Errorf("LookupDomain(%q) = %v, 期望 %v", c.domain, ok, c.want)
		}
	}
}

func TestBuiltinIPIntel(t *testing.T) {
	s := NewStore(true)
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"9.9.9.9", true},
		{"223.5.5.5", true},
		{"8.8.4.4", true},
		{"198.51.100.7", false}, // TEST-NET 文档地址，不应在内置库
	}
	for _, c := range cases {
		_, ok := s.LookupAddr(netip.MustParseAddr(c.ip))
		if ok != c.want {
			t.Errorf("LookupAddr(%s) = %v, 期望 %v", c.ip, ok, c.want)
		}
	}
}

func TestExternalFeedMerge(t *testing.T) {
	s := NewStore(true)
	before, _, _ := s.Stats()
	s.Merge([]Entry{
		{Key: "custom-doh.internal.example", Provider: "custom", Cat: CatDoH, IsDomain: true},
		{Key: "198.51.100.0/24", Provider: "custom", Cat: CatDoT},
		{Key: "203.0.113.9", Provider: "custom", Cat: CatDoQ},
	})
	if r, ok := s.LookupDomain("custom-doh.internal.example"); !ok || r.Provider != "custom" {
		t.Error("外部域名情报未生效")
	}
	if _, ok := s.LookupAddr(netip.MustParseAddr("198.51.100.55")); !ok {
		t.Error("外部 CIDR 情报未生效")
	}
	if _, ok := s.LookupAddr(netip.MustParseAddr("203.0.113.9")); !ok {
		t.Error("外部单 IP 情报未生效")
	}
	after, ips, prefixes := s.Stats()
	if after <= before {
		t.Error("域名条目数应增加")
	}
	if ips == 0 || prefixes == 0 {
		t.Errorf("IP/CIDR 计数异常 ips=%d prefixes=%d", ips, prefixes)
	}
}

func TestParseFeed(t *testing.T) {
	feed := `# 注释行
8.8.8.8
192.0.2.0/24,custom-provider
doh.example.net
another-domain.example
`
	entries := parseFeed(strings.NewReader(feed), "doh", "test-feed")
	if len(entries) != 4 {
		t.Fatalf("期望解析 4 条，实际 %d: %+v", len(entries), entries)
	}
	if !entries[2].IsDomain || entries[2].Key != "doh.example.net" {
		t.Errorf("域名条目解析错误: %+v", entries[2])
	}
	if entries[0].Provider != "test-feed" {
		t.Error("缺省 provider 应为 feed 名")
	}
	if entries[1].Provider != "custom-provider" {
		t.Error("显式 provider 未解析")
	}
	if !entries[3].IsDomain {
		t.Error("多词域名行的首个 token 应按域名处理")
	}
}
