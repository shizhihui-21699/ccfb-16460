package config

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	QueueNum          uint16   `yaml:"queue_num"`
	InternalResolvers []string `yaml:"internal_resolvers"` // 内部解析器,用于解析 DoH 域名清单
	LogOnly           bool     `yaml:"log_only"`           // 只审计不阻断(灰度模式)
	BlockTimeoutSec   int      `yaml:"block_timeout_sec"`  // 检出后动态封禁目标 IP 的时长

	Feeds struct {
		URLs            []string      `yaml:"urls"`
		RefreshInterval time.Duration `yaml:"refresh_interval"`
	} `yaml:"feeds"`

	Canary struct {
		ReportInterval time.Duration `yaml:"report_interval"`
	} `yaml:"canary"`

	Exceptions []Exception `yaml:"exceptions"`

	NftTable string `yaml:"nft_table"`

	MetricsAddr string `yaml:"metrics_addr"`
}

// Exception 业务软件强制使用加密解析时的放行规则:
// 来自 Src 网段、访问 AllowSNI 后缀或 AllowDst 中地址的加密解析流量被放行并记录审计日志。
type Exception struct {
	Comment  string   `yaml:"comment"`
	Src      string   `yaml:"src"`
	AllowSNI []string `yaml:"allow_sni"`
	AllowDst []string `yaml:"allow_dst"`

	SrcPrefix netip.Prefix   `yaml:"-"`
	DstAddrs  []netip.Addr   `yaml:"-"`
	DstCIDRs  []netip.Prefix `yaml:"-"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{
		QueueNum:        100,
		BlockTimeoutSec: 600,
		NftTable:        "dnsguard",
		MetricsAddr:     "127.0.0.1:9153",
	}
	c.Feeds.RefreshInterval = 6 * time.Hour
	c.Canary.ReportInterval = 10 * time.Minute
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	for i := range c.Exceptions {
		ex := &c.Exceptions[i]
		p, err := netip.ParsePrefix(ex.Src)
		if err != nil {
			return nil, fmt.Errorf("exception %d: bad src %q: %w", i, ex.Src, err)
		}
		ex.SrcPrefix = p
		for _, d := range ex.AllowDst {
			if a, err := netip.ParseAddr(d); err == nil {
				ex.DstAddrs = append(ex.DstAddrs, a)
				continue
			}
			if p, err := netip.ParsePrefix(d); err == nil {
				ex.DstCIDRs = append(ex.DstCIDRs, p)
				continue
			}
			return nil, fmt.Errorf("exception %d: bad dst %q", i, d)
		}
	}
	if len(c.InternalResolvers) == 0 {
		return nil, fmt.Errorf("internal_resolvers is required")
	}
	return c, nil
}
