// Package policy 判定一条疑似加密解析流量是放行、阻断还是仅审计。
package policy

import (
	"log"
	"net/netip"
	"strings"
	"sync"

	"github.com/example/dnsguard/internal/config"
)

type Verdict int

const (
	Accept Verdict = iota
	Drop
)

// Decision 是一次判定的结果,Reason 用于审计日志。
type Decision struct {
	Verdict Verdict
	Reason  string
}

type Engine struct {
	mu      sync.RWMutex
	domains map[string]struct{}      // 已知 DoH 域名(来自清单)
	ips     map[netip.Addr]struct{}  // 已知 DoH IP(来自清单)
	exc     []config.Exception
	logOnly bool
}

func New(exc []config.Exception, logOnly bool) *Engine {
	return &Engine{
		domains: map[string]struct{}{},
		ips:     map[netip.Addr]struct{}{},
		exc:     exc,
		logOnly: logOnly,
	}
}

// UpdateFeeds 热更新清单数据。
func (e *Engine) UpdateFeeds(domains map[string]struct{}, ips map[netip.Addr]struct{}) {
	e.mu.Lock()
	e.domains, e.ips = domains, ips
	e.mu.Unlock()
}

// CheckEncryptedDNS 判定一条到 443 的加密连接(TLS/QUIC,已提取 SNI)。
// sni 可能为空(ECH 或无 SNI),此时只能依据目标 IP。
func (e *Engine) CheckEncryptedDNS(src, dst netip.Addr, sni, proto string) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	isDoH := false
	reason := ""
	if sni != "" {
		if _, ok := e.domains[sni]; ok {
			isDoH, reason = true, "sni="+sni
		} else {
			// 后缀匹配,覆盖清单里的泛域名条目(如 *.dns.example.com 的父域)
			for d := range e.domains {
				if strings.HasSuffix(sni, "."+d) {
					isDoH, reason = true, "sni="+sni+"~"+d
					break
				}
			}
		}
	}
	if !isDoH {
		if _, ok := e.ips[dst]; ok {
			isDoH, reason = true, "dst="+dst.String()
		}
	}
	if !isDoH {
		return Decision{Accept, ""}
	}

	// 命中 DoH:检查业务例外
	for _, ex := range e.exc {
		if !ex.SrcPrefix.Contains(src) {
			continue
		}
		for _, s := range ex.AllowSNI {
			if sni == s || strings.HasSuffix(sni, "."+s) {
				return Decision{Accept, "exception sni=" + sni + " (" + ex.Comment + ")"}
			}
		}
		for _, a := range ex.DstAddrs {
			if a == dst {
				return Decision{Accept, "exception dst=" + dst.String() + " (" + ex.Comment + ")"}
			}
		}
		for _, p := range ex.DstCIDRs {
			if p.Contains(dst) {
				return Decision{Accept, "exception dst=" + dst.String() + " (" + ex.Comment + ")"}
			}
		}
	}

	if e.logOnly {
		return Decision{Accept, "AUDIT-ONLY would-block " + reason}
	}
	return Decision{Drop, "block " + reason}
}

// LogDecision 统一审计输出(接入 SIEM 时替换为结构化输出)。
func LogDecision(proto string, src, dst netip.Addr, sni string, d Decision) {
	if d.Reason == "" {
		return
	}
	log.Printf("AUDIT proto=%s src=%s dst=%s sni=%q action=%s %s",
		proto, src, dst, sni, verdictName(d.Verdict), d.Reason)
}

func verdictName(v Verdict) string {
	if v == Drop {
		return "DROP"
	}
	return "ACCEPT"
}
