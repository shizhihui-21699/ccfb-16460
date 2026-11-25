// Package canary 跟踪每台内网终端的明文 DNS 使用情况。
// 一台终端如果长期没有任何明文 DNS 查询却正常上网,说明它绕过了内部解析,
// 需要排查(可能是 DoH 未被识别、VPN、或恶意程序自带解析)。
package canary

import (
	"log"
	"net/netip"
	"sync"
	"time"
)

type Tracker struct {
	mu  sync.Mutex
	dns map[netip.Addr]int // 明文 DNS 查询次数
	doh map[netip.Addr]int // 被检出的加密解析次数
}

func New() *Tracker {
	return &Tracker{dns: map[netip.Addr]int{}, doh: map[netip.Addr]int{}}
}

func (t *Tracker) ObserveDNS(src netip.Addr) {
	t.mu.Lock()
	t.dns[src]++
	t.mu.Unlock()
}

func (t *Tracker) ObserveDoH(src netip.Addr) {
	t.mu.Lock()
	t.doh[src]++
	t.mu.Unlock()
}

// ReportLoop 周期性输出可疑终端:有加密解析行为但几乎不用内部 DNS。
func (t *Tracker) ReportLoop(stop <-chan struct{}, interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			t.report()
		}
	}
}

func (t *Tracker) report() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for src, n := range t.doh {
		if n >= 3 && t.dns[src] == 0 {
			log.Printf("CANARY host=%s doh_detections=%d plain_dns=0 — 该终端完全绕过内部解析,需排查", src, n)
		}
	}
	// 滚动清零,下一轮重新计数
	t.dns = map[netip.Addr]int{}
	t.doh = map[netip.Addr]int{}
}
