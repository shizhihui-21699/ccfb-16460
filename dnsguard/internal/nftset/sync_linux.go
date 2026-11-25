//go:build linux

// Package nftset 把 DoH IP 清单和动态封禁结果同步进 nftables 集合。
// 表结构见 deploy/dnsguard.nft,本包只做集合元素的增删,不管规则。
package nftset

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/nftables"
)

type Syncer struct {
	conn   *nftables.Conn
	table  *nftables.Table
	set4   *nftables.Set
	set6   *nftables.Set
	blocked4 *nftables.Set // 动态封禁(带超时)
}

func New(tableName string) (*Syncer, error) {
	c := &nftables.Conn{}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
	s := &Syncer{conn: c, table: t}
	var err error
	if s.set4, err = lookupSet(c, t, "doh4"); err != nil {
		return nil, err
	}
	if s.set6, err = lookupSet(c, t, "doh6"); err != nil {
		return nil, err
	}
	if s.blocked4, err = lookupSet(c, t, "blocked4"); err != nil {
		return nil, err
	}
	return s, nil
}

func lookupSet(c *nftables.Conn, t *nftables.Table, name string) (*nftables.Set, error) {
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return nil, fmt.Errorf("nft set %s not found (apply deploy/dnsguard.nft first): %w", name, err)
	}
	return s, nil
}

// SyncFeeds 全量同步 DoH IP 集合:先清后加(清单量级几千条,flush 重建最简单可靠)。
func (s *Syncer) SyncFeeds(ips []netip.Addr) error {
	s.conn.FlushSet(s.set4)
	s.conn.FlushSet(s.set6)
	n4, n6 := 0, 0
	for _, a := range ips {
		el := nftables.SetElement{Key: a.AsSlice()}
		if a.Is4() {
			s.conn.SetAddElements(s.set4, []nftables.SetElement{el})
			n4++
		} else {
			s.conn.SetAddElements(s.set6, []nftables.SetElement{el})
			n6++
		}
	}
	if err := s.conn.Flush(); err != nil {
		return fmt.Errorf("nft sync feeds: %w", err)
	}
	return nil
}

// AddBlocked 把检出 DoH 的目标 IP 加入动态封禁集,后续包由 nftables 直接丢弃,
// 不必再进 NFQUEUE,降低 CPU 开销。
func (s *Syncer) AddBlocked(ip netip.Addr, timeout time.Duration) error {
	el := nftables.SetElement{Key: ip.AsSlice(), Timeout: timeout}
	s.conn.SetAddElements(s.blocked4, []nftables.SetElement{el})
	return s.conn.Flush()
}
