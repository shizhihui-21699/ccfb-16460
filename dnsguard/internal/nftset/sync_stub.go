//go:build !linux

package nftset

import (
	"errors"
	"net/netip"
	"time"
)

// 非 Linux 平台的桩实现,仅保证可编译(便于在开发机上跑单测)。
type Syncer struct{}

func New(tableName string) (*Syncer, error) { return &Syncer{}, nil }

func (s *Syncer) SyncFeeds(ips []netip.Addr) error {
	return errors.New("nftset: linux only")
}

func (s *Syncer) AddBlocked(ip netip.Addr, timeout time.Duration) error {
	return errors.New("nftset: linux only")
}
