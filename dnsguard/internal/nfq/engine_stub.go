//go:build !linux

package nfq

import (
	"context"
	"errors"
)

// Run 非 Linux 平台不可用,仅保证可编译。
func (e *Engine) Run(ctx context.Context, queueNum uint16) error {
	return errors.New("nfqueue: linux only, use -pcap for offline analysis")
}
