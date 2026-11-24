//go:build !linux

package capture

import (
	"context"
	"log/slog"
	"time"

	"github.com/enterprise/edns-gateway/internal/flowtrack"
)

// NfqueueSource 非 Linux 平台的占位实现，保证主程序可编译与离线测试。
type NfqueueSource struct{}

// NewNfqueue 在非 Linux 上始终返回错误。
func NewNfqueue(queueID uint16, family string, maxLen uint32,
	action func(flowtrack.Meta) string, log *slog.Logger) (*NfqueueSource, error) {
	return nil, ErrUnsupportedPlatform
}

// Run 非 Linux 不可用。
func (n *NfqueueSource) Run(ctx context.Context) error { return ErrUnsupportedPlatform }

var nowFunc = time.Now
