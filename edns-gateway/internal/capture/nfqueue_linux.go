//go:build linux

// Package capture 的 nfqueue 部分：在 Linux 网关上把检测引擎的判定翻译为
// 内核动作。NFQUEUE 通过 nftables 规则把匹配报文送入用户态队列，本程序
// 异步给出 verdict，不引入额外转发跳数。
package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/enterprise/edns-gateway/internal/flowtrack"
)

var nowFunc = time.Now

// ActionFn 由上层（engine 接线层）提供：给定流元数据返回动作。
// 返回值约定："accept" | "drop" | "mark:<n>"
type ActionFn func(meta flowtrack.Meta) string

// NfqueueSource 内核队列采集 + 动作执行。
type NfqueueSource struct {
	queueID uint16
	family  uint8 // unix.AF_INET / unix.AF_INET6
	maxLen  uint32
	action  ActionFn
	log     *slog.Logger

	nfq *nfqueue.Nfqueue
}

// NewNfqueue 创建执行器。family: "ipv4" | "ipv6"。
func NewNfqueue(queueID uint16, family string, maxLen uint32, action ActionFn, log *slog.Logger) (*NfqueueSource, error) {
	af := uint8(2) // unix.AF_INET
	if family == "ipv6" {
		af = 10 // unix.AF_INET6
	}
	if maxLen == 0 {
		maxLen = 4096
	}
	return &NfqueueSource{
		queueID: queueID, family: af, maxLen: maxLen, action: action, log: log,
	}, nil
}

// Run 打开队列并阻塞处理，直到 ctx 取消。fail-open：本程序异常时内核
// 放行报文（NfQaCfgFlagFailOpen），避免网关故障导致全网断网。
func (n *NfqueueSource) Run(ctx context.Context) error {
	cfg := &nfqueue.Config{
		NfQueue:      n.queueID,
		MaxQueueLen:  n.maxLen,
		Copymode:     nfqueue.NfQnlCopyPacket,
		MaxPacketLen: 0xffff,
		AfFamily:     n.family,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	}
	nfq, err := nfqueue.Open(cfg)
	if err != nil {
		return fmt.Errorf("open nfqueue %d: %w", n.queueID, err)
	}
	n.nfq = nfq
	defer nfq.Close()

	if err := nfq.RegisterWithErrorFunc(ctx, n.hook, func(e error) int {
		n.log.Error("nfqueue 错误", "err", e)
		return 0
	}); err != nil {
		return fmt.Errorf("register nfqueue hook: %w", err)
	}
	<-ctx.Done()
	return nil
}

func (n *NfqueueSource) hook(attr nfqueue.Attribute) int {
	if attr.PacketID == nil || attr.Payload == nil {
		return 0
	}
	pid := *attr.PacketID
	meta, ok := parseKernelPacket(*attr.Payload, n.family)
	if !ok {
		// 非 TCP/UDP 或解析失败：放行，不影响无关业务
		_ = n.nfq.SetVerdict(pid, nfqueue.NfAccept)
		return 0
	}

	action := n.action(meta)
	switch action {
	case "drop":
		if err := n.nfq.SetVerdict(pid, nfqueue.NfDrop); err != nil {
			n.log.Warn("nfqueue drop verdict 失败", "err", err)
		}
		return 0
	case "accept":
		_ = n.nfq.SetVerdict(pid, nfqueue.NfAccept)
		return 0
	default:
		// mark:<n>：打 connmark 供 nftables 导流规则匹配，报文继续放行
		if mark, ok := parseMark(action); ok {
			if err := n.nfq.SetVerdictWithConnMark(pid, nfqueue.NfAccept, mark); err != nil {
				n.log.Warn("nfqueue mark verdict 失败", "err", err)
				_ = n.nfq.SetVerdict(pid, nfqueue.NfAccept)
			}
			return 0
		}
		_ = n.nfq.SetVerdict(pid, nfqueue.NfAccept)
		return 0
	}
}

// parseKernelPacket NFQUEUE payload 是完整 IP 报文（无 L2 头）。
func parseKernelPacket(packet []byte, family uint8) (flowtrack.Meta, bool) {
	var first gopacket.Decoder
	if family == 10 {
		first = layers.LayerTypeIPv6
	} else {
		first = layers.LayerTypeIPv4
	}
	pkt := gopacket.NewPacket(packet, first, gopacket.Default)
	meta, ok := decodePacket(pkt)
	if ok {
		// 内核队列报文没有时间戳时补当前时间
		if meta.TS.IsZero() {
			meta.TS = nowFunc()
		}
	}
	return meta, ok
}

func parseMark(action string) (int, bool) {
	var n int
	if _, err := fmt.Sscanf(action, "mark:%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

// ErrNfqueueUnavailable 平台不支持。
var ErrNfqueueUnavailable = errors.New("nfqueue 仅在 Linux 可用")
