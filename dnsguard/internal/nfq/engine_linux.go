//go:build linux

package nfq

import (
	"context"
	"log"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
)

// Run 启动 NFQUEUE 消费循环,直到 ctx 取消。
func (e *Engine) Run(ctx context.Context, queueNum uint16) error {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	defer nf.Close()

	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			return 0
		}
		verdict := nfqueue.NfAccept
		if !e.Process(*a.Payload) {
			verdict = nfqueue.NfDrop
		}
		if err := nf.SetVerdict(*a.PacketID, verdict); err != nil {
			log.Printf("nfq: set verdict: %v", err)
		}
		return 0
	}
	errFn := func(err error) int {
		log.Printf("nfq: %v", err)
		return 0
	}
	return nf.RegisterWithErrorFunc(ctx, fn, errFn)
}
