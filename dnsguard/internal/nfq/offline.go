package nfq

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket/pcapgo"
)

// AnalyzePcap 离线模式:从 pcap 文件读包走一遍识别逻辑,用于验证规则和清单,
// 不影响现网。判定结果只打日志,不执行阻断。
func (e *Engine) AnalyzePcap(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return fmt.Errorf("pcap reader: %w", err)
	}
	n := 0
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break // EOF
		}
		// pcap 里是以太网帧,剥掉 14 字节以太头(VLAN 场景需扩展)
		if len(data) < 14 {
			continue
		}
		ethType := uint16(data[12])<<8 | uint16(data[13])
		if ethType != 0x0800 && ethType != 0x86DD {
			continue
		}
		e.Process(data[14:])
		n++
	}
	log.Printf("pcap analysis done, %d ip packets processed", n)
	return nil
}
