//go:build linux

package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// liveSource 包装 pcap.Handle 到统一 packetSource 接口。
type liveSource struct{ h *pcap.Handle }

func (s *liveSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.h.ReadPacketData()
}
func (s *liveSource) LinkType() layers.LinkType { return s.h.LinkType() }
func (s *liveSource) Close()                    { s.h.Close() }

// openLive 打开网卡实时抓包句柄（Linux 实现，libpcap）。
func (p *PcapSource) openLive() error {
	handle, err := pcap.OpenLive(p.iface, p.snapLen, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	if p.bpf != "" {
		if err := handle.SetBPFFilter(p.bpf); err != nil {
			handle.Close()
			return err
		}
	}
	p.src = &liveSource{h: handle}
	return nil
}
