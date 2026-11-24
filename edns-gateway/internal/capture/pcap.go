// Package capture 提供流量采集抽象与两种实现：
//   - pcap：网卡实时抓包或离线 pcap 文件（跨平台，开发/测试/取证分析）
//   - nfqueue：Linux 内核 NFQUEUE，具备 accept/drop/mark 动作执行能力（生产导流/阻断）
//
// 两种实现都输出统一的 flowtrack.Meta，检测引擎与部署形态解耦。
package capture

import (
	"errors"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/enterprise/edns-gateway/internal/flowtrack"
)

// packetSource 统一 pcapgo.Reader / NgReader / 实时 handle 的最小接口。
type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	Close()
}

// PcapSource 基于 gopacket 的采集源，支持实时网卡与离线文件。
type PcapSource struct {
	src     packetSource
	iface   string
	file    string
	bpf     string
	snapLen int32
}

// NewPcapFile 离线 pcap/pcapng 文件源。
func NewPcapFile(path string) *PcapSource {
	return &PcapSource{file: path, snapLen: 65535}
}

// NewPcapLive 实时网卡源。
func NewPcapLive(iface, bpf string, snapLen int32) *PcapSource {
	return &PcapSource{iface: iface, bpf: bpf, snapLen: snapLen}
}

// open 延迟打开，使构造函数不产生副作用，便于测试。
func (p *PcapSource) open() error {
	if p.file != "" {
		return p.openFile()
	}
	return p.openLive()
}

func (p *PcapSource) openFile() error {
	f, err := openOsFile(p.file)
	if err != nil {
		return err
	}
	// 先尝试 pcapng，失败回退经典 pcap
	if ng, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{}); err == nil {
		p.src = &ngSource{r: ng, f: f}
		return nil
	}
	// NgReader 失败后文件偏移已移动，重新打开
	_ = f.Close()
	f2, err := openOsFile(p.file)
	if err != nil {
		return err
	}
	pr, err := pcapgo.NewReader(f2)
	if err != nil {
		_ = f2.Close()
		return err
	}
	p.src = &classicSource{r: pr, f: f2}
	return nil
}

// Run 阻塞读取报文并回调 handler，直到数据源结束（文件 EOF）或返回错误。
func (p *PcapSource) Run(handler func(flowtrack.Meta)) error {
	if err := p.open(); err != nil {
		return err
	}
	defer p.src.Close()

	source := gopacket.NewPacketSource(p.src, p.src.LinkType())
	source.Lazy = true
	source.NoCopy = true

	for pkt := range source.Packets() {
		meta, ok := decodePacket(pkt)
		if !ok {
			continue
		}
		handler(meta)
	}
	return nil
}

// decodePacket 从 gopacket 报文提取 L3/L4 元数据。
// 只关注 TCP/UDP；IP 分片重组依赖部署侧（nftables/网卡），引擎不重复实现。
func decodePacket(pkt gopacket.Packet) (flowtrack.Meta, bool) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return flowtrack.Meta{}, false
	}
	var srcIP, dstIP netip.Addr
	switch l := netLayer.(type) {
	case *layers.IPv4:
		srcIP, _ = netip.AddrFromSlice(l.SrcIP)
		dstIP, _ = netip.AddrFromSlice(l.DstIP)
	case *layers.IPv6:
		srcIP, _ = netip.AddrFromSlice(l.SrcIP)
		dstIP, _ = netip.AddrFromSlice(l.DstIP)
	default:
		return flowtrack.Meta{}, false
	}

	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	switch tl := pkt.TransportLayer().(type) {
	case *layers.TCP:
		payload := tl.Payload
		return flowtrack.Meta{
			SrcIP:   srcIP.Unmap(),
			DstIP:   dstIP.Unmap(),
			SrcPort: uint16(tl.SrcPort),
			DstPort: uint16(tl.DstPort),
			TCP:     true,
			Bytes:   len(payload),
			Payload: payload,
			TS:      ts,
			FIN:     tl.FIN,
			RST:     tl.RST,
			SYN:     tl.SYN && !tl.ACK,
		}, true
	case *layers.UDP:
		payload := tl.Payload
		return flowtrack.Meta{
			SrcIP:   srcIP.Unmap(),
			DstIP:   dstIP.Unmap(),
			SrcPort: uint16(tl.SrcPort),
			DstPort: uint16(tl.DstPort),
			TCP:     false,
			Bytes:   len(payload),
			Payload: payload,
			TS:      ts,
		}, true
	default:
		return flowtrack.Meta{}, false
	}
}

// ErrUnsupportedPlatform 该采集模式在当前平台不可用。
var ErrUnsupportedPlatform = errors.New("capture mode unsupported on this platform")
