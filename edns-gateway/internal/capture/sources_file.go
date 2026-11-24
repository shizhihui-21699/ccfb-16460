package capture

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ngSource / classicSource 把 pcapgo 的两种 reader 适配到统一 packetSource。

type ngSource struct {
	r *pcapgo.NgReader
	f *os.File
}

func (s *ngSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.r.ReadPacketData()
}
func (s *ngSource) LinkType() layers.LinkType { return s.r.LinkType() }
func (s *ngSource) Close()                    { _ = s.f.Close() }

type classicSource struct {
	r *pcapgo.Reader
	f *os.File
}

func (s *classicSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.r.ReadPacketData()
}
func (s *classicSource) LinkType() layers.LinkType { return s.r.LinkType() }
func (s *classicSource) Close()                    { _ = s.f.Close() }

func openOsFile(path string) (*os.File, error) { return os.Open(path) }

// openFile 仅为保留接口对称性，当前直接复用 openOsFile。
func openFile(path string) *os.File {
	f, _ := os.Open(path)
	return f
}
