package protocol

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// recordingPacketConn 包装 UDP conn，把所有长头数据报送入缓冲通道。
type recordingPacketConn struct {
	net.PacketConn
	ch chan []byte
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// 深拷贝后非阻塞投递；缓冲满则丢弃（测试只需要握手初期的少量包）
	if len(p) > 0 && p[0]&0x80 != 0 {
		cp := append([]byte(nil), p...)
		select {
		case c.ch <- cp:
		default:
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// isV1Initial 判断是否为 QUIC v1 Initial 长头包。
// 线编码：高 4 位 1100（固定位+type=00），版本字段 0x00000001。
func isV1Initial(p []byte) bool {
	return len(p) >= 5 && p[0]&0x30 == 0 && p[0]&0x80 != 0 &&
		p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 1
}

// captureQUICInitial 用 quic-go 客户端发起握手，捕获它发出的 Initial 数据报。
// 服务端无需真实完成握手——Initial 在握手第一步就发出。
func captureQUICInitial(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	rec := &recordingPacketConn{
		PacketConn: clientConn,
		ch:         make(chan []byte, 64),
	}

	// 服务端读一点数据维持 NAT，不做任何回应
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := serverConn.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		tlsConf := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         alpn,
		}
		_, _ = quic.Dial(ctx, rec, serverConn.LocalAddr(), tlsConf, &quic.Config{
			HandshakeIdleTimeout: time.Second,
		})
	}()

	// 轮询缓冲通道直到拿到 v1 Initial；握手初期包很少，几次读取即可命中。
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-rec.ch:
			if isV1Initial(pkt) {
				return pkt
			}
		case <-deadline:
			t.Fatal("未捕获 QUIC Initial")
			return nil
		}
	}
}

// captureAllInitials 捕获握手窗口内同一目标的所有 v1 Initial 数据报。
func captureAllInitials(t *testing.T, sni string, alpn []string) [][]byte {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	rec := &recordingPacketConn{PacketConn: clientConn, ch: make(chan []byte, 128)}
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := serverConn.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		tlsConf := &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: alpn}
		_, _ = quic.Dial(ctx, rec, serverConn.LocalAddr(), tlsConf,
			&quic.Config{HandshakeIdleTimeout: time.Second})
	}()

	var out [][]byte
	deadline := time.After(800 * time.Millisecond)
	for {
		select {
		case pkt := <-rec.ch:
			if isV1Initial(pkt) {
				out = append(out, pkt)
			}
		case <-deadline:
			if len(out) == 0 {
				t.Fatal("未捕获任何 QUIC Initial")
			}
			return out
		}
	}
}

func TestParseQUICInitial_RealQuicGo(t *testing.T) {
	packets := captureAllInitials(t, "dns.adguard-dns.com", []string{"doq"})

	// 逐包解密，CRYPTO 帧交给重组器跨包还原完整 ClientHello
	ra := NewCryptoReassembler(65536)
	var hello *ParsedClientHello
	var dcid []byte
	for _, pkt := range packets {
		frames, err := DecryptQUICInitial(pkt)
		if err != nil {
			t.Fatalf("Initial 解密失败: %v", err)
		}
		dcid = frames.DCID
		key := string(frames.DCID)
		for _, f := range frames.Frames {
			assembled, ok := ra.Add(key, f.Offset, f.Data)
			if !ok {
				continue
			}
			if h, err := ParseTLSClientHello(assembled); err == nil {
				MarkQUICJA4(h)
				hello = h
			}
		}
	}
	if hello == nil {
		t.Fatalf("重组 %d 个 Initial 后仍未还原 ClientHello", len(packets))
	}
	if hello.ServerName != "dns.adguard-dns.com" {
		t.Errorf("SNI = %q，期望 dns.adguard-dns.com", hello.ServerName)
	}
	foundDoQ := false
	for _, a := range hello.ALPN {
		if a == "doq" {
			foundDoQ = true
		}
	}
	if !foundDoQ {
		t.Errorf("ALPN = %v，期望包含 doq", hello.ALPN)
	}
	if len(dcid) == 0 {
		t.Error("DCID 为空")
	}
	if hello.JA4 == "" || hello.JA4[0] != 'q' {
		t.Errorf("QUIC JA4 应以 q 开头，实际 %q", hello.JA4)
	}
}

func TestParseQUICInitial_RejectsShortHeader(t *testing.T) {
	// 短头（1-RTT）包无法也不应被解析
	short := make([]byte, 20)
	short[0] = 0x40 // 最高位 0
	if _, err := ParseQUICInitial(short); !errors.Is(err, ErrNotQUICInitial) {
		t.Errorf("短头包应返回 ErrNotQUICInitial，实际 %v", err)
	}
}

func TestParseQUICInitial_RejectsGarbage(t *testing.T) {
	garbage := make([]byte, 1200)
	garbage[0] = 0xc0
	// 随机版本号不在支持表中
	garbage[1], garbage[2], garbage[3], garbage[4] = 0xff, 0xff, 0xff, 0xff
	if _, err := ParseQUICInitial(garbage); !errors.Is(err, ErrNotQUICInitial) {
		t.Errorf("未知版本应返回 ErrNotQUICInitial，实际 %v", err)
	}
}

// TestParseQUICInitial_TamperedFailsAEAD 验证密文被篡改时 AEAD 校验失败，
// 证明我们不是"碰巧"解析成功。
func TestParseQUICInitial_TamperedFailsAEAD(t *testing.T) {
	pkt := append([]byte(nil), captureQUICInitial(t, "dns.google", []string{"doq"})...)
	// 篡改 payload 靠后位置（避开头部），AEAD tag 校验必须失败
	if len(pkt) < 60 {
		t.Skip("报文过短")
	}
	pkt[len(pkt)-5] ^= 0xff
	if _, err := ParseQUICInitial(pkt); err == nil {
		t.Error("篡改后的报文不应解密成功")
	}
}

var _ = io.EOF
