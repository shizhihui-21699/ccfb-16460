package tlssni

import (
	"encoding/binary"
	"testing"
)

// buildClientHello 构造一个带 SNI 的 TLS ClientHello(record + handshake)。
func buildClientHello(serverName string) []byte {
	// SNI 扩展
	name := []byte(serverName)
	sniData := []byte{0, 0} // list length 占位
	entry := []byte{0, byte(len(name) >> 8), byte(len(name))}
	entry = append(entry, name...)
	listLen := len(entry)
	sniData[0], sniData[1] = byte(listLen>>8), byte(listLen)
	sniData = append(sniData, entry...)
	ext := []byte{0, 0, byte(len(sniData) >> 8), byte(len(sniData))}
	ext = append(ext, sniData...)
	exts := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)

	// ClientHello body
	body := []byte{0x03, 0x03} // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id len
	body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
	body = append(body, 1, 0)                // compression
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestServerName(t *testing.T) {
	pkt := buildClientHello("dns.example.com")
	got, err := ServerName(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "dns.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestServerNameTruncated(t *testing.T) {
	pkt := buildClientHello("dns.example.com")
	// 截断到 SNI 之前应报错,截断在 SNI 之后应尽力解析
	if _, err := ServerName(pkt[:20]); err == nil {
		t.Fatal("expected error for heavily truncated packet")
	}
}

func TestParseClientHelloBody(t *testing.T) {
	pkt := buildClientHello("doh.test.org")
	// 跳过 record(5) + handshake header(4)
	got, err := ParseClientHelloBody(pkt[9:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "doh.test.org" {
		t.Fatalf("got %q", got)
	}
}

func TestNotClientHello(t *testing.T) {
	if _, err := ServerName([]byte{0x17, 0x03, 0x03, 0, 10}); err != ErrNotClientHello {
		t.Fatalf("expected ErrNotClientHello, got %v", err)
	}
}

func TestRecordLengthBound(t *testing.T) {
	pkt := buildClientHello("a.b")
	// 篡改 record 长度为一个超大值,解析器不应越界
	binary.BigEndian.PutUint16(pkt[3:5], 0xFFFF)
	if _, err := ServerName(pkt); err != nil {
		t.Fatalf("should tolerate oversized record length: %v", err)
	}
}
