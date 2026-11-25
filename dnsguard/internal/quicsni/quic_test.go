package quicsni

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// 测试:手工构造一个加密的 QUIC Initial(加密侧是解析侧的逆运算),
// 验证 ServerName 能正确解密并提取 SNI。

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xC0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func buildTestClientHello(serverName string) []byte {
	name := []byte(serverName)
	entry := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
	sniData := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	ext := append([]byte{0, 0, byte(len(sniData) >> 8), byte(len(sniData))}, sniData...)
	exts := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func buildInitial(t *testing.T, dcid []byte, serverName string) []byte {
	t.Helper()

	// CRYPTO 帧: type=0x06, offset=0, length, data
	crypto := appendVarint(nil, 0x06)
	crypto = appendVarint(crypto, 0)
	ch := buildTestClientHello(serverName)
	crypto = appendVarint(crypto, uint64(len(ch)))
	plain := append(crypto, ch...)
	// 补 PADDING 让包足够大
	for len(plain) < 64 {
		plain = append(plain, 0)
	}

	// 与解析侧相同的密钥导出
	initialSecret := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	clientSecret := expandLabel(sha256.New, initialSecret, "client in", 32)
	key := expandLabel(sha256.New, clientSecret, "quic key", 16)
	iv := expandLabel(sha256.New, clientSecret, "quic iv", 12)
	hpKey := expandLabel(sha256.New, clientSecret, "quic hp", 16)

	var pn uint64 = 1
	pnLen := 4

	// 组头部(先不加密)
	hdr := []byte{0xC0 | byte(pnLen-1), 0, 0, 0, 1} // long header, Initial, v1
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0) // scid len 0
	hdr = append(hdr, 0) // token len 0

	// length = pnLen + len(plain) + 16(GCM tag),先占位后补
	lenBytes := appendVarint(nil, uint64(pnLen+len(plain)+16))
	hdr = append(hdr, lenBytes...)
	pnOffset := len(hdr)
	hdr = append(hdr, byte(pn>>24), byte(pn>>16), byte(pn>>8), byte(pn))

	// 加密载荷
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	ciphertext := aead.Seal(nil, nonce, plain, hdr)

	pkt := append(hdr, ciphertext...)

	// 头部保护
	hpCipher, _ := aes.NewCipher(hpKey)
	mask := make([]byte, 16)
	hpCipher.Encrypt(mask, pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

func TestServerNameQUIC(t *testing.T) {	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08} // RFC 9001 示例 DCID
	pkt := buildInitial(t, dcid, "dns.example-doh.com")
	got, err := ServerName(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "dns.example-doh.com" {
		t.Fatalf("got %q", got)
	}
}

func TestNotInitial(t *testing.T) {
	if _, err := ServerName([]byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}); err != ErrNotInitial {
		t.Fatalf("expected ErrNotInitial, got %v", err)
	}
}

func TestBadVersion(t *testing.T) {
	pkt := buildInitial(t, []byte{1, 2, 3, 4}, "x.example")
	binary.BigEndian.PutUint32(pkt[1:5], 0xdeadbeef)
	if _, err := ServerName(pkt); err != ErrVersion {
		t.Fatalf("expected ErrVersion, got %v", err)
	}
}
