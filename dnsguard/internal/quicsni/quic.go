// Package quicsni 解析 QUIC Initial 包,解密出 TLS ClientHello 并提取 SNI。
// 用于识别 DoH3 (DNS over HTTP/3) 流量。QUIC Initial 的密钥由 DCID 公开导出,
// 因此被动解密不需要任何私钥,这是协议设计使然(RFC 9001)。
package quicsni

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/example/dnsguard/internal/tlssni"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrNotInitial = errors.New("not a QUIC Initial packet")
	ErrTruncated  = errors.New("truncated QUIC packet")
	ErrVersion    = errors.New("unsupported QUIC version")
	ErrDecrypt    = errors.New("initial decryption failed")
)

// RFC 9001 §5.2 / RFC 9369
var (
	initialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// ServerName 从一个 UDP 载荷(应为客户端首个 QUIC Initial)提取 SNI。
// 只处理第一个 Initial;合并包(coalesced)中 Initial 必在最前。
func ServerName(pkt []byte) (string, error) {
	if len(pkt) < 7 {
		return "", ErrTruncated
	}
	if pkt[0]&0x80 == 0 || pkt[0]&0x40 == 0 { // 长包头 + fixed bit
		return "", ErrNotInitial
	}
	if (pkt[0]&0x30)>>4 != 0 { // type != Initial
		return "", ErrNotInitial
	}
	ver := binary.BigEndian.Uint32(pkt[1:5])
	var salt []byte
	switch ver {
	case 0x00000001:
		salt = initialSaltV1
	case 0x6b3343cf:
		salt = initialSaltV2
	default:
		return "", ErrVersion
	}

	off := 5
	dcidLen := int(pkt[off])
	off++
	if len(pkt) < off+dcidLen+1 {
		return "", ErrTruncated
	}
	dcid := pkt[off : off+dcidLen]
	off += dcidLen
	scidLen := int(pkt[off])
	off++
	if len(pkt) < off+scidLen {
		return "", ErrTruncated
	}
	off += scidLen

	tokLen, n := readVarint(pkt[off:])
	if n == 0 {
		return "", ErrTruncated
	}
	off += n + int(tokLen)
	if len(pkt) < off+2 {
		return "", ErrTruncated
	}
	length, n := readVarint(pkt[off:])
	if n == 0 {
		return "", ErrTruncated
	}
	off += n
	pnOffset := off
	if length < 20 || len(pkt) < pnOffset+int(length) {
		return "", ErrTruncated
	}
	pkt = pkt[:pnOffset+int(length)] // 去掉可能合并的后续包

	// ---- 导出 Initial 密钥 (RFC 9001 §5.2) ----
	initialSecret := hkdf.Extract(sha256.New, dcid, salt)
	clientSecret := expandLabel(sha256.New, initialSecret, "client in", 32)
	key := expandLabel(sha256.New, clientSecret, "quic key", 16)
	iv := expandLabel(sha256.New, clientSecret, "quic iv", 12)
	hpKey := expandLabel(sha256.New, clientSecret, "quic hp", 16)

	// ---- 去头部保护 (RFC 9001 §5.4) ----
	if len(pkt) < pnOffset+4+16 {
		return "", ErrTruncated
	}
	sample := pkt[pnOffset+4 : pnOffset+4+16]
	hpCipher, err := aes.NewCipher(hpKey)
	if err != nil {
		return "", err
	}
	mask := make([]byte, 16)
	hpCipher.Encrypt(mask, sample)

	header := make([]byte, pnOffset+4)
	copy(header, pkt[:pnOffset+4])
	header[0] = pkt[0] ^ (mask[0] & 0x0f)
	pnLen := int(header[0]&0x03) + 1
	header = header[:pnOffset+pnLen]
	var pn uint64
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] = pkt[pnOffset+i] ^ mask[1+i]
		pn = pn<<8 | uint64(header[pnOffset+i])
	}

	// ---- AES-GCM 解密载荷 ----
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	aead, err := cipher.NewGCM(mustAES(key))
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, nonce, pkt[pnOffset+pnLen:], header)
	if err != nil {
		return "", ErrDecrypt
	}

	// ---- 遍历帧,找 CRYPTO ----
	return sniFromFrames(plain)
}

func sniFromFrames(d []byte) (string, error) {
	for len(d) > 0 {
		typ, n := readVarint(d)
		if n == 0 {
			return "", ErrTruncated
		}
		d = d[n:]
		switch typ {
		case 0x00: // PADDING
			continue
		case 0x01: // PING
			continue
		case 0x06: // CRYPTO
			offV, n := readVarint(d)
			if n == 0 {
				return "", ErrTruncated
			}
			d = d[n:]
			ln, n := readVarint(d)
			if n == 0 || len(d) < n+int(ln) {
				return "", ErrTruncated
			}
			data := d[n : n+int(ln)]
			if offV != 0 {
				return "", errors.New("crypto frame offset != 0, reassembly unsupported")
			}
			if len(data) < 4 || data[0] != 0x01 {
				return "", tlssni.ErrNotClientHello
			}
			return tlssni.ParseClientHelloBody(data[4:])
		case 0x02, 0x03: // ACK
			d = skipACK(d, typ == 0x03)
			if d == nil {
				return "", ErrTruncated
			}
		default:
			// 客户端首个 Initial 通常只有 CRYPTO+PADDING,其他帧直接放弃
			return "", errors.New("unexpected frame before CRYPTO")
		}
	}
	return "", errors.New("no CRYPTO frame")
}

func skipACK(d []byte, hasECN bool) []byte {
	// largest_ack, delay, range_count, first_range
	var rangeCount uint64
	for i := 0; i < 4; i++ {
		v, n := readVarint(d)
		if n == 0 {
			return nil
		}
		if i == 2 {
			rangeCount = v
		}
		d = d[n:]
	}
	// 每个 range 是 gap+len 两个 varint
	for i := uint64(0); i < rangeCount*2; i++ {
		_, n := readVarint(d)
		if n == 0 {
			return nil
		}
		d = d[n:]
	}
	if hasECN { // ect0, ect1, ce
		for i := 0; i < 3; i++ {
			_, n := readVarint(d)
			if n == 0 {
				return nil
			}
			d = d[n:]
		}
	}
	return d
}

func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

func expandLabel(h func() hash.Hash, secret []byte, label string, length int) []byte {
	info := make([]byte, 0, 3+6+len(label)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, []byte("tls13 ")...)
	info = append(info, []byte(label)...)
	info = append(info, 0)
	r := hkdf.Expand(h, secret, info)
	out := make([]byte, length)
	if _, err := r.Read(out); err != nil {
		panic(err) // hkdf.Expand 的 Read 不会失败
	}
	return out
}

func mustAES(key []byte) cipher.Block {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return c
}
