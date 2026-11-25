// Package tlssni 从 TLS ClientHello 中提取 SNI,用于识别 DoH 连接的目标。
// 支持两种输入:TCP 载荷(TLS record 封装)和 QUIC CRYPTO 帧里的裸握手消息。
package tlssni

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrNotClientHello = errors.New("not a TLS ClientHello")
	ErrTruncated      = errors.New("truncated ClientHello")
)

// ServerName 从 TCP 载荷(以 TLS record 开头)中提取 SNI。
// 抓包只抓连接初始的少量字节,record 可能被截断,此时尽力解析已有部分。
func ServerName(payload []byte) (string, error) {
	if len(payload) < 5 {
		return "", ErrTruncated
	}
	// 跳过可能的 TCP 时间戳等干扰后,第一个 record 必须是 handshake
	if payload[0] != 0x16 { // content_type = handshake
		return "", ErrNotClientHello
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	body := payload[5:]
	if len(body) > recLen {
		body = body[:recLen]
	}
	return parseHandshake(body)
}

func parseHandshake(d []byte) (string, error) {
	if len(d) < 4 {
		return "", ErrTruncated
	}
	if d[0] != 0x01 { // handshake_type = client_hello
		return "", ErrNotClientHello
	}
	hlen := int(d[1])<<16 | int(d[2])<<8 | int(d[3])
	body := d[4:]
	if len(body) > hlen {
		body = body[:hlen]
	}
	return ParseClientHelloBody(body)
}

// ParseClientHelloBody 解析 ClientHello 消息体(handshake 头之后的内容)。
// 导出供 QUIC CRYPTO 帧复用。
func ParseClientHelloBody(d []byte) (string, error) {
	// legacy_version(2) + random(32)
	if len(d) < 34 {
		return "", ErrTruncated
	}
	d = d[34:]

	// session_id
	if len(d) < 1 {
		return "", ErrTruncated
	}
	sidLen := int(d[0])
	d = d[1:]
	if len(d) < sidLen {
		return "", ErrTruncated
	}
	d = d[sidLen:]

	// cipher_suites
	if len(d) < 2 {
		return "", ErrTruncated
	}
	csLen := int(binary.BigEndian.Uint16(d))
	d = d[2:]
	if len(d) < csLen {
		return "", ErrTruncated
	}
	d = d[csLen:]

	// compression_methods
	if len(d) < 1 {
		return "", ErrTruncated
	}
	compLen := int(d[0])
	d = d[1:]
	if len(d) < compLen {
		return "", ErrTruncated
	}
	d = d[compLen:]

	// extensions
	if len(d) < 2 {
		return "", nil // 无扩展,无 SNI
	}
	extTotal := int(binary.BigEndian.Uint16(d))
	d = d[2:]
	if len(d) < extTotal {
		extTotal = len(d) // 截断容忍
	}
	d = d[:extTotal]

	for len(d) >= 4 {
		etype := binary.BigEndian.Uint16(d)
		elen := int(binary.BigEndian.Uint16(d[2:]))
		d = d[4:]
		if len(d) < elen {
			return "", ErrTruncated
		}
		edata := d[:elen]
		d = d[elen:]
		if etype == 0x0000 { // server_name
			return parseSNI(edata)
		}
	}
	return "", nil // 有扩展但无 SNI(可能 ECH 或裸 IP 连接)
}

func parseSNI(d []byte) (string, error) {
	if len(d) < 2 {
		return "", ErrTruncated
	}
	listLen := int(binary.BigEndian.Uint16(d))
	d = d[2:]
	if len(d) < listLen {
		listLen = len(d)
	}
	d = d[:listLen]
	for len(d) >= 3 {
		typ := d[0]
		nlen := int(binary.BigEndian.Uint16(d[1:3]))
		d = d[3:]
		if len(d) < nlen {
			return "", ErrTruncated
		}
        if typ == 0 { // host_name
			name := string(d[:nlen])
			if !validHostname(name) {
				return "", errors.New("invalid SNI hostname")
			}
			return strings.ToLower(strings.TrimSuffix(name, ".")), nil
		}
		d = d[nlen:]
	}
	return "", nil
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}
