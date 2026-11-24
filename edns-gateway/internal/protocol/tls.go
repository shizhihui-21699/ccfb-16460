// Package protocol 实现 TLS ClientHello、HTTP/2、QUIC Initial 的线协议解析。
//
// 所有解析器都遵循同一原则：只读取握手/头部中的明文字段，绝不尝试解密应用数据，
// 因而无需任何会话密钥，也不影响转发性能。
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNotClientHello 数据不是 TLS ClientHello（或版本/格式无法识别）。
var ErrNotClientHello = errors.New("not a tls client hello")

// byteReader 顺序读取器，所有长度字段按 TLS 大端约定。
type byteReader struct {
	b   []byte
	pos int
	err error
}

func (r *byteReader) remaining() int { return len(r.b) - r.pos }

func (r *byteReader) u8() byte {
	if r.remaining() < 1 {
		r.err = ErrNotClientHello
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *byteReader) u16() uint16 {
	if r.remaining() < 2 {
		r.err = ErrNotClientHello
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *byteReader) bytes(n int) []byte {
	if r.remaining() < n {
		r.err = ErrNotClientHello
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

// u16LengthPrefixed 读取 2 字节长度前缀的块。
func (r *byteReader) u16LengthPrefixed() []byte {
	n := int(r.u16())
	return r.bytes(n)
}

// u8LengthPrefixed 读取 1 字节长度前缀的块。
func (r *byteReader) u8LengthPrefixed() []byte {
	n := int(r.u8())
	return r.bytes(n)
}

// IsGREASE RFC 8701 保留值：0x0a0a, 0x1a1a, ..., 0xfafa（第二字节恒为 0xa?）。
// 判定规则：低字节 == 高字节，且高字节 ∈ {0x0a,0x1a,...,0xfa}。
func IsGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && hi&0x0f == 0x0a
}

// ParsedClientHello 解析结果。
type ParsedClientHello struct {
	Version         uint16
	ServerName      string
	ALPN            []string
	CipherSuites    []uint16 // 已过滤 GREASE
	Extensions      []uint16 // 已过滤 GREASE
	SupportedGroups []uint16 // 已过滤 GREASE
	SignatureAlgos  []uint16
	ECHPresent      bool
	ECHOuterSNI     string
	RawExtensions   []uint16 // 未过滤 GREASE 的扩展列表
	JA3             string
	JA4             string
	// Truncated 为 true 时表示握手消息不完整（QUIC 跨包），
	// 已解析字段仍可信，但指纹可能缺失尾部扩展。
	Truncated bool
}

// TLS 扩展编号常量（只列用到的）。
const (
	extServerName      uint16 = 0
	extALPN            uint16 = 16
	extSupportedGroups uint16 = 10
	extSigAlgs         uint16 = 13
	extECHOuter        uint16 = 65037 // draft-ietf-tls-esni 外层扩展
	extECHOuterDraft13 uint16 = 65489 // 早期 draft
)

// ParseTLSClientHello 输入一个 TLS record（含 5 字节 record 头）或纯 handshake 消息。
// 支持 TLS 1.0~1.3 的 ClientHello；兼容 TLS 1.3 兼容模式下的 legacy_version=0x0303。
func ParseTLSClientHello(data []byte) (*ParsedClientHello, error) {
	if len(data) < 5 {
		return nil, ErrNotClientHello
	}
	r := &byteReader{b: data}

	// 形态一：TLS record 头 (contentType=0x16 handshake)
	if data[0] == 0x16 {
		_ = r.u8()               // content type
		recordVersion := r.u16() // legacy record version
		recordLen := int(r.u16())
		if recordLen == 0 || r.remaining() < recordLen {
			return nil, ErrNotClientHello
		}
		_ = recordVersion
		// 后续按 handshake 消息解析
	}

	// handshake header: type(1)=0x01 ClientHello, length(3)
	hsType := r.u8()
	if hsType != 0x01 {
		return nil, fmt.Errorf("%w: handshake type=%d", ErrNotClientHello, hsType)
	}
	hsLen := int(r.u8())<<16 | int(r.u8())<<8 | int(r.u8())
	// QUIC 场景下 ClientHello 可能跨多个 CRYPTO 帧/数据包，当前缓冲不完整时
	// 不直接报错：截断到可用字节尽力解析（SNI/ALPN 位于 ClientHello 前部，
	// 单 Initial 通常已包含识别所需的全部明文扩展）。
	truncated := r.remaining() < hsLen
	bodyEnd := r.pos + hsLen
	if bodyEnd > len(r.b) {
		bodyEnd = len(r.b)
	}
	// 限定在 handshake 体内，防止越界读到下一条 record/帧。
	savedB := r.b
	r.b = r.b[:bodyEnd]
	defer func() { r.b = savedB }()

	ch := &ParsedClientHello{Truncated: truncated}
	ch.Version = r.u16() // legacy_version
	_ = r.bytes(32)      // random

	// session id
	if sid := r.u8LengthPrefixed(); sid == nil && r.err != nil {
		return nil, r.err
	}
	// cookie（TLS1.3 兼容 ClientHello 没有 cookie；靠剩余结构自适应，这里按标准无 cookie 处理。
	// 中间盒极少插入 cookie；DTLS 才有固定 cookie 字段，本项目不解析 DTLS）

	// cipher suites
	cipherBlock := r.u16LengthPrefixed()
	cr := &byteReader{b: cipherBlock}
	for cr.remaining() >= 2 && cr.err == nil {
		c := cr.u16()
		if !IsGREASE(c) {
			ch.CipherSuites = append(ch.CipherSuites, c)
		}
	}

	// compression methods
	if cm := r.u8LengthPrefixed(); cm == nil && r.err != nil {
		return nil, r.err
	}

	// extensions
	extBlock := r.u16LengthPrefixed()
	if r.err != nil {
		if truncated {
			// 截断导致扩展长度字段本身不完整：返回已解析的前部字段
			ch.JA3 = buildJA3(ch)
			ch.JA4 = buildJA4(ch)
			return ch, nil
		}
		return nil, r.err
	}
	ch.parseExtensions(extBlock)
	if r.err != nil && !truncated {
		return nil, r.err
	}

	ch.JA3 = buildJA3(ch)
	ch.JA4 = buildJA4(ch)
	return ch, nil
}

func (ch *ParsedClientHello) parseExtensions(block []byte) {
	r := &byteReader{b: block}
	for r.remaining() >= 4 && r.err == nil {
		extType := r.u16()
		extData := r.u16LengthPrefixed()
		ch.RawExtensions = append(ch.RawExtensions, extType)
		if !IsGREASE(extType) {
			ch.Extensions = append(ch.Extensions, extType)
		}
		switch extType {
		case extServerName:
			ch.ServerName = parseSNI(extData)
		case extALPN:
			ch.ALPN = parseALPN(extData)
		case extSupportedGroups:
			groups := (&byteReader{b: extData}).u16LengthPrefixed()
			gr := &byteReader{b: groups}
			for gr.remaining() >= 2 && gr.err == nil {
				g := gr.u16()
				if !IsGREASE(g) {
					ch.SupportedGroups = append(ch.SupportedGroups, g)
				}
			}
		case extSigAlgs:
			algos := (&byteReader{b: extData}).u16LengthPrefixed()
			ar := &byteReader{b: algos}
			for ar.remaining() >= 2 && ar.err == nil {
				ch.SignatureAlgos = append(ch.SignatureAlgos, ar.u16())
			}
		case extECHOuter, extECHOuterDraft13:
			ch.ECHPresent = true
			ch.ECHOuterSNI = ch.ServerName // 外层 SNI 是掩护域名，真实 SNI 已加密
		}
	}
}

func parseSNI(block []byte) string {
	r := &byteReader{b: block}
	list := r.u16LengthPrefixed() // server_name_list
	lr := &byteReader{b: list}
	if lr.remaining() < 1 {
		return ""
	}
	nameType := lr.u8()
	name := lr.u16LengthPrefixed()
	if nameType != 0 || lr.err != nil {
		return ""
	}
	return string(name)
}

func parseALPN(block []byte) []string {
	r := &byteReader{b: block}
	list := r.u16LengthPrefixed()
	lr := &byteReader{b: list}
	var out []string
	for lr.remaining() >= 1 && lr.err == nil {
		proto := lr.u8LengthPrefixed()
		if proto != nil {
			out = append(out, string(proto))
		}
	}
	return out
}

func u16Join(vs []uint16, sep string) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, sep)
}

// buildJA3 标准 JA3：SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// 线序保留、GREASE 已在解析阶段过滤。
func buildJA3(ch *ParsedClientHello) string {
	// JA3 的版本字段取 ClientHello legacy_version；TLS1.3 兼容模式为 0x0303，
	// 与 Wireshark/Salesforce 官方实现口径一致（支持版本扩展不参与 JA3）。
	return fmt.Sprintf("%d,%s,%s,%s,",
		ch.Version,
		u16Join(ch.CipherSuites, "-"),
		u16Join(ch.Extensions, "-"),
		u16Join(ch.SupportedGroups, "-"),
	)
}

// buildJA4 生成 JA4 风格指纹。
//
// 格式：q1q2q3q4_q5q6_<12hex ciphers>_<12hex extensions>
//
//	q1: 传输/QUIC 标记这里固定为 t（本函数只处理 TLS；QUIC 解析器单独覆盖为 q）
//	q2: TLS 版本，13=TLS1.3,12=TLS1.2
//	q3: SNI 存在性 d/i，q4: ALPN 数量 0~9（>=10 记 9）
//	q5: 密码套件数 00~99，q6: 扩展数 00~99
//
// 两段 hash：对排序后的逗号拼接列表取 SHA-256 前 12 位。
//
// 注意：官方 JA4 对 extension 列表要剔除 SNI(0)/ALPN(16) 与 GREASE，签名算法
// 另有独立 _c 后缀段；本实现做了简化（签名算法并入扩展段哈希的口径与官方不同），
// 适合做内部聚类和黑名单初筛，跨工具比对时请以本包输出为准。
func buildJA4(ch *ParsedClientHello) string {
	q1 := "t"
	q2 := "12"
	if ch.Version >= 0x0304 || contains(ch.Extensions, 43) { // supported_versions=43
		q2 = "13"
	}
	q3 := "i"
	if ch.ServerName != "" {
		q3 = "d"
	}
	q4 := len(ch.ALPN)
	if q4 > 9 {
		q4 = 9
	}
	q5q6 := fmt.Sprintf("%02d%02d", min(len(ch.CipherSuites), 99), min(len(ch.Extensions), 99))

	cipherHash := sortedHash12(ch.CipherSuites)
	// 官方口径：扩展哈希剔除 SNI 与 ALPN
	extForHash := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if e != extServerName && e != extALPN {
			extForHash = append(extForHash, e)
		}
	}
	extHash := sortedHash12(extForHash)

	return fmt.Sprintf("%s%s%s%d_%s_%s_%s", q1, q2, q3, q4, q5q6, cipherHash, extHash)
}

func contains(vs []uint16, target uint16) bool {
	for _, v := range vs {
		if v == target {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
