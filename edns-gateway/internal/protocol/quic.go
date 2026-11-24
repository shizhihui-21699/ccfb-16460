package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
)

// QUIC 版本号。
const (
	QUICv1 uint32 = 0x00000001
	QUICv2 uint32 = 0x6b3343cf
)

// RFC 9001 §5.2（v1）与 RFC 9369（v2）定义的 Initial 盐值（公开常量，非秘密）。
var quicSalt = map[uint32][]byte{
	QUICv1: {
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
		0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a,
	},
	// RFC 9369 §3.2（与 quic-go 实现核对一致）
	QUICv2: {
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
		0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
		0xf9, 0xbd, 0x2e, 0xd9,
	},
}

// QUIC 帧类型常量。
const (
	framePadding         = 0x00
	framePing            = 0x01
	frameCrypto          = 0x06
	frameAck             = 0x02
	frameAckECN          = 0x03
	frameConnectionClose = 0x1c
)

// ErrNotQUICInitial 不是可解析的 QUIC Initial（短头、不支持的版本或格式错误）。
var ErrNotQUICInitial = errors.New("not a quic initial packet")

// QUICParseResult QUIC Initial 解密结果。
type QUICParseResult struct {
	Version uint32
	DCID    []byte
	SCID    []byte
	Token   []byte
	Hello   *ParsedClientHello
	ALPN    []string // 便捷副本，与 Hello.ALPN 一致
}

// 变长整数（RFC 9000 §16）最大值 2^62-1。
func readQUICVarint(b []byte, off int) (uint64, int, error) {
	if off >= len(b) {
		return 0, off, ErrNotQUICInitial
	}
	first := b[off]
	prefix := first >> 6
	n := 1 << prefix // 1,2,4,8 字节
	if off+n > len(b) {
		return 0, off, ErrNotQUICInitial
	}
	var v uint64
	switch n {
	case 1:
		v = uint64(first & 0x3f)
	case 2:
		v = uint64(b[off]&0x3f)<<8 | uint64(b[off+1])
	case 4:
		v = uint64(b[off]&0x3f)<<24 | uint64(b[off+1])<<16 |
			uint64(b[off+2])<<8 | uint64(b[off+3])
	default:
		v = uint64(b[off]&0x3f)<<56 | uint64(b[off+1])<<48 |
			uint64(b[off+2])<<40 | uint64(b[off+3])<<32 |
			uint64(b[off+4])<<24 | uint64(b[off+5])<<16 |
			uint64(b[off+6])<<8 | uint64(b[off+7])
	}
	return v, off + n, nil
}

// QUICInitialFrames 一个 Initial 包解密后得到的帧与头部信息。
type QUICInitialFrames struct {
	Version uint32
	DCID    []byte
	SCID    []byte
	Token   []byte
	Frames  []CryptoFrame
}

// DecryptQUICInitial 只做头部解析、Initial 解密与 CRYPTO 帧提取，
// 不解析内层 ClientHello，供调用方跨数据包重组 CRYPTO 流。
func DecryptQUICInitial(packet []byte) (*QUICInitialFrames, error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return nil, ErrNotQUICInitial
	}
	formByte := packet[0]
	version := binary.BigEndian.Uint32(packet[1:5])
	salt, ok := quicSalt[version]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported version 0x%x", ErrNotQUICInitial, version)
	}

	off := 5
	dcidLen := int(packet[off])
	off++
	if off+dcidLen > len(packet) {
		return nil, ErrNotQUICInitial
	}
	dcid := append([]byte(nil), packet[off:off+dcidLen]...)
	off += dcidLen

	scidLen := int(packet[off])
	off++
	if off+scidLen > len(packet) {
		return nil, ErrNotQUICInitial
	}
	scid := append([]byte(nil), packet[off:off+scidLen]...)
	off += scidLen

	wireType := (formByte & 0x30) >> 4
	isInitialV1 := version == QUICv1 && wireType == 0
	isInitialV2 := version == QUICv2 && wireType == 1
	if !isInitialV1 && !isInitialV2 {
		return nil, fmt.Errorf("%w: long header wireType=%d is not initial", ErrNotQUICInitial, wireType)
	}

	var token []byte
	if version == QUICv1 {
		tokLen, newOff, err := readQUICVarint(packet, off)
		if err != nil {
			return nil, err
		}
		off = newOff
		if off+int(tokLen) > len(packet) {
			return nil, ErrNotQUICInitial
		}
		token = packet[off : off+int(tokLen)]
		off += int(tokLen)
	}

	remainLen, newOff, err := readQUICVarint(packet, off)
	if err != nil {
		return nil, err
	}
	off = newOff
	if off+int(remainLen) > len(packet) {
		return nil, ErrNotQUICInitial
	}
	plain, _, err := decryptInitial(version, salt, dcid, packet, off, off+int(remainLen))
	if err != nil {
		return nil, fmt.Errorf("decrypt initial: %w", err)
	}
	frames, err := ExtractCryptoFrames(plain)
	if err != nil {
		return nil, err
	}
	return &QUICInitialFrames{
		Version: version, DCID: dcid, SCID: scid, Token: token, Frames: frames,
	}, nil
}

// markQUICJA4 把 JA4 指纹首字符改为 q，表示承载于 QUIC（官方 JA4 约定）。
func markQUICJA4(hello *ParsedClientHello) {
	if len(hello.JA4) > 0 {
		hello.JA4 = "q" + hello.JA4[1:]
	}
}

// MarkQUICJA4 导出包装，供 flowtrack 重组路径使用。
func MarkQUICJA4(hello *ParsedClientHello) { markQUICJA4(hello) }

// ParseQUICInitial 解析一个 UDP 数据报中的首个 QUIC Initial 包。
//
// 安全模型：QUIC Initial 的密钥由公开盐值 + 客户端生成的 DCID 经 HKDF 派生，
// 任何中间设备都可按 RFC 9001 还原出 ClientHello（这正是 RFC 刻意保证的可探测性，
// 用于负载均衡与中间盒审计）。1-RTT 应用数据无法也不会被解析。
func ParseQUICInitial(packet []byte) (*QUICParseResult, error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		// 短头包（已完成握手的 1-RTT）无法解析，直接跳过
		return nil, ErrNotQUICInitial
	}
	formByte := packet[0]
	version := binary.BigEndian.Uint32(packet[1:5])
	salt, ok := quicSalt[version]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported version 0x%x", ErrNotQUICInitial, version)
	}

	off := 5
	dcidLen := int(packet[off])
	off++
	if off+dcidLen > len(packet) {
		return nil, ErrNotQUICInitial
	}
	dcid := append([]byte(nil), packet[off:off+dcidLen]...)
	off += dcidLen

	scidLen := int(packet[off])
	off++
	if off+scidLen > len(packet) {
		return nil, ErrNotQUICInitial
	}
	scid := append([]byte(nil), packet[off:off+scidLen]...)
	off += scidLen

	// 长头包类型编码在 form byte 的 bit4-5（RFC 9000 §17.2 表 4）。
	// v1 线编码：Initial=0b00、0-RTT=0b01、Handshake=0b10、Retry=0b11；
	// RFC 9369 把 v2 的 Initial 改到 0b01（与 v1 的 0-RTT 位置交换）。
	wireType := (formByte & 0x30) >> 4
	isInitialV1 := version == QUICv1 && wireType == 0
	isInitialV2 := version == QUICv2 && wireType == 1
	if !isInitialV1 && !isInitialV2 {
		return nil, fmt.Errorf("%w: long header wireType=%d is not initial", ErrNotQUICInitial, wireType)
	}

	var token []byte
	if version == QUICv1 {
		tokLen, newOff, err := readQUICVarint(packet, off)
		if err != nil {
			return nil, err
		}
		off = newOff
		if off+int(tokLen) > len(packet) {
			return nil, ErrNotQUICInitial
		}
		token = packet[off : off+int(tokLen)]
		off += int(tokLen)
	}
	// v2 移除了 Initial token 字段

	// 剩余长度（packet number + 加密 payload）
	remainLen, newOff, err := readQUICVarint(packet, off)
	if err != nil {
		return nil, err
	}
	off = newOff
	if off+int(remainLen) > len(packet) {
		return nil, ErrNotQUICInitial
	}
	// remainLen = packet number(4 字节区) + 密文 + tag 的长度，
	// 据此界定本 Initial 包边界（数据报可能 coalesce 了后续 Handshake 包）。
	plain, pnLen, err := decryptInitial(version, salt, dcid, packet, off, off+int(remainLen))
	if err != nil {
		return nil, fmt.Errorf("decrypt initial: %w", err)
	}
	_ = pnLen

	frames, err := ExtractCryptoFrames(plain)
	if err != nil {
		return nil, err
	}
	cryptoData := assembleCrypto(frames, cryptoMaxOffset(frames))
	hello, err := ParseTLSClientHello(cryptoData)
	if err != nil {
		return nil, fmt.Errorf("parse inner clienthello: %w", err)
	}
	// JA4 首字符改为 q 以区分 QUIC 承载（官方 JA4 约定）
	markQUICJA4(hello)

	return &QUICParseResult{
		Version: version,
		DCID:    dcid,
		SCID:    scid,
		Token:   token,
		Hello:   hello,
		ALPN:    hello.ALPN,
	}, nil
}

// decryptInitial 执行 Initial 密钥派生、去头保护与 AEAD 解密。
//
//	wholePacket: 完整 UDP 数据报（样本与 AAD 都按整包偏移计算）
//	headerEnd:   packet number 4 字节区在 wholePacket 中的起始偏移
//	packetEnd:   本 Initial 包结束偏移（Length 字段界定，排除 coalesced 包）
func decryptInitial(version uint32, salt, dcid, wholePacket []byte,
	headerEnd, packetEnd int) ([]byte, int, error) {
	// RFC 9001 §5.2：initial_secret = HKDF-Extract(salt, DCID)
	initialSecret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, 0, err
	}

	clientSecretLabel := "client in"
	if version == QUICv2 {
		clientSecretLabel = "quicv2 client in"
	}
	clientSecret := hkdfExpandLabel(initialSecret, nil, clientSecretLabel, sha256.Size)

	keyLabel, ivLabel := "quic key", "quic iv"
	if version == QUICv2 {
		keyLabel, ivLabel = "quicv2 key", "quicv2 iv"
	}
	key := hkdfExpandLabel(clientSecret, nil, keyLabel, 16)
	iv := hkdfExpandLabel(clientSecret, nil, ivLabel, 12)

	hpLabel := "quic hp"
	if version == QUICv2 {
		hpLabel = "quicv2 hp"
	}
	hpKey := hkdfExpandLabel(clientSecret, nil, hpLabel, 16)

	// 长头在 wholePacket 中的布局（RFC 9000 §17.2，经 RFC 9001 附录 A.2 与
	// 真实 quic-go 客户端报文双重验证）：
	//   [0]                     头首字节（高 4 位固定/类型，低 4 位受头保护）
	//   [1 .. headerEnd-1]     版本/DCID/SCID/token/Length（明文，不受保护）
	//   [headerEnd .. +3]      packet number 4 字节区（受头保护，仅前 pnLen 字节有效）
	//   [headerEnd+pnLen .. ]  密文 + AEAD tag（pnLen<4 时紧跟有效 PN，不留空）
	// 样本固定取 PN 4 字节区之后的 16 字节，即 wholePacket[headerEnd+4 : headerEnd+20]。
	if len(wholePacket) < headerEnd+20 {
		return nil, 0, ErrNotQUICInitial
	}
	sample := wholePacket[headerEnd+4 : headerEnd+20]

	mask, err := headerProtectionMask(hpKey, sample)
	if err != nil {
		return nil, 0, err
	}

	// 去头保护（RFC 9001 §5.4，对照 quic-go header_protector.apply）：
	//   长头首字节（wholePacket[0]）异或 mask[0] 低 4 位；
	//   PN 4 字节区（wholePacket[headerEnd] 起）逐字节异或 mask[1..]。
	firstByte := wholePacket[0] ^ (mask[0] & 0x0f)
	pnLen := int(firstByte&0x03) + 1

	// 保存原始 PN 4 字节区；pnLen<4 时，AAD 中未使用字节保持原始密文
	origPN := append([]byte(nil), wholePacket[headerEnd:headerEnd+4]...)
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = origPN[i] ^ mask[1+i]
	}
	var pn uint64
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	// AAD = 去保护后的完整长头：wholePacket[0] 到有效 PN 结束。
	// 复制原包，写回去保护后的首字节与 PN（未使用的 PN 位置还原为原始值）。
	aadPkt := append([]byte(nil), wholePacket...)
	aadPkt[0] = firstByte
	copy(aadPkt[headerEnd:headerEnd+4], origPN)
	copy(aadPkt[headerEnd:headerEnd+pnLen], pnBytes)
	aad := aadPkt[:headerEnd+pnLen]

	// 密文从有效 PN 之后（headerEnd+pnLen）开始，到本包 Length 边界结束。
	// 注意不能用固定的 headerEnd+4：PN 实际长度 pnLen 可能小于 4，
	// 多切会把属于密文的字节丢掉导致 AEAD 校验失败。
	ciphertext := wholePacket[headerEnd+pnLen : packetEnd]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	// nonce：pn 右对齐进 8 字节缓冲，前补 4 零字节成 12 字节，再与 IV 异或
	var pnBuf [8]byte
	for i, b := range pnBytes {
		pnBuf[8-pnLen+i] = b
	}
	nonce := make([]byte, 12)
	copy(nonce[4:], pnBuf[:])
	for i := range nonce {
		nonce[i] ^= iv[i]
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("aead open: %w (pn=%d)", err, pn)
	}
	return plain, pnLen, nil
}

// headerProtectionMask 用 AES-ECB(hpKey, sample) 生成 16 字节掩码。
// QUIC v1/v2 的 Initial 强制使用 AES-128-GCM，HP 对应 AES-ECB，
// 因此这里不考虑 ChaCha20 分支（1-RTT 才可能协商，本解析器不处理）。
func headerProtectionMask(hpKey, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	// aes.Block 本身就是 ECB 单块加密
	block.Encrypt(mask, sample)
	return mask, nil
}

// hkdfExpandLabel 实现 RFC 8446 §7.1 的 HKDF-Expand-Label，QUIC 所有
// Initial 密钥派生都使用该结构（而非裸 HKDF-Expand）。
//
//	HkdfLabel 结构：
//	  uint16 length; opaque label<7..255> ("tls13 " + label);
//	  opaque context<0..255>;
func hkdfExpandLabel(secret, context []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	buf := make([]byte, 0, 3+len(fullLabel)+1+len(context))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(length))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, byte(len(fullLabel)))
	buf = append(buf, fullLabel...)
	buf = append(buf, byte(len(context)))
	buf = append(buf, context...)

	out, err := hkdf.Expand(sha256.New, secret, string(buf), length)
	if err != nil {
		// 标签均来自协议常量，失败只可能是库级异常
		panic(err)
	}
	return out
}

// CryptoFrame 解密后的一个 QUIC CRYPTO 帧（流偏移 + 数据）。
type CryptoFrame struct {
	Offset int
	Data   []byte
}

// ExtractCryptoFrames 在解密后的 Initial payload 中提取所有 CRYPTO 帧，
// 保留各自的流 offset，供跨数据包重组（RFC 9000 §19.6）。
func ExtractCryptoFrames(payload []byte) ([]CryptoFrame, error) {
	var out []CryptoFrame
	off := 0
	for off < len(payload) {
		frameType, newOff, err := readQUICVarint(payload, off)
		if err != nil {
			return nil, err
		}
		off = newOff

		switch frameType {
		case framePadding, framePing:
			// 无载荷，继续
		case frameCrypto:
			cryptoOff, o2, err := readQUICVarint(payload, off)
			if err != nil {
				return nil, err
			}
			cryptoLen, o3, err := readQUICVarint(payload, o2)
			if err != nil {
				return nil, err
			}
			off = o3
			if off+int(cryptoLen) > len(payload) {
				return nil, ErrNotQUICInitial
			}
			out = append(out, CryptoFrame{
				Offset: int(cryptoOff),
				Data:   append([]byte(nil), payload[off:off+int(cryptoLen)]...),
			})
			off += int(cryptoLen)
		case frameAck, frameAckECN:
			// ACK 帧结构复杂且不含 ClientHello；正常 Initial 中它在 CRYPTO 之后
			return out, nil
		case frameConnectionClose:
			return nil, errors.New("initial contains CONNECTION_CLOSE")
		default:
			// 未知帧：Initial 中可合法出现的类型有限，遇到即停止
			return out, nil
		}
	}
	return out, nil
}

// cryptoMaxOffset 返回分片覆盖的最大结束偏移。
func cryptoMaxOffset(segs []CryptoFrame) int {
	maxOff := 0
	for _, s := range segs {
		if end := s.Offset + len(s.Data); end > maxOff {
			maxOff = end
		}
	}
	return maxOff
}

// assembleCrypto 把同包内的分片按 offset 拼回连续缓冲（可能含前导空洞，留零）。
func assembleCrypto(segs []CryptoFrame, maxOff int) []byte {
	if len(segs) == 0 {
		return nil
	}
	buf := make([]byte, maxOff)
	for _, s := range segs {
		copy(buf[s.Offset:], s.Data)
	}
	return buf
}

// 编译期保证 tls 包被引用（ALPN 常量等供其他文件扩展使用）。
var _ = tls.VersionTLS13
