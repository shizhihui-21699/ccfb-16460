package protocol

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// HTTP/2 帧常量。
const (
	H2Preface        = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	H2FrameHeaderLen = 9

	FrameData         = 0x0
	FrameHeaders      = 0x1
	FrameSettings     = 0x4
	FrameContinuation = 0x9
)

// HPACK 动态表容量：浏览器客户端一般通告 4096 或更大；
// 只做只读解析时取一个足够大的上限，遇到过大更新直接重置，避免恶意流撑内存。
const hpackMaxTableSize = 16384

// ParsedHTTP2Stream 从加密流中还原出的 HTTP/2 请求头（只取 DoH 判定需要的字段）。
type ParsedHTTP2Stream struct {
	Method      string
	Path        string
	Scheme      string
	Authority   string
	ContentType string
	Accept      string
	UserAgent   string
	// 所有头部的扁平副本，供扩展检测
	AllHeaders []hpack.HeaderField
}

// HTTP2Parser 在（解密后的）TLS record 序列上识别 HTTP/2 帧。
// 网关环境里 application_data 实际是密文，本解析器的真实数据来源是：
//  1. 离线 pcap 中导出的解密流量（SSLKEYLOGFILE 场景的运维分析）
//  2. 导流到本机后、由内部服务在 TLS 终止点拿到的明文
//  3. 单元测试构造的明文 HTTP/2 会话
//
// 在线纯旁路场景下 DoH 主要靠 SNI/ALPN/行为识别，本结构保证在任何能拿到明文
// 的部署形态中都具备 dns-query 路径级别的坐实能力。
type HTTP2Parser struct {
	buf          []byte
	sawPreface   bool
	hpackDecoder *hpack.Decoder
	streams      map[uint32]*ParsedHTTP2Stream
	// 当前 HEADERS 帧的拼装状态（支持 CONTINUATION）
	curStreamID    uint32
	curHeaderBlock bytes.Buffer
	inHeaders      bool
	maxStreams     int
}

// NewHTTP2Parser 创建解析器，maxStreams 限制同时跟踪的流数量以防内存膨胀。
func NewHTTP2Parser(maxStreams int) *HTTP2Parser {
	p := &HTTP2Parser{
		streams:    make(map[uint32]*ParsedHTTP2Stream),
		maxStreams: maxStreams,
	}
	p.hpackDecoder = hpack.NewDecoder(hpackMaxTableSize, nil)
	return p
}

var errNotHTTP2 = errors.New("not http/2 traffic")

// Feed 输入一段明文字节，返回新解析完成的流（HEADERS 解码完毕即输出，不必等 DATA）。
func (p *HTTP2Parser) Feed(chunk []byte) ([]*ParsedHTTP2Stream, error) {
	p.buf = append(p.buf, chunk...)
	var done []*ParsedHTTP2Stream

	if !p.sawPreface {
		if len(p.buf) < len(H2Preface) {
			return nil, ErrNeedMoreData
		}
		if string(p.buf[:len(H2Preface)]) != H2Preface {
			return nil, errNotHTTP2
		}
		p.buf = p.buf[len(H2Preface):]
		p.sawPreface = true
	}

	for len(p.buf) >= H2FrameHeaderLen {
		length := int(p.buf[0])<<16 | int(p.buf[1])<<8 | int(p.buf[2])
		frameType := p.buf[3]
		flags := p.buf[4]
		streamID := uint32(p.buf[5]&0x7f)<<16 | uint32(p.buf[6])<<8 | uint32(p.buf[7])
		if length > 1<<24-1 {
			return done, errors.New("http2 frame too large")
		}
		if len(p.buf) < H2FrameHeaderLen+length {
			return done, ErrNeedMoreData
		}
		payload := p.buf[H2FrameHeaderLen : H2FrameHeaderLen+length]
		p.buf = p.buf[H2FrameHeaderLen+length:]

		switch frameType {
		case FrameSettings:
			// SETTINGS ACK 之外的帧可能带 HPACK 表大小通告；hpack.Decoder 在 HEADERS
			// 内处理表更新，这里无需动作。
		case FrameHeaders:
			if len(payload) < 5 {
				continue
			}
			padLen := 0
			off := 0
			if flags&0x8 != 0 { // PADDED
				padLen = int(payload[0])
				off = 1
			}
			priorityLen := 0
			if flags&0x20 != 0 { // PRIORITY
				priorityLen = 5
			}
			if off+priorityLen >= len(payload) {
				continue
			}
			headerBlock := payload[off+priorityLen:]
			if padLen > 0 && padLen < len(headerBlock) {
				headerBlock = headerBlock[:len(headerBlock)-padLen]
			}
			p.curStreamID = streamID
			p.curHeaderBlock.Reset()
			p.curHeaderBlock.Write(headerBlock)
			p.inHeaders = true
			if flags&0x4 != 0 { // END_HEADERS
				if st := p.finishHeaders(); st != nil {
					done = append(done, st)
				}
			}
		case FrameContinuation:
			if !p.inHeaders {
				return done, errors.New("unexpected CONTINUATION frame")
			}
			p.curHeaderBlock.Write(payload)
			if flags&0x4 != 0 {
				if st := p.finishHeaders(); st != nil {
					done = append(done, st)
				}
			}
		case FrameData:
			// DoH 的 DNS 报文在 DATA 内且已加密，旁路不解析内容；
			// 路径命中已足够坐实 DoH。
		}
	}
	return done, nil
}

func (p *HTTP2Parser) finishHeaders() *ParsedHTTP2Stream {
	p.inHeaders = false
	id := p.curStreamID
	if _, ok := p.streams[id]; !ok {
		if len(p.streams) >= p.maxStreams {
			return nil
		}
		p.streams[id] = &ParsedHTTP2Stream{}
	}
	st := p.streams[id]

	// 动态表是连接级状态，必须复用同一个 hpack.Decoder；
	// 每块 HEADERS 只需切换发射回调填充当前流。
	p.hpackDecoder.SetEmitFunc(func(hf hpack.HeaderField) {
		st.AllHeaders = append(st.AllHeaders, hf)
		switch hf.Name {
		case ":method":
			st.Method = hf.Value
		case ":path":
			st.Path = hf.Value
		case ":scheme":
			st.Scheme = hf.Value
		case ":authority":
			st.Authority = hf.Value
		case "content-type":
			st.ContentType = hf.Value
		case "accept":
			st.Accept = hf.Value
		case "user-agent":
			st.UserAgent = hf.Value
		}
	})
	if _, err := p.hpackDecoder.Write(p.curHeaderBlock.Bytes()); err != nil {
		p.hpackDecoder.Close()
		p.hpackDecoder = hpack.NewDecoder(hpackMaxTableSize, nil)
		return nil
	}
	if st.Path == "" && st.Method == "" {
		return nil
	}
	// 输出后从跟踪表移除，控制内存；头部信息已在返回值里
	delete(p.streams, id)
	return st
}

// IsDoHPath 判断 :path 是否为 RFC 8484 的 DNS 查询端点。
// 严格匹配 /dns-query，兼容带 query string 的写法（如 /dns-query?dns=...）。
func IsDoHPath(path string) bool {
	if path == "/dns-query" {
		return true
	}
	if len(path) > len("/dns-query?") && path[:len("/dns-query?")] == "/dns-query?" {
		return true
	}
	return false
}

// String 便于日志输出。
func (s *ParsedHTTP2Stream) String() string {
	return fmt.Sprintf("%s :authority=%s :path=%s", s.Method, s.Authority, s.Path)
}
