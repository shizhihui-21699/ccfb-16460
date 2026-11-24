package protocol

import (
	"errors"
)

// TLS record 层常量。
const (
	TLSRecordHeaderLen = 5
	TLSContentTypeApp  = 23 // application_data
	TLSContentTypeHS   = 22 // handshake
)

// ErrNeedMoreData 数据不完整，等待同一 TCP 流的后续报文。
var ErrNeedMoreData = errors.New("need more data")

// TLSRecordReader 在 TCP 字节流上切分 TLS record。
// 一个 record 可能跨多个 TCP 段，多个 record 也可能在同一个段里；
// 本结构缓存不完整尾部，调用方按序 Feed 即可。
type TLSRecordReader struct {
	buf []byte
}

// Record 一条 TLS record 的视图。
type Record struct {
	ContentType byte
	Version     uint16
	Data        []byte
}

// Feed 追加新到达的 TCP 负载，返回可完整切出的 record。
// 非 TLS 数据（首字节不是合法 content type）返回错误，调用方可据此放弃协议解析。
func (r *TLSRecordReader) Feed(chunk []byte) ([]Record, error) {
	r.buf = append(r.buf, chunk...)
	var out []Record
	for len(r.buf) >= TLSRecordHeaderLen {
		ct := r.buf[0]
		if ct < 20 || ct > 25 { // 合法 TLS content type 区间
			return out, errors.New("not a tls record stream")
		}
		recLen := int(r.buf[3])<<8 | int(r.buf[4])
		if recLen > 16384+256 { // TLS record 上限 16KiB (+TLS1.3 膨胀)
			return out, errors.New("tls record length out of range")
		}
		if len(r.buf) < TLSRecordHeaderLen+recLen {
			return out, ErrNeedMoreData
		}
		ver := uint16(r.buf[1])<<8 | uint16(r.buf[2])
		out = append(out, Record{
			ContentType: ct,
			Version:     ver,
			Data:        append([]byte(nil), r.buf[TLSRecordHeaderLen:TLSRecordHeaderLen+recLen]...),
		})
		r.buf = r.buf[TLSRecordHeaderLen+recLen:]
	}
	return out, nil
}

// Pending 返回当前缓存的未消费字节数（调试/流淘汰用）。
func (r *TLSRecordReader) Pending() int { return len(r.buf) }
