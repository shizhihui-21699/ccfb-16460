package protocol

import (
	"sort"
	"sync"
)

// CryptoReassembler 按 QUIC 连接（DCID）重组 CRYPTO 帧流。
//
// 一个大的 TLS ClientHello 会被 quic-go 等实现拆到多个 Initial 数据包的
// CRYPTO 帧里，每帧带流内 offset。本结构收集分片并在连续覆盖 [0, n) 时
// 还原出完整（或当前可用前缀）的 CRYPTO 字节流。
//
// 网关只做被动识别，重组上限受控以防内存耗尽。
type CryptoReassembler struct {
	mu       sync.Mutex
	streams  map[string]*cryptoStream
	maxBytes int
}

type cryptoSeg struct {
	offset int
	data   []byte
}

type cryptoStream struct {
	segs     []cryptoSeg
	complete bool // 已观测到覆盖起始且足够解析的连续前缀
}

// NewCryptoReassembler 创建重组器，maxBytes 为单连接 CRYPTO 缓冲上限。
func NewCryptoReassembler(maxBytes int) *CryptoReassembler {
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	return &CryptoReassembler{streams: make(map[string]*cryptoStream), maxBytes: maxBytes}
}

// Add 追加一个 CRYPTO 帧分片，返回当前可连续读取的 CRYPTO 前缀字节。
// 返回的 ok=false 表示尚无连续前缀（起始分片未到）。
func (r *CryptoReassembler) Add(dcidKey string, offset int, data []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.streams[dcidKey]
	if st == nil {
		st = &cryptoStream{}
		r.streams[dcidKey] = st
	}
	if offset+len(data) > r.maxBytes {
		// 超上限只截断保留范围内的部分，识别所需的 ClientHello 前部不受影响
		if remain := r.maxBytes - offset; remain > 0 {
			data = data[:remain]
		} else {
			return r.contiguous(st)
		}
	}
	// 去重：同 offset 分片（重传）直接忽略
	for _, s := range st.segs {
		if s.offset == offset && len(s.data) == len(data) {
			return r.contiguous(st)
		}
	}
	st.segs = append(st.segs, cryptoSeg{offset: offset, data: append([]byte(nil), data...)})
	return r.contiguous(st)
}

// contiguous 在锁内计算从 offset 0 开始的连续字节。
func (r *CryptoReassembler) contiguous(st *cryptoStream) ([]byte, bool) {
	if len(st.segs) == 0 {
		return nil, false
	}
	sort.Slice(st.segs, func(i, j int) bool { return st.segs[i].offset < st.segs[j].offset })
	// 必须有覆盖 offset 0 的分片
	if st.segs[0].offset != 0 {
		return nil, false
	}
	need := 0
	for _, s := range st.segs {
		if s.offset > need {
			break // 出现空洞，连续前缀到此为止
		}
		if end := s.offset + len(s.data); end > need {
			need = end
		}
	}
	buf := make([]byte, need)
	for _, s := range st.segs {
		if s.offset >= need {
			break
		}
		n := copy(buf[s.offset:], s.data)
		_ = n
	}
	return buf, true
}

// Drop 回收某连接的重组状态（流结束或超时清理时调用）。
func (r *CryptoReassembler) Drop(dcidKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.streams, dcidKey)
}

// Stats 返回当前跟踪的连接数（metrics 用）。
func (r *CryptoReassembler) Stats() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}
