package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// sortedHash12 对 uint16 列表排序、逗号拼接后取 SHA-256 前 12 个 hex 字符。
// 排序使指纹与服务端/客户端的通告顺序无关，符合 JA4 聚类意图。
func sortedHash12(vs []uint16) string {
	if len(vs) == 0 {
		// 空列表与"含一个值 0"要可区分：空集使用固定空串哈希
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])[:12]
	}
	cp := append([]uint16(nil), vs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	parts := make([]string, len(cp))
	for i, v := range cp {
		parts[i] = strconv.Itoa(int(v))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])[:12]
}
