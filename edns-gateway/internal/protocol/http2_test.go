package protocol

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// buildH2Request 构造一条包含 HTTP/2 前导、SETTINGS 与 HEADERS 帧的明文字节流。
func buildH2Request(t *testing.T, headers []hpack.HeaderField) []byte {
	t.Helper()
	var hpackBuf bytes.Buffer
	enc := hpack.NewEncoder(&hpackBuf)
	for _, h := range headers {
		if err := enc.WriteField(h); err != nil {
			t.Fatalf("hpack 编码失败: %v", err)
		}
	}

	var out bytes.Buffer
	out.WriteString(H2Preface)
	// 空 SETTINGS 帧（4 字节头 + 0 载荷）
	out.Write([]byte{0, 0, 0, FrameSettings, 0, 0, 0, 0, 0})
	// HEADERS 帧（END_HEADERS=0x4），单帧承载
	block := hpackBuf.Bytes()
	hdr := []byte{
		byte(len(block) >> 16), byte(len(block) >> 8), byte(len(block)),
		FrameHeaders, 0x4, 0, 0, 0, 0,
	}
	out.Write(hdr)
	out.Write(block)
	return out.Bytes()
}

func TestHTTP2_DoHPathDetection(t *testing.T) {
	stream := buildH2Request(t, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/dns-query"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "dns.google"},
		{Name: "content-type", Value: "application/dns-message"},
	})

	p := NewHTTP2Parser(16)
	got, err := p.Feed(stream)
	if err != nil {
		t.Fatalf("HTTP/2 解析失败: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("期望 1 个流，实际 %d", len(got))
	}
	req := got[0]
	if !IsDoHPath(req.Path) {
		t.Errorf("应识别为 DoH 路径，path=%q", req.Path)
	}
	if req.Authority != "dns.google" {
		t.Errorf("authority=%q", req.Authority)
	}
	if req.ContentType != "application/dns-message" {
		t.Errorf("content-type=%q", req.ContentType)
	}
}

func TestHTTP2_NonDoHPath(t *testing.T) {
	stream := buildH2Request(t, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":authority", Value: "example.com"},
	})
	p := NewHTTP2Parser(16)
	got, err := p.Feed(stream)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("期望 1 个流，实际 %d", len(got))
	}
	if IsDoHPath(got[0].Path) {
		t.Error("普通网页路径不应被判为 DoH")
	}
}

func TestHTTP2_QueryStringVariant(t *testing.T) {
	if !IsDoHPath("/dns-query?dns=AAAB") {
		t.Error("带 query string 的 /dns-query 应识别为 DoH")
	}
	if IsDoHPath("/dns-query-evil") {
		t.Error("前缀相似但不同的路径不应误判")
	}
	if IsDoHPath("/other/dns-query") {
		t.Error("非根路径的 dns-query 不应误判")
	}
}

func TestHTTP2_PartialFeed(t *testing.T) {
	stream := buildH2Request(t, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/dns-query"},
	})
	p := NewHTTP2Parser(16)
	// 分两次喂入，第一次只给前导的一半 -> 需要更多数据
	if _, err := p.Feed(stream[:len(H2Preface)-3]); err != ErrNeedMoreData {
		t.Errorf("不完整前导应返回 ErrNeedMoreData，实际 %v", err)
	}
	got, err := p.Feed(stream[len(H2Preface)-3:])
	if err != nil {
		t.Fatalf("二次喂入失败: %v", err)
	}
	if len(got) != 1 || !IsDoHPath(got[0].Path) {
		t.Error("分片喂入后应正确还原 DoH 请求")
	}
}
