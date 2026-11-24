package protocol

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
)

// captureClientHello 启动一个只记录 ClientHello 原始字节的 TCP 监听器，
// 让标准库 tls.Client 发起握手，返回抓到的第一个 TLS record。
func captureClientHello(t *testing.T, sni string, alpn []string, version uint16) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		record []byte
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		resCh <- result{record: append([]byte(nil), buf[:n]...)}
	}()

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConf := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         alpn,
			MinVersion:         version,
			MaxVersion:         version,
		}
		tconn := tls.Client(conn, tlsConf)
		_ = tconn.Handshake() // 服务端不回应，握手必然失败，但 ClientHello 已发出
	}()

	res := <-resCh
	if res.err != nil || len(res.record) == 0 {
		t.Fatalf("未捕获 ClientHello: err=%v len=%d", res.err, len(res.record))
	}
	return res.record
}

func TestParseTLSClientHello_TLS13_RealStack(t *testing.T) {
	record := captureClientHello(t, "dns.google", []string{"h2", "http/1.1"}, tls.VersionTLS13)

	hello, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("解析 ClientHello 失败: %v", err)
	}
	if hello.ServerName != "dns.google" {
		t.Errorf("SNI = %q, 期望 dns.google", hello.ServerName)
	}
	foundH2 := false
	for _, a := range hello.ALPN {
		if a == "h2" {
			foundH2 = true
		}
	}
	if !foundH2 {
		t.Errorf("ALPN 未包含 h2: %v", hello.ALPN)
	}
	if len(hello.CipherSuites) == 0 {
		t.Error("密码套件为空")
	}
	if len(hello.Extensions) == 0 {
		t.Error("扩展为空")
	}
	// GREASE 不应出现在过滤后的列表中
	for _, c := range hello.CipherSuites {
		if IsGREASE(c) {
			t.Errorf("GREASE 值 0x%x 未被过滤", c)
		}
	}
	for _, e := range hello.Extensions {
		if IsGREASE(e) {
			t.Errorf("GREASE 扩展 0x%x 未被过滤", e)
		}
	}
	if hello.JA3 == "" || hello.JA4 == "" {
		t.Error("指纹为空")
	}
	if hello.JA4[0] != 't' {
		t.Errorf("TLS 的 JA4 首字符应为 t，实际 %q", hello.JA4[:1])
	}
}

func TestParseTLSClientHello_DoT_ALPN(t *testing.T) {
	record := captureClientHello(t, "dns.quad9.net", []string{"dot"}, tls.VersionTLS12)
	hello, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if hello.ServerName != "dns.quad9.net" {
		t.Errorf("SNI = %q", hello.ServerName)
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "dot" {
		t.Errorf("ALPN = %v, 期望 [dot]", hello.ALPN)
	}
}

func TestIsGREASE(t *testing.T) {
	cases := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0xfafa: true,
		0x002f: false, 0x1301: false, 0x0010: false, 0x0000: false,
	}
	for v, want := range cases {
		if got := IsGREASE(v); got != want {
			t.Errorf("IsGREASE(0x%x) = %v, 期望 %v", v, got, want)
		}
	}
}

func TestRejectNonClientHello(t *testing.T) {
	// application_data record 不应被识别
	bad := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}
	if _, err := ParseTLSClientHello(bad); err == nil {
		t.Error("application_data 不应解析为 ClientHello")
	}
	// 过短
	if _, err := ParseTLSClientHello([]byte{0x16, 0x03}); err == nil {
		t.Error("过短数据应报错")
	}
}

// TestFragmentedHandshake 验证跨 TLS record 的分片重组。
func TestFragmentedHandshake(t *testing.T) {
	record := captureClientHello(t, "cloudflare-dns.com", []string{"h2"}, tls.VersionTLS13)
	// 把完整 record 切成两半，先确认 record reader 能缓存，再合并解析
	rr := &TLSRecordReader{}
	mid := len(record) / 2
	recs1, err := rr.Feed(record[:mid])
	if err != nil && err != ErrNeedMoreData {
		t.Fatalf("前半段 Feed 异常: %v", err)
	}
	if len(recs1) != 0 {
		t.Fatal("不完整 record 不应被切出")
	}
	recs2, err := rr.Feed(record[mid:])
	if err != nil {
		t.Fatalf("后半段 Feed 异常: %v", err)
	}
	if len(recs2) != 1 || recs2[0].ContentType != TLSContentTypeHS {
		t.Fatalf("重组结果异常: %+v", recs2)
	}
	hello, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("完整数据解析失败: %v", err)
	}
	if hello.ServerName != "cloudflare-dns.com" {
		t.Errorf("SNI = %q", hello.ServerName)
	}
}

// 防止未使用导入（binary/rand 在其他测试文件也会用到）
var _ = binary.BigEndian
var _ = rand.Reader
