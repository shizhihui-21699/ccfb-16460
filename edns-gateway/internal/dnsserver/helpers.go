package dnsserver

import (
	"encoding/base64"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
)

// errEmptyBase64 空 dns 参数。
var errEmptyBase64 = errors.New("empty base64 input")

// slogToStd 把 slog.Logger 适配到标准库 log（http.Server.ErrorLog 需要）。
func slogToStd(l *slog.Logger) *log.Logger {
	if l == nil {
		return log.Default()
	}
	return log.New(&slogWriter{l: l}, "", 0)
}

type slogWriter struct{ l *slog.Logger }

func (w *slogWriter) Write(p []byte) (int, error) {
	w.l.Error("http server", "msg", string(p))
	return len(p), nil
}

// addrFromHTTP 从 HTTP 请求中提取客户端 IP（兼容 X-Forwarded-For 透明代理场景）。
func addrFromHTTP(req *http.Request) netip.Addr {
	// 透明代理（tproxy/DNAT）场景下 RemoteAddr 即真实客户端
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a
		}
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		if a, err := netip.ParseAddr(net.ParseIP(xff).String()); err == nil {
			return a
		}
	}
	return netip.Addr{}
}

// decodeBase64URL 解码 RFC 8484 的 dns 参数（URL-safe，有无填充均可）。
func decodeBase64URL(s string) ([]byte, error) {
	if s == "" {
		return nil, errEmptyBase64
	}
	enc := base64.RawURLEncoding
	if v, err := enc.DecodeString(s); err == nil {
		return v, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
