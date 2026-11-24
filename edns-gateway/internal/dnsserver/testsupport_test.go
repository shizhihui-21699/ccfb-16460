package dnsserver

import (
	"io"
	"log/slog"
)

// testLogger 丢弃日志的静默 logger。
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
