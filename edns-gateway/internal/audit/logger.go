// Package audit 输出加密 DNS 识别审计事件：结构化 JSON、异步写入、文件轮转。
package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/enterprise/edns-gateway/internal/core"
)

// Logger 异步审计日志器。
type Logger struct {
	mu      sync.Mutex
	writer  io.WriteCloser
	path    string
	json    bool
	rotSize int64
	current int64
	log     *slog.Logger

	queue  chan core.AuditEvent
	closed chan struct{}
}

// New 创建日志器。path 为空时写 stdout。
func New(path string, jsonFormat bool, rotateSizeMB int64, log *slog.Logger) *Logger {
	l := &Logger{
		path:    path,
		json:    jsonFormat,
		rotSize: rotateSizeMB * 1024 * 1024,
		log:     log,
		queue:   make(chan core.AuditEvent, 4096),
		closed:  make(chan struct{}),
	}
	l.openSink()
	go l.loop()
	return l
}

func (l *Logger) openSink() {
	if l.path == "" {
		l.writer = nopCloser{os.Stdout}
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.log.Error("审计文件打开失败，降级 stdout", "path", l.path, "err", err)
		l.writer = nopCloser{os.Stdout}
		l.path = ""
		return
	}
	if st, err := f.Stat(); err == nil {
		l.current = st.Size()
	}
	l.writer = f
}

func (l *Logger) loop() {
	defer close(l.closed)
	for ev := range l.queue {
		l.write(ev)
	}
}

// Emit 非阻塞投递；队列满时丢弃并计数（不能反压抓包主路径）。
func (l *Logger) Emit(ev core.AuditEvent) {
	select {
	case l.queue <- ev:
	default:
		droppedAudit.Add(1)
	}
}

func (l *Logger) write(ev core.AuditEvent) {
	var line []byte
	if l.json {
		line, _ = json.Marshal(ev)
		line = append(line, '\n')
	} else {
		line = []byte(textFormat(ev) + "\n")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rotSize > 0 && l.path != "" && l.current+int64(len(line)) > l.rotSize {
		l.rotate()
	}
	n, err := l.writer.Write(line)
	if err != nil {
		l.log.Error("审计写入失败", "err", err)
		return
	}
	l.current += int64(n)
}

// rotate 简单轮转：当前文件改名 .1（覆盖旧轮转），重新打开。
func (l *Logger) rotate() {
	if c, ok := l.writer.(io.Closer); ok {
		_ = c.Close()
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		l.log.Warn("审计轮转失败", "err", err)
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.writer = nopCloser{os.Stdout}
		l.path = ""
		return
	}
	l.writer = f
	l.current = 0
}

// Close 冲刷队列并关闭文件。
func (l *Logger) Close() {
	close(l.queue)
	<-l.closed
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.writer.Close()
}

func textFormat(ev core.AuditEvent) string {
	sni := ev.SNI
	if sni == "" {
		sni = "-"
	}
	return ev.Time.Format("2006-01-02T15:04:05.000Z07:00") + " " +
		ev.Action + " " + ev.Protocol + " score=" + itoa(ev.Score) +
		" " + ev.Src + "->" + ev.Dst + " sni=" + sni + " " + ev.Reason
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
