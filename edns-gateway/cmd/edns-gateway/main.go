// edns-gateway 企业出口加密 DNS 识别与导流网关。
//
// 子命令：
//
//	run      以守护进程模式运行检测管线与加密 DNS 兼容前端
//	analyze  离线分析 pcap/pcapng 文件，输出识别结果（取证/调参/回归测试）
//	cert     生成企业根 CA 与演示叶子证书（生产建议接入企业 PKI/ACME）
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/enterprise/edns-gateway/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		if err := runDaemon(args); err != nil {
			fatal(err)
		}
	case "analyze":
		if err := runAnalyze(args); err != nil {
			fatal(err)
		}
	case "cert":
		if err := runCert(args); err != nil {
			fatal(err)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `edns-gateway — 企业出口加密 DNS 识别与导流网关

用法:
  edns-gateway run -c config.yaml          守护进程模式
  edns-gateway analyze -f trace.pcap       离线 pcap 分析
  edns-gateway cert -out certs/            生成本地 CA 与演示证书
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}

// setupLogger 按配置构建结构化日志器。
func setupLogger(cfg config.LoggingConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.JSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}

// installSignal 返回在 SIGINT/SIGTERM 取消的 context，SIGHUP 触发热更新。
func installSignal(reload func()) (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if reload != nil {
					reload()
				}
			}
		}
	}()
	return ctx, cancel
}
