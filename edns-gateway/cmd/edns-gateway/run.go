package main

import (
	"context"
	"flag"
	"log/slog"
	"time"

	"github.com/enterprise/edns-gateway/internal/audit"
	"github.com/enterprise/edns-gateway/internal/capture"
	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/dnsserver"
	"github.com/enterprise/edns-gateway/internal/engine"
	"github.com/enterprise/edns-gateway/internal/flowtrack"
	"github.com/enterprise/edns-gateway/internal/intel"
	"github.com/enterprise/edns-gateway/internal/metrics"
	"github.com/enterprise/edns-gateway/internal/pki"
	"github.com/enterprise/edns-gateway/internal/resolver"
)

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		return err
	}
	config.Replace(cfg)
	log := setupLogger(cfg.Logging)

	ctx, cancel := installSignal(func() { reloadConfig(*cfgPath, eng, log) })
	defer cancel()

	// ---- 情报库 ----
	store := intel.NewStore(cfg.Intel.UseBuiltin)
	loader := intel.NewFeedLoader(store, cfg.Intel, log)
	loader.LoadCache()
	go loader.Run(ctx)

	// ---- 审计与指标 ----
	aud := audit.New(cfg.Logging.AuditFile, cfg.Logging.JSON, cfg.Logging.RotateSize, log)
	defer aud.Close()
	reg := metrics.New()
	if cfg.Metrics.Listen != "" {
		reg.Listen(cfg.Metrics.Listen, cfg.Metrics.Path)
	}

	// ---- 流表与检测引擎 ----
	tracker := flowtrack.NewTracker(
		cfg.Detect.FlowIdleTimeout.Duration,
		cfg.Detect.FlowMaxLifetime.Duration,
		cfg.Detect.FlowCacheEntries,
		cfg.Detect.BehaviorWindow.Duration,
	)
	eng = engine.New(cfg, store, tracker, aud, reg, log)

	// ---- 内部解析器与加密 DNS 前端 ----
	rec := resolver.New(cfg.Resolver)
	if err := startDNSFrontends(ctx, cfg, rec, log); err != nil {
		return err
	}

	// ---- 周期 sweep ----
	go sweepLoop(ctx, eng)

	// ---- 采集 ----
	log.Info("edns-gateway 启动", "mode", cfg.Capture.Mode)
	switch cfg.Capture.Mode {
	case "pcap":
		src := buildPcapSource(cfg)
		return src.Run(eng.HandleMeta)
	case "nfqueue":
		nfq, err := capture.NewNfqueue(
			cfg.Capture.NfqueueID, cfg.Capture.NfqueueFamily,
			cfg.Capture.NfqueueLen, eng.Decide, log)
		if err != nil {
			return err
		}
		return nfq.Run(ctx)
	}
	return nil
}

// eng 包级变量仅供 SIGHUP 回调使用。
var eng *engine.Engine

func reloadConfig(path string, eng *engine.Engine, log *slog.Logger) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		log.Error("配置热更新失败，沿用旧配置", "err", err)
		return
	}
	config.Replace(cfg)
	if eng != nil {
		eng.Reload()
	}
	log.Info("配置热更新生效")
}

func buildPcapSource(cfg *config.Config) *capture.PcapSource {
	if cfg.Capture.PcapFile != "" {
		return capture.NewPcapFile(cfg.Capture.PcapFile)
	}
	return capture.NewPcapLive(cfg.Capture.Interface, cfg.Capture.BPFFilter, cfg.Capture.SnapLen)
}

func startDNSFrontends(ctx context.Context, cfg *config.Config,
	rec *resolver.Recursor, log *slog.Logger) error {
	mint, err := pki.LoadCA(cfg.Redirect.CertFile, cfg.Redirect.KeyFile)
	if err != nil {
		// 无证书时仅启动 DoH（h2c 测试模式）；生产必须提供 CA
		log.Warn("CA 加载失败，加密前端将受限（DoT/DoQ 不启动）", "err", err)
		doh, err := dnsserver.NewDoH(cfg.Redirect.DoHListen, "", "", rec, log)
		if err != nil {
			return err
		}
		go func() {
			if err := doh.Run(ctx); err != nil {
				log.Error("DoH 前端退出", "err", err)
			}
		}()
		return nil
	}

	doh, err := dnsserver.NewDoHWithTLS(cfg.Redirect.DoHListen,
		mint.TLSConfig([]string{"h2", "http/1.1"}), rec, log)
	if err != nil {
		return err
	}
	go func() {
		if err := doh.Run(ctx); err != nil {
			log.Error("DoH 前端退出", "err", err)
		}
	}()

	dot := dnsserver.NewDoTWithConfig(cfg.Redirect.DoTListen,
		mint.TLSConfig([]string{"dot"}), rec, log)
	go func() {
		if err := dot.Run(ctx); err != nil {
			log.Error("DoT 前端退出", "err", err)
		}
	}()

	doq := dnsserver.NewDoQWithConfig(cfg.Redirect.DoQListen,
		mint.TLSConfig([]string{"doq"}), cfg.Resolver.DoQMaxUDPPayload, rec, log)
	go func() {
		if err := doq.Run(ctx); err != nil {
			log.Error("DoQ 前端退出", "err", err)
		}
	}()
	return nil
}

func sweepLoop(ctx context.Context, eng *engine.Engine) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			eng.Sweep()
		}
	}
}
