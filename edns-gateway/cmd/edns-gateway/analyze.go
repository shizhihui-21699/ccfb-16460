package main

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/enterprise/edns-gateway/internal/audit"
	"github.com/enterprise/edns-gateway/internal/capture"
	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/core"
	"github.com/enterprise/edns-gateway/internal/engine"
	"github.com/enterprise/edns-gateway/internal/flowtrack"
	"github.com/enterprise/edns-gateway/internal/intel"
	"github.com/enterprise/edns-gateway/internal/metrics"
)

// jsonlCollector 收集审计事件并编码为 JSON Lines。
type jsonlCollector struct {
	enc   *json.Encoder
	count int
}

func newCollector(enc *json.Encoder) *jsonlCollector { return &jsonlCollector{enc: enc} }

func (c *jsonlCollector) emit(ev core.AuditEvent) {
	if err := c.enc.Encode(ev); err == nil {
		c.count++
	}
}

func (c *jsonlCollector) flush() {}

// runAnalyze 离线分析 pcap：用默认/指定配置跑完整检测管线，把审计事件
// 以 JSON Lines 输出到文件或 stdout，用于取证复盘、阈值调参与回归测试。
func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	pcapFile := fs.String("f", "", "pcap/pcapng 文件路径（必填）")
	cfgFile := fs.String("c", "", "可选配置文件；不指定则用默认策略")
	outFile := fs.String("o", "", "JSONL 输出路径；不指定则输出 stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pcapFile == "" {
		fs.Usage()
		os.Exit(2)
	}

	var cfg *config.Config
	var err error
	if *cfgFile != "" {
		cfg, err = config.LoadFile(*cfgFile)
	} else {
		cfg = config.Default()
	}
	if err != nil {
		return err
	}
	config.Replace(cfg)
	log := setupLogger(config.LoggingConfig{JSON: true, Level: "error"})

	store := intel.NewStore(cfg.Intel.UseBuiltin)
	tracker := flowtrack.NewTracker(
		cfg.Detect.FlowIdleTimeout.Duration,
		cfg.Detect.FlowMaxLifetime.Duration,
		cfg.Detect.FlowCacheEntries,
		cfg.Detect.BehaviorWindow.Duration,
	)

	out := os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	collector := newCollector(json.NewEncoder(out))
	aud := audit.New("", true, 0, log)
	reg := metrics.New()
	eng := engine.New(cfg, store, tracker, aud, reg, log)
	eng.SetAuditSink(collector.emit)

	var packets int
	src := capture.NewPcapFile(*pcapFile)
	err = src.Run(func(meta flowtrack.Meta) {
		eng.HandleMeta(meta)
		packets++
	})
	eng.Sweep() // 冲刷尚未超时的流
	collector.flush()

	log.Info("离线分析完成", "packets", packets, "events", collector.count)
	return err
}
