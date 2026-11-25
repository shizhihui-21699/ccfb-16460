package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/dnsguard/internal/canary"
	"github.com/example/dnsguard/internal/config"
	"github.com/example/dnsguard/internal/dohfeed"
	"github.com/example/dnsguard/internal/nfq"
	"github.com/example/dnsguard/internal/nftset"
	"github.com/example/dnsguard/internal/policy"
)

func main() {
	cfgPath := flag.String("config", "/etc/dnsguard/dnsguard.yaml", "config file")
	pcapFile := flag.String("pcap", "", "offline pcap analysis mode (no nftables/nfqueue needed)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.LogOnly {
		log.Printf("running in LOG-ONLY mode (audit, no blocking)")
	}

	pol := policy.New(cfg.Exceptions, cfg.LogOnly)
	tracker := canary.New()

	// nftables 集合同步器(离线模式跳过)
	var nft *nftset.Syncer
	if *pcapFile == "" {
		nft, err = nftset.New(cfg.NftTable)
		if err != nil {
			log.Fatalf("nftables: %v", err)
		}
	}

	engine := nfq.NewEngine(pol, tracker, func(dst netip.Addr) {
		if nft == nil {
			return
		}
		if err := nft.AddBlocked(dst, time.Duration(cfg.BlockTimeoutSec)*time.Second); err != nil {
			log.Printf("add blocked %s: %v", dst, err)
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ---- DoH 清单定时刷新 ----
	fetcher := dohfeed.NewFetcher(cfg.Feeds.URLs, cfg.InternalResolvers)
	refresh := func() {
		list, err := fetcher.Fetch(ctx)
		if err != nil {
			log.Printf("feed refresh: %v (keeping old list)", err)
			return
		}
		pol.UpdateFeeds(list.Domains, list.IPs)
		if nft != nil {
			ips := make([]netip.Addr, 0, len(list.IPs))
			for a := range list.IPs {
				ips = append(ips, a)
			}
			if err := nft.SyncFeeds(ips); err != nil {
				log.Printf("nft sync: %v", err)
			}
		}
	}
	refresh() // 启动时先拉一次
	go func() {
		tk := time.NewTicker(cfg.Feeds.RefreshInterval)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				refresh()
			}
		}
	}()

	// ---- canary 周期报告 ----
	go tracker.ReportLoop(ctx.Done(), cfg.Canary.ReportInterval)

	// ---- metrics ----
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		log.Printf("metrics on %s", cfg.MetricsAddr)
		http.ListenAndServe(cfg.MetricsAddr, mux)
	}()

	// ---- 离线分析模式 ----
	if *pcapFile != "" {
		if err := engine.AnalyzePcap(*pcapFile); err != nil {
			log.Fatalf("pcap: %v", err)
		}
		return
	}

	log.Printf("dnsguard started, queue=%d", cfg.QueueNum)
	if err := engine.Run(ctx, cfg.QueueNum); err != nil && ctx.Err() == nil {
		log.Fatalf("nfqueue: %v", err)
	}
}
