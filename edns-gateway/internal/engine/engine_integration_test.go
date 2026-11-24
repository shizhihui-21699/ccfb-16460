package engine

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/enterprise/edns-gateway/internal/audit"
	"github.com/enterprise/edns-gateway/internal/capture"
	"github.com/enterprise/edns-gateway/internal/config"
	"github.com/enterprise/edns-gateway/internal/core"
	"github.com/enterprise/edns-gateway/internal/flowtrack"
	"github.com/enterprise/edns-gateway/internal/intel"
	"github.com/enterprise/edns-gateway/internal/metrics"
)

// realClientHello 发起真实 TLS 握手并返回 ClientHello record 字节。
func realClientHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8192)
		n, _ := conn.Read(buf)
		got <- buf[:n]
	}()
	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		c := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: alpn})
		_ = c.Handshake()
	}()
	return <-got
}

// writePCAP 把若干 TCP payload 写成 pcap 文件（构造以太网/IPv4/TCP 包）。
type pcapStream struct {
	srcIP, dstIP     netip.Addr
	srcPort, dstPort uint16
	payloads         [][]byte
}

func writePCAP(t *testing.T, path string, streams []pcapStream) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	// 测试只验证解析逻辑，校验和由真实网卡/内核保证，这里关闭计算避免坏包
	serialize := gopacket.SerializeOptions{FixLengths: true}
	now := time.Now()
	for si, st := range streams {
		for pi, payload := range st.payloads {
			eth := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
				DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.IP(st.srcIP.AsSlice()),
				DstIP: net.IP(st.dstIP.AsSlice()),
			}
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(st.srcPort), DstPort: layers.TCPPort(st.dstPort),
				Seq: uint32(pi * 1000), Window: 65535, SYN: pi == 0,
			}
			if pi > 0 {
				tcp.PSH = true
			}
			buf := gopacket.NewSerializeBuffer()
			if pi == 0 {
				_ = gopacket.SerializeLayers(buf, serialize, eth, ip, tcp)
			} else {
				tcp.SYN = false
				_ = gopacket.SerializeLayers(buf, serialize, eth, ip, tcp,
					gopacket.Payload(payload))
			}
			ci := gopacket.CaptureInfo{
				Timestamp:     now.Add(time.Duration(si*10+pi) * time.Millisecond),
				CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes()),
			}
			if err := w.WritePacket(ci, buf.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestEngine_PCAPEndToEnd(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "trace.pcap")

	// 三类流：DoT（ALPN=dot + 853）、DoH 特征（SNI 命中 + h2）、普通网站
	dotHello := realClientHello(t, "dns.quad9.net", []string{"dot"})
	dohHello := realClientHello(t, "dns.google", []string{"h2"})
	normalHello := realClientHello(t, "www.example.com", []string{"h2", "http/1.1"})

	writePCAP(t, pcapPath, []pcapStream{
		{netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("9.9.9.9"), 40001, 853,
			[][]byte{{}, dotHello}},
		{netip.MustParseAddr("10.0.0.11"), netip.MustParseAddr("8.8.8.8"), 40002, 443,
			[][]byte{{}, dohHello}},
		{netip.MustParseAddr("10.0.0.12"), netip.MustParseAddr("198.51.100.30"), 40003, 443,
			[][]byte{{}, normalHello}},
	})

	// 用 analyze 同款接线
	cfg := config.Default()
	config.Replace(cfg)
	store := intel.NewStore(true)
	tracker := flowtrack.NewTracker(
		cfg.Detect.FlowIdleTimeout.Duration, cfg.Detect.FlowMaxLifetime.Duration,
		cfg.Detect.FlowCacheEntries, cfg.Detect.BehaviorWindow.Duration)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	aud := audit.New("", true, 0, log)
	reg := metrics.New()
	eng := New(cfg, store, tracker, aud, reg, log)

	var verdicts []*core.Verdict
	var auditEvents []core.AuditEvent
	eng.SetAuditSink(func(ev core.AuditEvent) {
		auditEvents = append(auditEvents, ev) // 含 observe 级识别结果
	})
	eng.ActionHook = func(v *core.Verdict) { verdicts = append(verdicts, v) }

	src := capture.NewPcapFile(pcapPath)
	if err := src.Run(eng.HandleMeta); err != nil {
		t.Fatalf("pcap 分析失败: %v", err)
	}
	eng.Sweep()

	// DoT（ALPN=dot + 853 + 情报）分数高，应产生 redirect/block 干预动作
	var sawDoTAction bool
	for _, v := range verdicts {
		if v.Protocol == core.ProtoDoT && v.Flow.Hello != nil &&
			v.Flow.Hello.SNI == "dns.quad9.net" {
			sawDoTAction = true
		}
	}
	if !sawDoTAction {
		t.Error("端到端未对 dns.quad9.net 的 DoT 流量产生干预动作")
	}

	// DoH 这条只有 SNI 情报 + h2（旁路无 dns-query 路径），判 observe，
	// 但必须被识别并写入审计，SNI 可见。
	var sawDoHSNI, normalSiteAbsent bool
	for _, ev := range auditEvents {
		if ev.SNI == "dns.google" && ev.Protocol == "DoH" {
			sawDoHSNI = true
		}
		if ev.SNI == "www.example.com" {
			normalSiteAbsent = true
		}
	}
	if !sawDoHSNI {
		t.Error("端到端未在审计中识别出 dns.google 的 DoH 流量")
	}
	if normalSiteAbsent {
		t.Error("普通网站 www.example.com 不应产生加密 DNS 审计事件")
	}
	if len(auditEvents) == 0 {
		t.Error("应产出至少一条审计事件")
	}
}

func TestEngine_ConfigReload(t *testing.T) {
	cfg := config.Default()
	config.Replace(cfg)
	store := intel.NewStore(true)
	tracker := flowtrack.NewTracker(time.Minute, time.Hour, 100, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := New(cfg, store, tracker, audit.New("", true, 0, log), metrics.New(), log)

	// 初始策略：dot 导流
	obs := &core.FlowObservation{
		Key: core.FlowKey{
			SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("9.9.9.9"),
			DstPort: 853, Protocol: core.TransportTCP,
		},
		Hello: &core.ClientHelloInfo{SNI: "dns.quad9.net", ALPN: []string{"dot"}},
	}
	v1 := eng.classifier.Classify(obs)
	if v1.Action != string(config.ActionRedirect) {
		t.Fatalf("初始动作应为 redirect，实际 %s", v1.Action)
	}

	// 热更新：把该 SNI 加白名单
	cfg2 := config.Default()
	cfg2.Policy.AllowSNI = []string{"dns.quad9.net"}
	config.Replace(cfg2)
	eng.Reload()

	v2 := eng.classifier.Classify(obs)
	if v2.Action != string(config.ActionAllowlist) {
		t.Errorf("热更新加白后应豁免，实际动作 %s", v2.Action)
	}
	_ = context.Background
}
