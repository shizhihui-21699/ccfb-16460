// Package nfq 是报文处理核心:从 NFQUEUE(或离线 pcap)读包,
// 识别 TLS/QUIC 的 SNI,交给策略引擎判定,并执行放行/丢弃。
package nfq

import (
	"net/netip"

	"github.com/example/dnsguard/internal/canary"
	"github.com/example/dnsguard/internal/policy"
	"github.com/example/dnsguard/internal/quicsni"
	"github.com/example/dnsguard/internal/tlssni"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BlockHook 在判定阻断后回调(用于把目标 IP 加入 nftables 动态封禁集)。
type BlockHook func(dst netip.Addr)

type Engine struct {
	pol     *policy.Engine
	tracker *canary.Tracker
	onBlock BlockHook
}

func NewEngine(pol *policy.Engine, tracker *canary.Tracker, onBlock BlockHook) *Engine {
	return &Engine{pol: pol, tracker: tracker, onBlock: onBlock}
}

// Process 处理一个 IP 报文(L3 起始),返回 true 表示放行。
func (e *Engine) Process(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	var (
		src, dst netip.Addr
	)
	switch data[0] >> 4 {
	case 4:
		var ip layers.IPv4
		if err := ip.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return true
		}
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
		return e.processL4(ip.Protocol, src, dst, ip.Payload)
	case 6:
		var ip layers.IPv6
		if err := ip.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return true
		}
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
		return e.processL4(ip.NextHeader, src, dst, ip.Payload)
	}
	return true
}

func (e *Engine) processL4(proto layers.IPProtocol, src, dst netip.Addr, payload []byte) bool {
	switch proto {
	case layers.IPProtocolTCP:
		var tcp layers.TCP
		if err := tcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return true
		}
		switch uint16(tcp.DstPort) {
		case 443:
			if len(tcp.Payload) == 0 {
				return true // SYN 等控制包直接放行,等有载荷的包
			}
			return e.checkTLS(src, dst, tcp.Payload)
		case 53:
			e.tracker.ObserveDNS(src) // 明文 DNS(nft 会 DNAT 回内部,这里只统计)
		}
	case layers.IPProtocolUDP:
		var udp layers.UDP
		if err := udp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return true
		}
		switch uint16(udp.DstPort) {
		case 443:
			return e.checkQUIC(src, dst, udp.Payload)
		case 53:
			e.tracker.ObserveDNS(src)
		}
	}
	return true
}

func (e *Engine) checkTLS(src, dst netip.Addr, payload []byte) bool {
	sni, err := tlssni.ServerName(payload)
	if err != nil {
		return true // 不是 ClientHello(可能是后续分片),放行;首个数据包才会被 queue
	}
	d := e.pol.CheckEncryptedDNS(src, dst, sni, "tls")
	policy.LogDecision("tls", src, dst, sni, d)
	if d.Verdict == policy.Drop {
		e.tracker.ObserveDoH(src)
		if e.onBlock != nil {
			e.onBlock(dst)
		}
		return false
	}
	return true
}

func (e *Engine) checkQUIC(src, dst netip.Addr, payload []byte) bool {
	sni, err := quicsni.ServerName(payload)
	if err != nil {
		return true // 非 Initial 或解析失败,放行(清单 IP 维度兜底)
	}
	d := e.pol.CheckEncryptedDNS(src, dst, sni, "quic")
	policy.LogDecision("quic", src, dst, sni, d)
	if d.Verdict == policy.Drop {
		e.tracker.ObserveDoH(src)
		if e.onBlock != nil {
			e.onBlock(dst)
		}
		return false
	}
	return true
}
