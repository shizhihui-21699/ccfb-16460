// Package resolver 实现内部 DNS 转发核心：接收 wire-format DNS 报文，转发给
// 企业既有的内部递归服务器，从而让恶意域名拦截与审计策略对加密查询同样生效。
//
// DoH(RFC 8484)/DoT(RFC 7858)/DoQ(RFC 9250) 三个前端只负责承载协议，
// 所有查询最终都汇聚到 Recursor.Exchange 这一个入口。
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/enterprise/edns-gateway/internal/config"
)

// Recursor DNS 转发器。
type Recursor struct {
	upstream string
	fallback string
	timeout  time.Duration

	// 复用连接池（miekg/dns Client 内部已对 TCP 保持连接复用）
	udpClient *dns.Client
	tcpClient *dns.Client

	stats Stats
}

// Stats 运行指标。
type Stats struct {
	Queries           atomic.Uint64
	UpstreamErrors    atomic.Uint64
	BlockedByUpstream atomic.Uint64 // 上游返回 NXDOMAIN/REFUSED（即内部拦截生效）
	LatencyMicros     atomic.Uint64
}

// New 按配置构建转发器。
func New(cfg config.ResolverConfig) *Recursor {
	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &Recursor{
		upstream:  cfg.Upstream,
		fallback:  cfg.Fallback,
		timeout:   timeout,
		udpClient: &dns.Client{Net: "udp", Timeout: timeout},
		tcpClient: &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

// Exchange 处理一条 DNS 请求报文，返回响应报文（wire 格式）。
// transport 标注来源（"doh"/"dot"/"doq"），仅用于日志与指标。
func (r *Recursor) Exchange(ctx context.Context, queryWire []byte, transport string,
	clientAddr netip.Addr) ([]byte, error) {
	r.stats.Queries.Add(1)
	start := time.Now()
	defer func() { r.stats.LatencyMicros.Add(uint64(time.Since(start).Microseconds())) }()

	msg := new(dns.Msg)
	if err := msg.Unpack(queryWire); err != nil {
		return nil, fmt.Errorf("unpack dns query: %w", err)
	}
	if len(msg.Question) == 0 {
		return nil, errors.New("dns query without question")
	}

	resp, err := r.forwardWithRetry(ctx, msg)
	if err != nil {
		r.stats.UpstreamErrors.Add(1)
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError || resp.Rcode == dns.RcodeRefused {
		r.stats.BlockedByUpstream.Add(1)
	}

	wire, err := resp.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns response: %w", err)
	}
	return wire, nil
}

// forwardWithRetry 先 UDP，截断（TC=1）自动升级 TCP；上游失败时尝试兜底。
func (r *Recursor) forwardWithRetry(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp, _, err := r.udpClient.ExchangeContext(ctx, msg, r.upstream)
	if err != nil && r.fallback != "" {
		resp, _, err = r.udpClient.ExchangeContext(ctx, msg, r.fallback)
	}
	if err != nil {
		return nil, fmt.Errorf("upstream exchange: %w", err)
	}
	if resp.Truncated {
		tcpResp, _, tcpErr := r.tcpClient.ExchangeContext(ctx, msg, r.upstream)
		if tcpErr == nil {
			return tcpResp, nil
		}
	}
	return resp, nil
}

// Snapshot 返回指标快照。
func (r *Recursor) Snapshot() (queries, upstreamErrs, blocked uint64, avgLatencyMicros uint64) {
	q := r.stats.Queries.Load()
	if q == 0 {
		return 0, 0, 0, 0
	}
	return q, r.stats.UpstreamErrors.Load(), r.stats.BlockedByUpstream.Load(),
		r.stats.LatencyMicros.Load() / q
}

// Upstream 返回当前上游地址（健康检查展示用）。
func (r *Recursor) Upstream() string { return r.upstream }
