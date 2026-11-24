// Package metrics 以 Prometheus 文本暴露格式提供运行指标，避免引入重依赖。
// 线程安全，标签维度受控（协议/动作各只有个位数枚举值）。
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Registry 极简指标注册中心。
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*counterVec
	gauges   map[string]*gauge
	help     map[string]string
}

type counterVec struct {
	mu     sync.Mutex
	values map[string]*atomic.Uint64
}

type gauge struct{ v atomic.Int64 }

// New 创建注册中心并注册标准指标。
func New() *Registry {
	r := &Registry{
		counters: make(map[string]*counterVec),
		gauges:   make(map[string]*gauge),
		help:     make(map[string]string),
	}
	r.help["edns_verdicts_total"] = "加密 DNS 判定总数，按协议与动作分标签"
	r.help["edns_signals_total"] = "信号命中次数"
	r.help["edns_audit_dropped_total"] = "审计队列满导致的丢弃数"
	r.help["edns_resolver_queries_total"] = "内部加密 DNS 前端查询数"
	r.help["edns_resolver_blocked_total"] = "内部递归拦截（NXDOMAIN/REFUSED）数"
	r.help["edns_resolver_upstream_errors_total"] = "上游递归错误数"
	r.help["edns_active_flows"] = "当前流表条目数"
	r.help["edns_intel_domains"] = "情报库域名条目数"
	r.help["edns_intel_ips"] = "情报库 IP 条目数"
	for _, n := range []string{
		"edns_verdicts_total", "edns_signals_total", "edns_audit_dropped_total",
		"edns_resolver_queries_total", "edns_resolver_blocked_total",
		"edns_resolver_upstream_errors_total",
	} {
		r.counters[n] = &counterVec{values: make(map[string]*atomic.Uint64)}
	}
	for _, n := range []string{"edns_active_flows", "edns_intel_domains", "edns_intel_ips"} {
		r.gauges[n] = &gauge{}
	}
	return r
}

// IncCounter 计数器 +1，labels 为 "k,v,k,v..." 形式。
func (r *Registry) IncCounter(name string, labels ...string) {
	r.AddCounter(name, 1, labels...)
}

// AddCounter 计数器累加。
func (r *Registry) AddCounter(name string, delta uint64, labels ...string) {
	r.mu.RLock()
	vec, ok := r.counters[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	key := labelKey(labels)
	vec.mu.Lock()
	c, ok := vec.values[key]
	if !ok {
		c = &atomic.Uint64{}
		vec.values[key] = c
	}
	vec.mu.Unlock()
	c.Add(delta)
}

// SetGauge 设置仪表盘值。
func (r *Registry) SetGauge(name string, v int64) {
	r.mu.RLock()
	g, ok := r.gauges[name]
	r.mu.RUnlock()
	if ok {
		g.v.Store(v)
	}
}

// Handler 返回 /metrics 风格的 HTTP handler。
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.render(w)
	})
}

// Listen 在独立地址提供指标端点（通常绑定 127.0.0.1 或运维网段）。
func (r *Registry) Listen(addr, path string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(path, r.Handler())
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	return srv
}

func (r *Registry) render(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.counters)+len(r.gauges))
	for n := range r.counters {
		names = append(names, n)
	}
	for n := range r.gauges {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if help, ok := r.help[n]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", n, help)
		}
		if vec, ok := r.counters[n]; ok {
			fmt.Fprintf(w, "# TYPE %s counter\n", n)
			vec.mu.Lock()
			keys := make([]string, 0, len(vec.values))
			for k := range vec.values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if k == "" {
					fmt.Fprintf(w, "%s %d\n", n, vec.values[k].Load())
				} else {
					fmt.Fprintf(w, "%s{%s} %d\n", n, k, vec.values[k].Load())
				}
			}
			vec.mu.Unlock()
		}
		if g, ok := r.gauges[n]; ok {
			fmt.Fprintf(w, "# TYPE %s gauge\n", n)
			fmt.Fprintf(w, "%s %d\n", n, g.v.Load())
		}
	}
}

// labelKey 把扁平 k,v 列表转为 Prometheus 标签串。
func labelKey(labels []string) string {
	if len(labels)%2 != 0 {
		labels = labels[:len(labels)-1]
	}
	out := ""
	for i := 0; i < len(labels); i += 2 {
		if out != "" {
			out += ","
		}
		out += fmt.Sprintf("%s=%q", labels[i], labels[i+1])
	}
	return out
}
