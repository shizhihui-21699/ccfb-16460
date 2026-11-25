// Package dohfeed 定时拉取公开 DoH 服务器清单(域名 + IP),
// 并用内部解析器把域名解析成 IP,产出域名匹配表和 nftables IP 集合。
// 解决"公共解析服务地址经常变化"的问题:清单自动刷新,无需人工维护。
package dohfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// List 是一份 DoH 服务器清单。
type List struct {
	Domains map[string]struct{} // SNI 匹配用,小写
	IPs     map[netip.Addr]struct{}
}

func NewList() *List {
	return &List{Domains: map[string]struct{}{}, IPs: map[netip.Addr]struct{}{}}
}

// Fetcher 拉取并解析清单。
type Fetcher struct {
	URLs     []string
	Resolver *net.Resolver // 指向内部解析器,避免解析清单本身又绕过管控
	Client   *http.Client
}

// NewFetcher 用内部解析器构造。resolvers 形如 ["10.0.0.53"]。
func NewFetcher(urls []string, resolvers []string) *Fetcher {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", resolvers[0]+":53")
		},
	}
	return &Fetcher{
		URLs:     urls,
		Resolver: r,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch 拉取所有清单源并合并,域名解析成 IP。
func (f *Fetcher) Fetch(ctx context.Context) (*List, error) {
	out := NewList()
	var errs []string
	for _, u := range f.URLs {
		domains, ips, err := f.fetchOne(ctx, u)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		for _, d := range domains {
			out.Domains[d] = struct{}{}
		}
		for _, ip := range ips {
			out.IPs[ip] = struct{}{}
		}
	}
	// 域名 → IP(走内部解析器,结果即内部视角,同时刷新内部缓存)
	for d := range out.Domains {
		addrs, err := f.Resolver.LookupIP(ctx, "ip", d)
		if err != nil {
			continue // 域名失效是常态,忽略
		}
		for _, a := range addrs {
			if na, ok := netip.AddrFromSlice(a); ok {
				out.IPs[na.Unmap()] = struct{}{}
			}
		}
	}
	var err error
	if len(errs) > 0 && len(out.Domains) == 0 && len(out.IPs) == 0 {
		err = fmt.Errorf("all feeds failed: %s", strings.Join(errs, "; "))
	}
	log.Printf("dohfeed: %d domains, %d ips", len(out.Domains), len(out.IPs))
	return out, err
}

func (f *Fetcher) fetchOne(ctx context.Context, url string) (domains []string, ips []netip.Addr, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, err
	}
	// JSON 格式(curl wiki doh-servers)或行文本格式(dibdot 等)
	trim := strings.TrimSpace(string(body))
	if strings.HasPrefix(trim, "[") || strings.HasPrefix(trim, "{") {
		return parseJSON(trim)
	}
	return parseLines(trim)
}

// parseLines 解析行文本清单:每行一个 IP/CIDR/域名,# 开头为注释。
func parseLines(text string) (domains []string, ips []netip.Addr, err error) {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// 去掉行尾注释
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		token := fields[0]
		// hosts 文件格式 "0.0.0.0 domain":第一个字段是 IP 时取第二个
		if len(fields) >= 2 {
			if _, e := netip.ParseAddr(fields[0]); e == nil {
				token = fields[1]
			}
		}
		if a, e := netip.ParseAddr(token); e == nil {
			ips = append(ips, a.Unmap())
			continue
		}
		if p, e := netip.ParsePrefix(token); e == nil {
			// 小网段展开,大网段只记网络地址(防止清单里混入大段)
			if ones, bits := p.Bits(), p.Addr().BitLen(); bits-ones <= 8 {
				for a := p.Masked().Addr(); p.Contains(a); a = a.Next() {
					ips = append(ips, a.Unmap())
				}
			}
			continue
		}
		if isDomain(token) {
			domains = append(domains, strings.ToLower(token))
		}
	}
	return domains, ips, sc.Err()
}

// parseJSON 解析 curl wiki 的 doh-servers JSON:[{"name":..,"url":"https://host/path","ips":[...]}]
func parseJSON(text string) (domains []string, ips []netip.Addr, err error) {
	var arr []struct {
		URL string   `json:"url"`
		IPs []string `json:"ips"`
	}
	if e := json.Unmarshal([]byte(text), &arr); e != nil {
		return nil, nil, e
	}
	for _, item := range arr {
		if item.URL != "" {
			host := item.URL
			host = strings.TrimPrefix(host, "https://")
			host = strings.TrimPrefix(host, "http://")
			if i := strings.IndexAny(host, "/:"); i >= 0 {
				host = host[:i]
			}
			if isDomain(host) {
				domains = append(domains, strings.ToLower(host))
			}
		}
		for _, s := range item.IPs {
			if a, e := netip.ParseAddr(s); e == nil {
				ips = append(ips, a.Unmap())
			}
		}
	}
	return domains, ips, nil
}

func isDomain(s string) bool {
	if len(s) < 4 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}
