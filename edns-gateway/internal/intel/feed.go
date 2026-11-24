package intel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/enterprise/edns-gateway/internal/config"
)

// FeedLoader 按配置周期拉取外部情报并合并进 Store。
type FeedLoader struct {
	store  *Store
	feeds  []config.FeedConfig
	every  time.Duration
	cache  string
	client *http.Client
	log    *slog.Logger
}

// NewFeedLoader 创建加载器。cacheFile 非空时，拉取成功会落盘，启动时若网络
// 不可用则从缓存恢复，避免网关重启后情报为空。
func NewFeedLoader(store *Store, cfg config.IntelConfig, log *slog.Logger) *FeedLoader {
	return &FeedLoader{
		store:  store,
		feeds:  cfg.Feeds,
		every:  cfg.RefreshEvery.Duration,
		cache:  cfg.CacheFile,
		client: &http.Client{Timeout: 15 * time.Second},
		log:    log,
	}
}

// Run 阻塞执行周期刷新，直到 ctx 取消。首次加载失败只告警不致命。
func (l *FeedLoader) Run(ctx context.Context) {
	if len(l.feeds) == 0 {
		return
	}
	if err := l.loadAll(ctx); err != nil {
		l.log.Warn("首次情报加载部分失败", "err", err)
	}
	ticker := time.NewTicker(l.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := l.loadAll(ctx); err != nil {
				l.log.Warn("情报周期刷新失败", "err", err)
			}
		}
	}
}

func (l *FeedLoader) loadAll(ctx context.Context) error {
	var firstErr error
	var merged []Entry
	for _, feed := range l.feeds {
		entries, err := l.loadOne(ctx, feed)
		if err != nil {
			l.log.Warn("加载情报源失败", "feed", feed.Name, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		l.log.Info("情报源加载完成", "feed", feed.Name, "entries", len(entries))
		merged = append(merged, entries...)
	}
	if len(merged) > 0 {
		l.store.Merge(merged)
		if l.cache != "" {
			if err := l.writeCache(merged); err != nil {
				l.log.Warn("写情报缓存失败", "err", err)
			}
		}
	}
	return firstErr
}

func (l *FeedLoader) loadOne(ctx context.Context, feed config.FeedConfig) ([]Entry, error) {
	var reader io.ReadCloser
	switch feed.Type {
	case "url":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.Path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := l.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("feed %s http %d", feed.Name, resp.StatusCode)
		}
		reader = resp.Body
	case "local":
		f, err := os.Open(feed.Path)
		if err != nil {
			return nil, err
		}
		reader = f
	default:
		return nil, fmt.Errorf("未知 feed 类型 %q", feed.Type)
	}
	defer reader.Close()
	return parseFeed(reader, feed.Category, feed.Name), nil
}

// parseFeed 支持的行格式：
//
//	8.8.8.8                     单 IP
//	192.0.2.0/24                CIDR
//	dns.example.com             域名
//	# 开头与空行忽略
//	支持 "IP,provider" 或 "IP provider" 附带厂商名
func parseFeed(r io.Reader, category, feedName string) []Entry {
	cat := parseCategory(category)
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		key := fields[0]
		provider := feedName
		if len(fields) > 1 && fields[1] != "" {
			provider = fields[1]
		}
		e := Entry{Key: strings.ToLower(key), Provider: provider, Cat: cat}
		if _, err := netip.ParseAddr(e.Key); err == nil {
			out = append(out, e)
			continue
		}
		if _, err := netip.ParsePrefix(e.Key); err == nil {
			out = append(out, e)
			continue
		}
		// 既不是 IP 也不是 CIDR，按域名处理
		if strings.Contains(e.Key, ".") {
			e.IsDomain = true
			out = append(out, e)
		}
	}
	return out
}

func parseCategory(c string) Category {
	switch strings.ToLower(c) {
	case "doh":
		return CatDoH
	case "dot":
		return CatDoT
	case "doq":
		return CatDoQ
	default:
		return CatDoH | CatDoT | CatDoQ
	}
}

// cacheFormat：每行 "category|key|provider|isdomain"
func (l *FeedLoader) writeCache(entries []Entry) error {
	tmp := l.cache + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, e := range entries {
		fmt.Fprintf(w, "%d|%s|%s|%t\n", e.Cat, e.Key, e.Provider, e.IsDomain)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return os.Rename(tmp, l.cache)
}

// LoadCache 启动时恢复本地缓存。
func (l *FeedLoader) LoadCache() int {
	if l.cache == "" {
		return 0
	}
	f, err := os.Open(l.cache)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "|")
		if len(parts) != 4 {
			continue
		}
		var cat Category
		fmt.Sscanf(parts[0], "%d", &cat)
		isDomain := parts[3] == "true"
		l.store.Merge([]Entry{{
			Key: parts[1], Provider: parts[2], Cat: cat, IsDomain: isDomain,
		}})
		n++
	}
	if n > 0 {
		l.log.Info("从本地缓存恢复情报", "entries", n)
	}
	return n
}
