// Package upstream 负责上游 HTTP 传输的构建与按代理维度的连接池缓存。
//
// 移植自 sub2api 的 repository/http_upstream.go 的 buildUpstreamTransport /
// buildUpstreamTransportWithTLSFingerprint 两条路径：
//   - TLS 指纹启用时：直连 → tlsfp.Dialer；http 代理 → CONNECT 隧道 + 指纹；
//     socks5h → SOCKS5 隧道 + 指纹；https 代理 → 回退普通代理（明文 CONNECT
//     preface 无法对 HTTPS 代理做指纹，与 sub2api 相同）；
//   - TLS 指纹关闭时：标准 net/http 代理配置（http/https/socks5h 全支持）。
package upstream

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"oai-mini-proxy/internal/config"
	"oai-mini-proxy/internal/tlsfp"
)

// Pool 按代理键缓存 transport 与 client，保证长连接复用（SSE 场景关键）。
type Pool struct {
	cfg *config.Config

	mu        sync.Mutex
	transport map[string]*http.Transport
	client    map[string]*http.Client
	refresh   map[string]*http.Client
}

// NewPool 创建传输池。
func NewPool(cfg *config.Config) *Pool {
	return &Pool{
		cfg:       cfg,
		transport: make(map[string]*http.Transport),
		client:    make(map[string]*http.Client),
		refresh:   make(map[string]*http.Client),
	}
}

// Client 返回某代理下的上游推理客户端（无整体超时；首包超时由 transport 的
// ResponseHeaderTimeout 约束，SSE 长流不受影响）。
func (p *Pool) Client(proxyKey string, proxyURL *url.URL) (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.client[proxyKey]; ok {
		return c, nil
	}
	transport, err := p.buildTransportLocked(proxyKey, proxyURL, p.cfg.TLSFingerprint)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Transport: transport}
	p.client[proxyKey] = c
	return c, nil
}

// RefreshClient 返回 token 刷新客户端（整体 120s 超时；与 sub2api 一致，
// 刷新请求不打 TLS 指纹，仅复用代理路由）。
func (p *Pool) RefreshClient(proxyKey string, proxyURL *url.URL) (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.refresh[proxyKey]; ok {
		return c, nil
	}
	transport, err := p.buildTransportLocked(proxyKey, proxyURL, false)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Transport: transport, Timeout: 120 * time.Second}
	p.refresh[proxyKey] = c
	return c, nil
}

func (p *Pool) buildTransportLocked(proxyKey string, proxyURL *url.URL, fingerprint bool) (*http.Transport, error) {
	cacheKey := proxyKey
	if fingerprint {
		cacheKey = "fp\x00" + proxyKey
	}
	if t, ok := p.transport[cacheKey]; ok {
		return t, nil
	}
	transport, err := buildTransport(p.cfg, proxyURL, fingerprint)
	if err != nil {
		return nil, err
	}
	p.transport[cacheKey] = transport
	return transport, nil
}

// buildTransport 构建单个 transport。
func buildTransport(cfg *config.Config, proxyURL *url.URL, fingerprint bool) (*http.Transport, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ForceAttemptHTTP2:     false,
	}

	if !fingerprint {
		// 标准代理路径（http/https/socks5h 全支持）。
		if err := configureProxy(transport, proxyURL, cfg.DialTimeout); err != nil {
			return nil, err
		}
		return transport, nil
	}

	if proxyURL == nil {
		// 直连：TCP 建连与 TLS 握手都必须有界，否则网络不可达时会永久挂起。
		baseDialer := (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext
		dialer := tlsfp.NewDialer(nil, baseDialer, cfg.DialTimeout)
		transport.DialTLSContext = dialer.DialTLSContext
		return transport, nil
	}

	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		socksDialer := tlsfp.NewSOCKS5ProxyDialer(nil, proxyURL, cfg.DialTimeout)
		transport.DialTLSContext = socksDialer.DialTLSContext
	case "http":
		httpDialer := tlsfp.NewHTTPProxyDialer(nil, proxyURL, cfg.DialTimeout)
		transport.DialTLSContext = httpDialer.DialTLSContext
	case "https":
		// 指纹 dialer 只能发明文 CONNECT preface，无法与 HTTPS 代理建立 TLS；
		// 退回普通代理路由（与 sub2api 行为一致）。
		return buildTransport(cfg, proxyURL, false)
	default:
		if err := configureProxy(transport, proxyURL, cfg.DialTimeout); err != nil {
			return nil, err
		}
	}
	return transport, nil
}

// configureProxy 为标准 transport 配置代理路由（含 SOCKS5 的自定义拨号）。
func configureProxy(transport *http.Transport, proxyURL *url.URL, dialTimeout time.Duration) error {
	if proxyURL == nil {
		return nil
	}

	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme == "socks5" || scheme == "socks5h" {
		dialContext, err := socks5DialContext(proxyURL, dialTimeout)
		if err != nil {
			return err
		}
		transport.DialContext = dialContext
		return nil
	}

	transport.Proxy = http.ProxyURL(proxyURL)
	return nil
}

// socks5DialContext 用 golang.org/x/net/proxy 构建 SOCKS5 拨号函数。
// socks5h 的远端 DNS 解析由该库对域名的处理保证（socks5:// 已在 proxyurl.Parse 升级）。
func socks5DialContext(proxyURL *url.URL, dialTimeout time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	var auth *proxy.Auth
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth = &proxy.Auth{User: username, Password: password}
	}

	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "1080")
	}

	base := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, base)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support context")
	}
	return contextDialer.DialContext, nil
}
