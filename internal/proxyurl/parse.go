// Package proxyurl 提供代理 URL 的统一验证（fail-fast，无效代理不回退直连）。
//
// 语义与 sub2api 的 pkg/proxyurl 保持一致：
//   - 空字符串 → 直连
//   - 非空且有效 → 返回规范化 URL
//   - 非空但无效 → error（绝不静默回退直连，避免真实 IP 泄露）
//   - socks5:// 自动升级为 socks5h://，确保 DNS 由代理端解析
package proxyurl

import (
	"fmt"
	"net/url"
	"strings"
)

var allowedSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks5":  true,
	"socks5h": true,
}

// Parse 解析并验证代理 URL。
func Parse(raw string) (trimmed string, parsed *url.URL, err error) {
	trimmed = strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil, nil
	}

	parsed, err = url.Parse(trimmed)
	if err != nil {
		// 不使用 %w 包装，避免底层错误消息泄漏原始 URL（可能含凭据）
		return "", nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", nil, fmt.Errorf("proxy URL missing host: %s", parsed.Redacted())
	}

	scheme := strings.ToLower(parsed.Scheme)
	if !allowedSchemes[scheme] {
		return "", nil, fmt.Errorf("unsupported proxy scheme %q (allowed: http, https, socks5, socks5h)", scheme)
	}

	// 自动升级 socks5 → socks5h：golang.org/x/net/proxy 对 socks5:// 默认本地解析
	// DNS，仅 socks5h:// 才把域名交给代理端远程解析，避免 DNS 泄漏。
	if scheme == "socks5" {
		parsed.Scheme = "socks5h"
		trimmed = parsed.String()
	}

	return trimmed, parsed, nil
}
