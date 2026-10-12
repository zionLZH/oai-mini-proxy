// Package config 提供 oai-mini-proxy 的运行时配置。
// 全部通过环境变量注入，缺省值面向「开箱即用」：
// 监听 :8317，凭证缓存落盘 ./data/credentials，上游固定为 ChatGPT Codex 后端。
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 汇总所有可配置项。
type Config struct {
	// Addr HTTP 监听地址。
	Addr string
	// CacheDir 凭证缓存目录（email 维度本地持久化）。
	CacheDir string
	// UpstreamBase 上游 base（默认 ChatGPT Codex 后端）。
	UpstreamBase string
	// UpstreamHost 上游 Host 头（OAuth 透传必须为 chatgpt.com）。
	UpstreamHost string
	// CodexVersion 出站声明的 Codex 客户端版本（决定 UA 与 version 头）。
	CodexVersion string
	// CodexUserAgent 完整出站 User-Agent 覆写；为空时由 CodexVersion 拼装规范 TUI UA。
	CodexUserAgent string
	// TLSFingerprint 是否启用 utls TLS 指纹伪装。
	TLSFingerprint bool
	// RefreshSkew access_token 到期前多久视为需要刷新。
	RefreshSkew time.Duration
	// ResponseHeaderTimeout 等待上游响应头的超时（SSE 长流只约束首包）。
	ResponseHeaderTimeout time.Duration
	// DialTimeout TCP 拨号超时。
	DialTimeout time.Duration
	// MaxBodyBytes 入站请求体大小上限。
	MaxBodyBytes int64
	// Debug 打开详细日志。
	Debug bool
}

// Load 从环境变量装载配置。
func Load() *Config {
	cfg := &Config{
		Addr:                  envOr("OAI_MINI_PROXY_ADDR", ":8317"),
		CacheDir:              envOr("OAI_MINI_PROXY_CACHE_DIR", "./data/credentials"),
		UpstreamBase:          envOr("OAI_MINI_PROXY_UPSTREAM_BASE", "https://chatgpt.com/backend-api/codex"),
		UpstreamHost:          envOr("OAI_MINI_PROXY_UPSTREAM_HOST", "chatgpt.com"),
		CodexVersion:          envOr("OAI_MINI_PROXY_CODEX_VERSION", "0.146.0"),
		CodexUserAgent:        strings.TrimSpace(os.Getenv("OAI_MINI_PROXY_CODEX_USER_AGENT")),
		TLSFingerprint:        envBool("OAI_MINI_PROXY_TLS_FINGERPRINT", true),
		RefreshSkew:           envDuration("OAI_MINI_PROXY_REFRESH_SKEW", 5*time.Minute),
		ResponseHeaderTimeout: envDuration("OAI_MINI_PROXY_RESPONSE_HEADER_TIMEOUT", 300*time.Second),
		DialTimeout:           envDuration("OAI_MINI_PROXY_DIAL_TIMEOUT", 10*time.Second),
		MaxBodyBytes:          envInt64("OAI_MINI_PROXY_MAX_BODY_BYTES", 64<<20),
		Debug:                 envBool("OAI_MINI_PROXY_DEBUG", false),
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
