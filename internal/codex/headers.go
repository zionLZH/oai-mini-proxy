package codex

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"oai-mini-proxy/internal/credential"
)

// responsesLiteHeaderKey 对齐 sub2api 的 responses-lite 协商头。
const responsesLiteHeaderKey = "x-openai-internal-codex-responses-lite"

// remoteCompactionV2Feature 是 OAuth 出站需补注的会话级 beta 能力声明
// （对齐 sub2api openAIRemoteCompactionV2Feature）。
const remoteCompactionV2Feature = "remote_compaction_v2"

// allowedPassthroughHeaders 是客户端→上游的头白名单（逐字移植 sub2api
// openaiPassthroughAllowedHeaders）：仅放行低风险头，避免非标准/环境噪声头
// 传给上游触发风控。
var allowedPassthroughHeaders = map[string]bool{
	"accept":                  true,
	"accept-language":         true,
	"content-type":            true,
	"conversation_id":         true,
	"openai-beta":             true,
	"user-agent":              true,
	"originator":              true,
	"session_id":              true,
	"x-codex-beta-features":   true,
	"x-codex-installation-id": true,
	"x-codex-turn-state":      true,
	"x-codex-turn-metadata":   true,
	"x-codex-window-id":       true,
	responsesLiteHeaderKey:    true,
}

// CopyAllowedClientHeaders 把客户端请求头按白名单拷入出站头。
func CopyAllowedClientHeaders(dst, src http.Header) {
	if dst == nil || src == nil {
		return
	}
	for key, values := range src {
		lower := strings.ToLower(strings.TrimSpace(key))
		if !allowedPassthroughHeaders[lower] {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

// StripLegacyResponsesBeta 移除客户端可能回带的 legacy `responses=experimental`
// beta 协商 token（保留同一头的其它独立协商值）。逐字移植 sub2api
// stripOpenAILegacyResponsesBeta。
func StripLegacyResponsesBeta(headers http.Header) {
	if headers == nil {
		return
	}
	preserved := make([]string, 0)
	for key, values := range headers {
		if !strings.EqualFold(strings.TrimSpace(key), "OpenAI-Beta") {
			continue
		}
		delete(headers, key)
		for _, value := range values {
			parts := strings.Split(value, ",")
			kept := parts[:0]
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" || strings.EqualFold(part, "responses=experimental") {
					continue
				}
				kept = append(kept, part)
			}
			if len(kept) > 0 {
				preserved = append(preserved, strings.Join(kept, ", "))
			}
		}
	}
	for _, value := range preserved {
		headers.Add("OpenAI-Beta", value)
	}
}

// applyOAuthCredentialHeaders 清理入站鉴权残留并注入 OAuth 凭据面头
// （Bearer + chatgpt-account-id + x-openai-fedramp），responses 与 models 共用。
func applyOAuthCredentialHeaders(h http.Header, cred *credential.Credential) {
	h.Del("authorization")
	h.Del("x-api-key")
	h.Del("x-goog-api-key")
	if cred != nil && cred.AccessToken != "" {
		h.Set("authorization", "Bearer "+cred.AccessToken)
	}
	if cred != nil {
		if cred.ChatGPTAccountID != "" {
			h.Set("chatgpt-account-id", cred.ChatGPTAccountID)
		}
		if cred.IsFedRAMP {
			h.Set("x-openai-fedramp", "true")
		} else {
			h.Del("x-openai-fedramp")
		}
	}
}

// ApplyOAuthUpstreamHeaders 组装 Codex OAuth 出站请求的完整头部集合。
// 步骤与 sub2api passthrough 的 OAuth 分支逐点对齐：
//  1. 清理入站鉴权残留，注入 Bearer + chatgpt-account-id；
//  2. 移除 legacy responses beta;
//  3. accept 默认 text/event-stream；
//  4. originator 缺失补规范值；
//  5. session_id / conversation_id / x-codex-window-id 等引擎指纹缺失兜底；
//  6. x-codex-beta-features 缺失补 remote_compaction_v2；
//  7. 终态收口：强制统一 User-Agent / originator / version。
func ApplyOAuthUpstreamHeaders(h http.Header, cred *credential.Credential, id Identity) {
	if h == nil {
		return
	}

	// 1. 鉴权面：清残留 + Bearer + chatgpt-account-id。
	applyOAuthCredentialHeaders(h, cred)

	// 2. legacy responses beta 清理。
	StripLegacyResponsesBeta(h)

	// 3. accept 默认 SSE（客户端显式声明的 Accept 已在白名单透传中保留）。
	if strings.TrimSpace(h.Get("accept")) == "" {
		h.Set("accept", "text/event-stream")
	}

	// 4. originator 缺失补规范值（后续收口会统一覆写，这里保证非空语义）。
	if strings.TrimSpace(h.Get("originator")) == "" {
		h.Set("originator", id.Originator)
	}

	// 5. 引擎指纹兜底：真实 codex 流量高频携带 x-codex-window-id（约 98.8%）
	// 与 session_id；缺失时补随机值，避免探测型请求的裸头形态。
	if strings.TrimSpace(h.Get("session_id")) == "" {
		h.Set("session_id", NewUUID())
	}
	if strings.TrimSpace(h.Get("conversation_id")) == "" {
		h.Set("conversation_id", NewUUID())
	}
	if strings.TrimSpace(h.Get("x-codex-window-id")) == "" {
		h.Set("x-codex-window-id", NewUUID())
	}

	// 6. beta features：客户端声明过则尊重，否则按 OAuth 会话级行为补注。
	if !hasNonEmptyHeader(h, "x-codex-beta-features") {
		h.Set("x-codex-beta-features", remoteCompactionV2Feature)
	}

	// 7. 终态收口：User-Agent / originator / version 同源自洽。
	ApplyUpstreamIdentity(h, id)
}

// ApplyOAuthModelsHeaders 组装 GET /models 的 OAuth 出站头部
// （对齐 sub2api FetchCodexModelsManifest 的 OAuth 分支）：凭据面鉴权头 +
// Accept: application/json + 身份对（version 为与 client_version 同源的协商值）。
// models 端点不带 responses 的会话指纹兜底头。
func ApplyOAuthModelsHeaders(h http.Header, cred *credential.Credential, id Identity, version string) {
	if h == nil {
		return
	}
	applyOAuthCredentialHeaders(h, cred)
	h.Set("accept", "application/json")
	if strings.TrimSpace(version) == "" {
		version = id.Version
	}
	ApplyUpstreamIdentity(h, Identity{
		UserAgent:  id.UserAgent,
		Originator: id.Originator,
		Version:    version,
	})
}

func hasNonEmptyHeader(h http.Header, key string) bool {
	for _, value := range h.Values(key) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// NewUUID 生成 RFC 4122 v4 UUID 字符串（随机源为 crypto/rand）。
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", 0)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}
