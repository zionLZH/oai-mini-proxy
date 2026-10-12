// Package oauth 实现 OpenAI OAuth refresh_token 刷新。
//
// 常量与请求形态对齐 sub2api 的 pkg/openai/oauth.go + repository/openai_oauth_service.go：
// POST https://auth.openai.com/oauth/token，form 编码，携带凭据面身份对
// （User-Agent + originator，不发 version）。刷新请求与真实 Codex 客户端一致，
// 走外部代理但不打 TLS 指纹（与 sub2api 相同：指纹只作用于 chatgpt.com 推理面）。
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// ClientID 是 Codex CLI 官方 OAuth client_id。
	ClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	// RefreshScopes 与真实 Codex 刷新请求一致（不含 offline_access）。
	RefreshScopes = "openid profile email"
	// errorBodyReadLimit 限制错误体读取大小，避免错误风暴。
	errorBodyReadLimit = 64 << 10
)

// TokenURL 是 OpenAI OAuth token 端点（刷新复用同一端点）；包级变量便于测试注入。
var TokenURL = "https://auth.openai.com/oauth/token"

// TokenResponse 是刷新成功后的令牌响应。
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Refresher 执行 refresh_token 授权流程。
type Refresher struct {
	client     *http.Client
	userAgent  string
	originator string
	tokenURL   string
}

// NewRefresher 构建刷新器。
// client 应已绑定（可选的）代理与超时；userAgent/originator 为凭据面规范身份对。
func NewRefresher(client *http.Client, userAgent, originator string) *Refresher {
	return &Refresher{
		client:     client,
		userAgent:  userAgent,
		originator: originator,
		tokenURL:   TokenURL,
	}
}

// Refresh 使用 refreshToken 换取新令牌。
// clientID 为空时使用 Codex CLI 官方 ClientID。
func (r *Refresher) Refresh(ctx context.Context, refreshToken, clientID string) (*TokenResponse, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token is empty")
	}
	if strings.TrimSpace(clientID) == "" {
		clientID = ClientID
	}

	formData := url.Values{}
	formData.Set("grant_type", "refresh_token")
	formData.Set("refresh_token", refreshToken)
	formData.Set("client_id", clientID)
	formData.Set("scope", RefreshScopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("user-agent", r.userAgent)
	req.Header.Set("originator", r.originator)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyReadLimit))
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RefreshError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode refresh response: %w", err)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return nil, fmt.Errorf("refresh response has no access_token")
	}
	return &tokenResp, nil
}

// RefreshError 携带上游状态码与错误体，供调用方区分「凭证被撤销」与「瞬态失败」。
type RefreshError struct {
	StatusCode int
	Body       string
}

func (e *RefreshError) Error() string {
	return fmt.Sprintf("token refresh rejected: status %d: %s", e.StatusCode, truncate(e.Body, 512))
}

// ExpiresAt 由 expires_in 换算绝对到期时间；缺省按 1 小时保守估计。
func (t *TokenResponse) ExpiresAt(now time.Time) time.Time {
	if t == nil || t.ExpiresIn <= 0 {
		return now.Add(time.Hour)
	}
	return now.Add(time.Duration(t.ExpiresIn) * time.Second)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
