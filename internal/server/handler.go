package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"oai-mini-proxy/internal/codex"
	"oai-mini-proxy/internal/credential"
	"oai-mini-proxy/internal/manager"
	"oai-mini-proxy/internal/proxyurl"
)

const (
	// headerCredentials 是 base64(JSON) 凭证的入站头。
	headerCredentials = "X-Credentials"
	// headerProxyURL 是代理 URL（base64 或明文）的入站头。
	headerProxyURL = "X-Proxy-URL"
	// upstreamResponsesPath 是 ChatGPT Codex 后端的 Responses 端点路径。
	upstreamResponsesPath = "/responses"
	// upstreamModelsPath 是 ChatGPT Codex 后端的模型清单端点路径。
	upstreamModelsPath = "/models"
	// retryBodyCaptureLimit 401 响应缓存上限（用于刷新失败时原地回放）。
	retryBodyCaptureLimit = 512 << 10
)

// upstreamPathSuffixPattern 限制 /responses 之后的子路径只允许安全段
// （对齐 sub2api sanitizedUpstreamPathSuffix）。
var upstreamPathSuffixPattern = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)*$`)

// handleResponses 是 /v1/responses 系列请求的主入口。
//
// 流程：解析凭证与代理头 → 缓存解析（必要时刷新并回写）→ 透传上游 →
// 401 时强制刷新并重试一次 → SSE/JSON 流式回写。
func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cred, err := s.extractCredential(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", err.Error())
		return
	}

	proxyKey, proxyURL, err := s.extractProxy(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_proxy", err.Error())
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "read_body_failed", err.Error())
		return
	}
	if int64(len(body)) > s.cfg.MaxBodyBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "body_too_large",
			fmt.Sprintf("request body exceeds %d bytes", s.cfg.MaxBodyBytes))
		return
	}

	// 合法化 ChatGPT 内网 Codex 端点要求：通用客户端（Cherry Studio 等）不带
	// store 字段会被上游拒绝（"Store must be set to false"）。已是合法形态的
	// 请求保持逐字节原样透传。
	if normalized, modified := codex.NormalizeResponsesBody(body); modified > 0 {
		s.logf("normalized responses body (key=%s, changed=%d fields, %d -> %d bytes)",
			cred.CacheKey(), modified, len(body), len(normalized))
		body = normalized
	}

	resolved, err := s.manager.Resolve(ctx, cred, proxyKey, proxyURL)
	if err != nil {
		s.logf("credential resolve failed (key=%s): %v", cred.CacheKey(), err)
		status := http.StatusBadGateway
		if errors.Is(err, manager.ErrNoRefreshToken) {
			status = http.StatusUnauthorized
		}
		s.writeError(w, status, "credential_error", err.Error())
		return
	}

	start := time.Now()
	upstreamResp, err := s.forward(ctx, r, body, resolved, proxyKey, proxyURL)
	if err != nil {
		s.logf("upstream request failed (key=%s): %v", resolved.CacheKey(), err)
		s.writeError(w, http.StatusBadGateway, "upstream_request_failed", err.Error())
		return
	}

	// 401：强制刷新一次并重试（rolling refresh 后的 transient 401 或 token 到期
	// 但本地无法预判的场景）。刷新失败时原地回放原始 401。
	if upstreamResp.StatusCode == http.StatusUnauthorized {
		captured, cerr := captureResponse(upstreamResp, retryBodyCaptureLimit)
		_ = upstreamResp.Body.Close()
		if cerr != nil {
			s.writeError(w, http.StatusBadGateway, "upstream_read_failed", cerr.Error())
			return
		}

		refreshed, rerr := s.manager.ForceRefresh(ctx, cred, resolved, proxyKey, proxyURL)
		if rerr != nil {
			s.logf("401 received; force refresh failed (key=%s): %v", resolved.CacheKey(), rerr)
			captured.replay(w)
			return
		}

		s.logf("401 received; retrying with refreshed token (key=%s)", refreshed.CacheKey())
		upstreamResp, err = s.forward(ctx, r, body, refreshed, proxyKey, proxyURL)
		if err != nil {
			s.logf("retry after refresh failed (key=%s): %v", refreshed.CacheKey(), err)
			s.writeError(w, http.StatusBadGateway, "upstream_request_failed", err.Error())
			return
		}
	}

	defer func() { _ = upstreamResp.Body.Close() }()
	s.logf("forwarded %s -> %d in %s (key=%s, proxy=%q)",
		r.URL.Path, upstreamResp.StatusCode, time.Since(start).Round(time.Millisecond), resolved.CacheKey(), proxyKey)
	s.writeUpstreamResponse(w, upstreamResp)
}

// handleModels 是 /v1/models、/models、/backend-api/codex/models 的接入口。
//
// Codex CLI 刷新模型选择器会调用 GET {base_url}/models?client_version=...
// （custom provider 模式）或 GET /backend-api/codex/models（chatgpt_base_url
// 模式）；两者统一映射到上游 {UpstreamBase}/models。流程与 Responses 一致：
// 凭证/代理解析 → 缓存解析（必要时刷新）→ GET 透传 → 401 强制刷新重试一次。
// client_version 按客户端原值透传，缺失时补规范版本。
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cred, err := s.extractCredential(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", err.Error())
		return
	}

	proxyKey, proxyURL, err := s.extractProxy(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_proxy", err.Error())
		return
	}

	// client_version 是内容协商参数：客户端原值透传，缺失时补规范版本；
	// Version 头与它同源协商（非法或低于门槛回退规范版本）。
	query := r.URL.Query()
	clientVersion := strings.TrimSpace(query.Get("client_version"))
	headerVersion := s.kit.VersionHeader(clientVersion)
	if clientVersion == "" {
		clientVersion = s.kit.Canonical().Version
		query.Set("client_version", clientVersion)
	}

	resolved, err := s.manager.Resolve(ctx, cred, proxyKey, proxyURL)
	if err != nil {
		s.logf("credential resolve failed (key=%s): %v", cred.CacheKey(), err)
		status := http.StatusBadGateway
		if errors.Is(err, manager.ErrNoRefreshToken) {
			status = http.StatusUnauthorized
		}
		s.writeError(w, status, "credential_error", err.Error())
		return
	}

	start := time.Now()
	upstreamResp, err := s.forwardModels(ctx, r, query, headerVersion, resolved, proxyKey, proxyURL)
	if err != nil {
		s.logf("upstream models request failed (key=%s): %v", resolved.CacheKey(), err)
		s.writeError(w, http.StatusBadGateway, "upstream_request_failed", err.Error())
		return
	}

	// 401：与 Responses 相同的强制刷新 + 重试一次语义（models 401 同样权威指示
	// 凭证失效，sub2api 亦将其接入账号鉴权错误处理）。
	if upstreamResp.StatusCode == http.StatusUnauthorized {
		captured, cerr := captureResponse(upstreamResp, retryBodyCaptureLimit)
		_ = upstreamResp.Body.Close()
		if cerr != nil {
			s.writeError(w, http.StatusBadGateway, "upstream_read_failed", cerr.Error())
			return
		}

		refreshed, rerr := s.manager.ForceRefresh(ctx, cred, resolved, proxyKey, proxyURL)
		if rerr != nil {
			s.logf("models 401 received; force refresh failed (key=%s): %v", resolved.CacheKey(), rerr)
			captured.replay(w)
			return
		}

		s.logf("models 401 received; retrying with refreshed token (key=%s)", refreshed.CacheKey())
		upstreamResp, err = s.forwardModels(ctx, r, query, headerVersion, refreshed, proxyKey, proxyURL)
		if err != nil {
			s.logf("models retry after refresh failed (key=%s): %v", refreshed.CacheKey(), err)
			s.writeError(w, http.StatusBadGateway, "upstream_request_failed", err.Error())
			return
		}
	}

	defer func() { _ = upstreamResp.Body.Close() }()
	s.logf("forwarded %s -> %d in %s (key=%s, proxy=%q)",
		r.URL.Path, upstreamResp.StatusCode, time.Since(start).Round(time.Millisecond), resolved.CacheKey(), proxyKey)
	s.writeUpstreamResponse(w, upstreamResp)
}

// forwardModels 构造并发送一次上游 models GET 请求。
func (s *Server) forwardModels(ctx context.Context, r *http.Request, query url.Values, headerVersion string, cred *credential.Credential, proxyKey string, proxyURL *url.URL) (*http.Response, error) {
	target := strings.TrimRight(s.cfg.UpstreamBase, "/") + upstreamModelsPath
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build upstream models request: %w", err)
	}
	req.Host = s.cfg.UpstreamHost

	codex.CopyAllowedClientHeaders(req.Header, r.Header)
	// 客户端 ETag 续期（Codex CLI 持有 etag 时会带 If-None-Match，上游 304 直接回放）。
	if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" {
		req.Header.Set("If-None-Match", inm)
	}
	codex.ApplyOAuthModelsHeaders(req.Header, cred, s.kit.Canonical(), headerVersion)
	req.Header.Del(headerCredentials)
	req.Header.Del(headerProxyURL)

	client, err := s.pool.Client(proxyKey, proxyURL)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// forward 构造并发送一次上游请求。
func (s *Server) forward(ctx context.Context, r *http.Request, body []byte, cred *credential.Credential, proxyKey string, proxyURL *url.URL) (*http.Response, error) {
	target, err := s.upstreamURL(r.URL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	// OAuth 透传到 ChatGPT 内部接口必须携带 Host: chatgpt.com。
	req.Host = s.cfg.UpstreamHost

	// 客户端头按白名单透传，随后由身份收口统一改写。
	codex.CopyAllowedClientHeaders(req.Header, r.Header)
	codex.ApplyOAuthUpstreamHeaders(req.Header, cred, s.kit.Canonical())
	if strings.TrimSpace(req.Header.Get("content-type")) == "" {
		req.Header.Set("content-type", "application/json")
	}
	// 出站不携带入站代理协商头与凭证头。
	req.Header.Del(headerCredentials)
	req.Header.Del(headerProxyURL)

	client, err := s.pool.Client(proxyKey, proxyURL)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// upstreamURL 把入站路径映射到上游端点：
// /v1/responses[/suffix] 或 /backend-api/codex/responses[/suffix]
// → {UpstreamBase}/responses[/suffix]?{query}。
func (s *Server) upstreamURL(in *url.URL) (string, error) {
	base := strings.TrimRight(s.cfg.UpstreamBase, "/")
	path := strings.TrimRight(in.Path, "/")

	suffix := ""
	if idx := strings.LastIndex(path, upstreamResponsesPath); idx >= 0 {
		suffix = path[idx+len(upstreamResponsesPath):]
	}
	if suffix != "" && !upstreamPathSuffixPattern.MatchString(suffix) {
		return "", fmt.Errorf("unsupported upstream path suffix %q", suffix)
	}

	target := base + upstreamResponsesPath + suffix
	if in.RawQuery != "" {
		target += "?" + in.RawQuery
	}
	return target, nil
}

// extractCredential 解析入站凭证：X-Credentials 优先，
// 其次兼容 `Authorization: Bearer <base64(credential JSON)>`（OpenAI SDK 的
// api_key 通道，方便只支持单一凭证字段的客户端）。
func (s *Server) extractCredential(r *http.Request) (*credential.Credential, error) {
	if raw := strings.TrimSpace(r.Header.Get(headerCredentials)); raw != "" {
		return credential.Decode(raw)
	}
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		if cred, err := credential.Decode(token); err == nil {
			return cred, nil
		}
	}
	return nil, fmt.Errorf("missing %s header (base64-encoded credential JSON) or Authorization Bearer credential", headerCredentials)
}

// extractProxy 解析代理头：base64 或明文 URL；空视为直连。
func (s *Server) extractProxy(r *http.Request) (string, *url.URL, error) {
	raw := strings.TrimSpace(r.Header.Get(headerProxyURL))
	if raw == "" {
		return "", nil, nil
	}
	if decoded, err := tryDecodeBase64(raw); err == nil {
		candidate := strings.TrimSpace(string(decoded))
		if strings.Contains(candidate, "://") {
			raw = candidate
		}
	}
	proxyKey, parsed, err := proxyurl.Parse(raw)
	if err != nil {
		return "", nil, err
	}
	return proxyKey, parsed, nil
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func tryDecodeBase64(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

// writeUpstreamResponse 以流式方式回写上游响应（SSE 每块立即 Flush）。
func (s *Server) writeUpstreamResponse(w http.ResponseWriter, resp *http.Response) {
	header := w.Header()
	for key, values := range resp.Header {
		if isHopByHopHeader(key) || strings.EqualFold(key, "content-length") {
			continue
		}
		for _, v := range values {
			header.Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// capturedResponse 用于 401 原地回放。
type capturedResponse struct {
	status int
	header http.Header
	body   []byte
}

func captureResponse(resp *http.Response, limit int64) (*capturedResponse, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return &capturedResponse{status: resp.StatusCode, header: resp.Header.Clone(), body: body}, nil
}

func (c *capturedResponse) replay(w http.ResponseWriter) {
	header := w.Header()
	for key, values := range c.header {
		if isHopByHopHeader(key) || strings.EqualFold(key, "content-length") {
			continue
		}
		for _, v := range values {
			header.Add(key, v)
		}
	}
	w.WriteHeader(c.status)
	_, _ = w.Write(c.body)
}

// writeError 输出统一错误 JSON。
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"type":    "oai_mini_proxy_" + code,
			"message": message,
		},
	})
}

// isHopByHopHeader 判断逐跳头（RFC 9110 §7.6.1）。
func isHopByHopHeader(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
