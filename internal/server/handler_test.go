package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oai-mini-proxy/internal/config"
	"oai-mini-proxy/internal/oauth"
)

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func encodeCredential(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func freshCredentialHeader(t *testing.T, email, marker string) string {
	t.Helper()
	jwt := makeJWT(t, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-" + email,
		},
	})
	return encodeCredential(t, map[string]any{
		"access_token":  jwt,
		"refresh_token": "rt-" + email,
		"email":         email,
		"_marker":       marker,
	})
}

type recordedRequest struct {
	path   string
	query  string
	host   string
	header http.Header
	body   []byte
}

// newTestServer 装配一个上游与刷新端点均为 httptest 的服务实例。
func newTestServer(t *testing.T, upstreamHandler http.HandlerFunc) (ts *httptest.Server, recorded *[]recordedRequest, mu *sync.Mutex) {
	t.Helper()
	rec := make([]recordedRequest, 0)
	var lock sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lock.Lock()
		rec = append(rec, recordedRequest{path: r.URL.Path, query: r.URL.RawQuery, host: r.Host, header: r.Header.Clone(), body: body})
		lock.Unlock()
		upstreamHandler(w, r)
	}))
	t.Cleanup(upstream.Close)

	cfg := config.Load()
	cfg.Addr = "127.0.0.1:0"
	cfg.CacheDir = t.TempDir()
	cfg.UpstreamBase = upstream.URL + "/backend-api/codex"
	cfg.UpstreamHost = "chatgpt.com"
	cfg.TLSFingerprint = false
	cfg.RefreshSkew = 5 * time.Minute
	cfg.MaxBodyBytes = 1 << 20

	srv, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	front := httptest.NewServer(srv.Handler())
	t.Cleanup(front.Close)
	return front, &rec, &lock
}

func postResponses(t *testing.T, baseURL, credentialHeader, proxyHeader string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/responses", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Credentials", credentialHeader)
	if proxyHeader != "" {
		req.Header.Set("X-Proxy-URL", proxyHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func sseStream() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, chunk := range []string{
			"data: {\"type\":\"response.created\"}\n\n",
			"data: {\"type\":\"response.completed\"}\n\n",
		} {
			_, _ = io.WriteString(w, chunk)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func swapTokenURL(t *testing.T, url string) {
	t.Helper()
	prev := oauth.TokenURL
	oauth.TokenURL = url
	t.Cleanup(func() { oauth.TokenURL = prev })
}

// TestForwardEndToEnd 验证新鲜凭证的直通转发与全部风控伪装头。
func TestForwardEndToEnd(t *testing.T) {
	front, recorded, mu := newTestServer(t, sseStream())

	header := freshCredentialHeader(t, "user@example.com", "at-original")
	resp := postResponses(t, front.URL, header, "", `{"model":"gpt-5.3-codex","stream":true,"input":"hi"}`)
	defer func() { _ = resp.Body.Close() }()

	streamBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, streamBody)
	}
	if !strings.Contains(string(streamBody), "response.completed") {
		t.Fatalf("SSE stream not relayed: %s", streamBody)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content type not relayed: %q", ct)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 1 {
		t.Fatalf("expected 1 upstream request, got %d", len(*recorded))
	}
	req := (*recorded)[0]

	if req.host != "chatgpt.com" {
		t.Fatalf("Host not rewritten: %q", req.host)
	}
	if req.path != "/backend-api/codex/responses" {
		t.Fatalf("unexpected upstream path: %q", req.path)
	}
	if auth := req.header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("missing bearer token: %q", auth)
	}
	if acct := req.header.Get("Chatgpt-Account-Id"); acct != "acct-user@example.com" {
		t.Fatalf("chatgpt-account-id not injected: %q", acct)
	}
	if ua := req.header.Get("User-Agent"); ua != "codex-tui/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color" {
		t.Fatalf("UA not enforced: %q", ua)
	}
	if orig := req.header.Get("Originator"); orig != "codex-tui" {
		t.Fatalf("originator not enforced: %q", orig)
	}
	if v := req.header.Get("Version"); v != "0.146.0" {
		t.Fatalf("version header mismatch: %q", v)
	}
	if sid := req.header.Get("Session_Id"); sid == "" {
		t.Fatal("session_id fingerprint fallback missing")
	}
	if wid := req.header.Get("X-Codex-Window-Id"); wid == "" {
		t.Fatal("x-codex-window-id fingerprint fallback missing")
	}
	if beta := req.header.Get("X-Codex-Beta-Features"); beta != "remote_compaction_v2" {
		t.Fatalf("beta features not annotated: %q", beta)
	}
	if _, leaked := req.header["X-Credentials"]; leaked {
		t.Fatal("X-Credentials must not be forwarded upstream")
	}
}

// TestResponsesBodyNormalizedForGenericClient 验证通用客户端形态的请求体
// （如 Cherry Studio：无 store 字段）在上游前被合法化为 store=false +
// stream=true，且 model/input 保留；已合法的请求体则逐字节原样透传。
func TestResponsesBodyNormalizedForGenericClient(t *testing.T) {
	front, recorded, mu := newTestServer(t, sseStream())

	header := freshCredentialHeader(t, "user@example.com", "at")
	genericBody := `{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"stream":true}`
	resp := postResponses(t, front.URL, header, "", genericBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// 第二次请求：已合法 body（store=false + stream=true + 无多余字段）。
	legitBody := `{"model":"gpt-5.5","store":false,"stream":true,"input":"hi"}`
	resp2 := postResponses(t, front.URL, header, "", legitBody)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp2.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 2 {
		t.Fatalf("expected 2 upstream requests, got %d", len(*recorded))
	}

	var sent map[string]json.RawMessage
	if err := json.Unmarshal((*recorded)[0].body, &sent); err != nil {
		t.Fatalf("upstream body not JSON: %v (%s)", err, (*recorded)[0].body)
	}
	if string(sent["store"]) != "false" {
		t.Fatalf("store = %s, want false (normalized)", sent["store"])
	}
	if string(sent["stream"]) != "true" {
		t.Fatalf("stream = %s, want true (normalized)", sent["stream"])
	}
	if string(sent["model"]) != `"gpt-5.5"` {
		t.Fatalf("model = %s, want preserved", sent["model"])
	}

	if string((*recorded)[1].body) != legitBody {
		t.Fatalf("legit body must be byte-identical\n got: %s\nwant: %s", (*recorded)[1].body, legitBody)
	}
}

// TestPathSuffixMapping 验证 /responses 子路径与 query 的映射。
func TestPathSuffixMapping(t *testing.T) {
	front, recorded, mu := newTestServer(t, sseStream())

	header := freshCredentialHeader(t, "user@example.com", "at")
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses/compact?x=1", strings.NewReader(`{}`))
	req.Header.Set("X-Credentials", header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 1 || (*recorded)[0].path != "/backend-api/codex/responses/compact" {
		t.Fatalf("suffix mapping failed: %+v", *recorded)
	}
}

// TestExpiredTokenRefreshesAndCaches 验证过期凭证的自动刷新、落盘与缓存优先语义。
func TestExpiredTokenRefreshesAndCaches(t *testing.T) {
	var refreshCalls int64
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&refreshCalls, 1)
		_ = r.ParseForm()
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("client_id"); got != oauth.ClientID {
			t.Errorf("client_id = %q", got)
		}
		if got := r.Form.Get("scope"); got != oauth.RefreshScopes {
			t.Errorf("scope = %q", got)
		}
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("refresh request missing User-Agent")
		}
		if orig := r.Header.Get("originator"); orig != "codex-tui" {
			t.Errorf("refresh originator = %q", orig)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rotated-rt","expires_in":3600}`,
			makeJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}))
	}))
	defer refreshSrv.Close()
	swapTokenURL(t, refreshSrv.URL)

	front, recorded, mu := newTestServer(t, sseStream())

	// 过期凭证（exp 在过去）。
	expiredJWT := makeJWT(t, map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-expired",
		},
	})
	oldHeader := encodeCredential(t, map[string]any{
		"access_token":  expiredJWT,
		"refresh_token": "rt-original",
		"email":         "expired@example.com",
	})

	resp := postResponses(t, front.URL, oldHeader, "", `{"model":"m","stream":true,"input":"x"}`)
	streamBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, streamBody)
	}
	if atomic.LoadInt64(&refreshCalls) != 1 {
		t.Fatalf("expected exactly 1 refresh call, got %d", refreshCalls)
	}

	mu.Lock()
	firstBearer := (*recorded)[0].header.Get("Authorization")
	mu.Unlock()
	if firstBearer == "Bearer "+expiredJWT {
		t.Fatal("upstream must receive the refreshed token, not the expired one")
	}

	// 第二次请求：仍然传入旧凭证，但缓存已持有新鲜 token → 快路径命中，触发 0 次刷新。
	resp2 := postResponses(t, front.URL, oldHeader, "", `{"model":"m","stream":true,"input":"x"}`)
	_, _ = io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if atomic.LoadInt64(&refreshCalls) != 1 {
		t.Fatalf("cache hit must not trigger a new refresh, got %d calls", refreshCalls)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 2 {
		t.Fatalf("expected 2 upstream requests, got %d", len(*recorded))
	}
	if (*recorded)[0].header.Get("Authorization") != (*recorded)[1].header.Get("Authorization") {
		t.Fatal("cached token must be reused across requests")
	}
}

// TestUnauthorizedForcesRefreshAndRetries 验证 401 → 强制刷新 → 重试一次。
func TestUnauthorizedForcesRefreshAndRetries(t *testing.T) {
	var refreshCalls int64
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&refreshCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-new","expires_in":3600}`,
			makeJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}))
	}))
	defer refreshSrv.Close()
	swapTokenURL(t, refreshSrv.URL)

	var upstreamCalls int64
	front, recorded, mu := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&upstreamCalls, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"token expired"}}`)
			return
		}
		sseStream()(w, r)
	})

	header := freshCredentialHeader(t, "retry@example.com", "at-stale")
	resp := postResponses(t, front.URL, header, "", `{"model":"m","stream":true,"input":"x"}`)
	streamBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry should succeed, status = %d body = %s", resp.StatusCode, streamBody)
	}
	if atomic.LoadInt64(&refreshCalls) != 1 {
		t.Fatalf("expected 1 refresh after 401, got %d", refreshCalls)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 2 {
		t.Fatalf("expected 2 upstream attempts, got %d", len(*recorded))
	}
	first := (*recorded)[0].header.Get("Authorization")
	second := (*recorded)[1].header.Get("Authorization")
	if first == second {
		t.Fatal("retry must use the refreshed token")
	}
}

// TestUnauthorizedReplaysWhenRefreshFails 验证刷新失败时原地回放原始 401。
func TestUnauthorizedReplaysWhenRefreshFails(t *testing.T) {
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer refreshSrv.Close()
	swapTokenURL(t, refreshSrv.URL)

	var upstreamCalls int64
	front, _, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&upstreamCalls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"token revoked"}}`)
	})

	header := freshCredentialHeader(t, "replay@example.com", "at-revoked")
	resp := postResponses(t, front.URL, header, "", `{"model":"m","stream":true,"input":"x"}`)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected original 401 to be replayed, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "token revoked") {
		t.Fatalf("original 401 body must be replayed: %s", body)
	}
	if atomic.LoadInt64(&upstreamCalls) != 1 {
		t.Fatalf("must not retry upstream when refresh fails, got %d calls", upstreamCalls)
	}
}

// TestMissingCredentialAndBadProxy 验证入参校验。
func TestMissingCredentialAndBadProxy(t *testing.T) {
	front, _, _ := newTestServer(t, sseStream())

	// 缺少凭证。
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing credential must be 401, got %d", resp.StatusCode)
	}

	// 非法代理头。
	badProxy := base64.StdEncoding.EncodeToString([]byte("ftp://evil:21"))
	resp2 := postResponses(t, front.URL, freshCredentialHeader(t, "p@e.com", "at"), badProxy, `{}`)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid proxy must be 400, got %d", resp2.StatusCode)
	}

	// 明文代理头也可用（非 base64）；指向无监听端口，快速连接拒绝。
	resp3 := postResponses(t, front.URL, freshCredentialHeader(t, "p@e.com", "at"), "http://127.0.0.1:1", `{"model":"m","input":"x"}`)
	_ = resp3.Body.Close()
	if resp3.StatusCode == http.StatusBadRequest {
		t.Fatalf("plaintext proxy header must be accepted as proxy route, got 400")
	}
}

// TestBearerCredentialFallback 验证 Authorization Bearer 承载 base64 凭证的兼容通道。
func TestBearerCredentialFallback(t *testing.T) {
	front, recorded, mu := newTestServer(t, sseStream())

	header := freshCredentialHeader(t, "bearer@example.com", "at")
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Authorization", "Bearer "+header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 1 {
		t.Fatalf("expected 1 upstream request, got %d", len(*recorded))
	}
	auth := (*recorded)[0].header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer header.") {
		t.Fatalf("upstream must receive Bearer access_token, got %q", auth)
	}
}

func getModels(t *testing.T, baseURL, credentialHeader, path string, extra http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Credentials", credentialHeader)
	for key, values := range extra {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// TestModelsEndToEnd 验证 models 清单接口的完整链路与出站头构造。
func TestModelsEndToEnd(t *testing.T) {
	const manifestBody = `{"models":[{"slug":"gpt-5.3-codex"},{"slug":"gpt-5.3-codex-mini","use_responses_lite":true}]}`
	front, recorded, mu := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"models-1"`)
		_, _ = io.WriteString(w, manifestBody)
	})

	header := freshCredentialHeader(t, "models@example.com", "at")
	resp := getModels(t, front.URL, header, "/v1/models?client_version=0.147.0", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if string(body) != manifestBody {
		t.Fatalf("manifest body must pass through verbatim: %s", body)
	}
	if etag := resp.Header.Get("ETag"); etag != `W/"models-1"` {
		t.Fatalf("ETag must pass through: %q", etag)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 1 {
		t.Fatalf("expected 1 upstream request, got %d", len(*recorded))
	}
	req := (*recorded)[0]

	if req.path != "/backend-api/codex/models" {
		t.Fatalf("unexpected upstream path: %q", req.path)
	}
	if req.query != "client_version=0.147.0" {
		t.Fatalf("client_version must pass through verbatim: %q", req.query)
	}
	if req.host != "chatgpt.com" {
		t.Fatalf("Host not rewritten: %q", req.host)
	}
	if auth := req.header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("missing bearer token: %q", auth)
	}
	if acct := req.header.Get("Chatgpt-Account-Id"); acct != "acct-models@example.com" {
		t.Fatalf("chatgpt-account-id not injected: %q", acct)
	}
	if accept := req.header.Get("Accept"); accept != "application/json" {
		t.Fatalf("models accept must be application/json: %q", accept)
	}
	if ua := req.header.Get("User-Agent"); ua != "codex-tui/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color" {
		t.Fatalf("UA not enforced: %q", ua)
	}
	if orig := req.header.Get("Originator"); orig != "codex-tui" {
		t.Fatalf("originator not enforced: %q", orig)
	}
	if v := req.header.Get("Version"); v != "0.147.0" {
		t.Fatalf("version header must follow client_version: %q", v)
	}
	if _, leaked := req.header["X-Credentials"]; leaked {
		t.Fatal("X-Credentials must not be forwarded upstream")
	}
}

// TestModelsDefaultAndFallbackVersion 验证 client_version 缺失补规范版本、
// 陈旧版本仅回退 Version 头、query 原值仍透传。
func TestModelsDefaultAndFallbackVersion(t *testing.T) {
	front, recorded, mu := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"models":[]}`)
	})

	header := freshCredentialHeader(t, "models2@example.com", "at")

	// chatgpt_base_url 模式：无 query → 补规范版本。
	resp := getModels(t, front.URL, header, "/backend-api/codex/models", nil)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// 陈旧 client_version：query 原值透传，Version 头回退规范版本。
	resp2 := getModels(t, front.URL, header, "/models?client_version=0.140.0", nil)
	_, _ = io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 2 {
		t.Fatalf("expected 2 upstream requests, got %d", len(*recorded))
	}
	if got := (*recorded)[0].query; got != "client_version=0.146.0" {
		t.Fatalf("missing client_version must default to canonical: %q", got)
	}
	if got := (*recorded)[0].header.Get("Version"); got != "0.146.0" {
		t.Fatalf("default version header mismatch: %q", got)
	}
	if got := (*recorded)[1].query; got != "client_version=0.140.0" {
		t.Fatalf("stale client_version must pass through verbatim: %q", got)
	}
	if got := (*recorded)[1].header.Get("Version"); got != "0.146.0" {
		t.Fatalf("stale version header must fall back to canonical: %q", got)
	}
}

// TestModelsETagNotModified 验证 If-None-Match 透传与 304 回放。
func TestModelsETagNotModified(t *testing.T) {
	front, recorded, mu := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"models-1"` {
			w.Header().Set("ETag", `W/"models-1"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"models-2"`)
		_, _ = io.WriteString(w, `{"models":[]}`)
	})

	header := freshCredentialHeader(t, "models3@example.com", "at")
	extra := http.Header{"If-None-Match": []string{`W/"models-1"`}}
	resp := getModels(t, front.URL, header, "/v1/models?client_version=0.146.0", extra)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if len(body) != 0 {
		t.Fatalf("304 must not carry a body: %q", body)
	}

	mu.Lock()
	defer mu.Unlock()
	if got := (*recorded)[0].header.Get("If-None-Match"); got != `W/"models-1"` {
		t.Fatalf("If-None-Match must pass through: %q", got)
	}
}

// TestModelsUnauthorizedForcesRefreshAndRetries 验证 models 401 → 强制刷新 → 重试一次。
func TestModelsUnauthorizedForcesRefreshAndRetries(t *testing.T) {
	var refreshCalls int64
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&refreshCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-new","expires_in":3600}`,
			makeJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}))
	}))
	defer refreshSrv.Close()
	swapTokenURL(t, refreshSrv.URL)

	var upstreamCalls int64
	front, recorded, mu := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&upstreamCalls, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"token expired"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"models":[{"slug":"gpt-5.3-codex"}]}`)
	})

	header := freshCredentialHeader(t, "models-retry@example.com", "at-stale")
	resp := getModels(t, front.URL, header, "/v1/models?client_version=0.146.0", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry should succeed, status = %d body = %s", resp.StatusCode, body)
	}
	if atomic.LoadInt64(&refreshCalls) != 1 {
		t.Fatalf("expected 1 refresh after 401, got %d", refreshCalls)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) != 2 {
		t.Fatalf("expected 2 upstream attempts, got %d", len(*recorded))
	}
	if (*recorded)[0].header.Get("Authorization") == (*recorded)[1].header.Get("Authorization") {
		t.Fatal("retry must use the refreshed token")
	}
}
