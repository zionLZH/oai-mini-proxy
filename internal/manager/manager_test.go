package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oai-mini-proxy/internal/codex"
	"oai-mini-proxy/internal/config"
	"oai-mini-proxy/internal/credential"
	"oai-mini-proxy/internal/oauth"
	"oai-mini-proxy/internal/upstream"
)

func testJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"exp": exp.Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
}

func testManager(t *testing.T, refreshHandler http.HandlerFunc) (*Manager, *int64) {
	t.Helper()

	var refreshCalls int64
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&refreshCalls, 1)
		refreshHandler(w, r)
	}))
	t.Cleanup(refreshSrv.Close)

	prev := oauth.TokenURL
	oauth.TokenURL = refreshSrv.URL
	t.Cleanup(func() { oauth.TokenURL = prev })

	store, err := credential.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	cfg := &config.Config{
		RefreshSkew:           5 * time.Minute,
		DialTimeout:           5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		CodexVersion:          "0.146.0",
	}
	pool := upstream.NewPool(cfg)
	kit := codex.NewKit(cfg.CodexVersion, "", "0.146.0")
	return New(cfg, store, pool, kit), &refreshCalls
}

func expiredCredential(t *testing.T) *credential.Credential {
	t.Helper()
	cred, err := credential.FromMap(map[string]any{
		"access_token":  testJWT(t, time.Now().Add(-time.Hour)),
		"refresh_token": "rt-old",
		"email":         "single@example.com",
	})
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	return cred
}

// TestConcurrentResolveSingleFlight 并发请求同一过期凭证时，刷新只发生一次。
func TestConcurrentResolveSingleFlight(t *testing.T) {
	mgr, refreshCalls := testManager(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond) // 拉长刷新窗口，暴露并发竞态
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-rotated","expires_in":3600}`, testJWT(t, time.Now().Add(time.Hour)))
	})

	header := expiredCredential(t)
	const workers = 20

	var wg sync.WaitGroup
	results := make([]*credential.Credential, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = mgr.Resolve(context.Background(), header, "", nil)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(refreshCalls); got != 1 {
		t.Fatalf("single-flight violated: %d refresh calls", got)
	}
	first := results[0].AccessToken
	for i, res := range results {
		if res.AccessToken != first {
			t.Fatalf("worker %d got different access token", i)
		}
		if res.RefreshToken != "rt-rotated" {
			t.Fatalf("worker %d missing rotated refresh token: %q", i, res.RefreshToken)
		}
	}
}

// TestResolveCacheFirst 刷新后写入缓存；后续请求即使传入旧凭证也命中缓存。
func TestResolveCacheFirst(t *testing.T) {
	mgr, refreshCalls := testManager(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-rotated","expires_in":3600}`, testJWT(t, time.Now().Add(time.Hour)))
	})

	header := expiredCredential(t)
	first, err := mgr.Resolve(context.Background(), header, "", nil)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if atomic.LoadInt64(refreshCalls) != 1 {
		t.Fatalf("expected 1 refresh, got %d", *refreshCalls)
	}

	second, err := mgr.Resolve(context.Background(), header, "", nil)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if atomic.LoadInt64(refreshCalls) != 1 {
		t.Fatalf("cache hit must not refresh again, got %d", *refreshCalls)
	}
	if first.AccessToken != second.AccessToken {
		t.Fatal("cache hit must return the persisted token")
	}
}

// TestRefreshFallbackToHeaderToken 缓存链被撤销时回退用传入凭证的 refresh_token。
func TestRefreshFallbackToHeaderToken(t *testing.T) {
	var calls int64
	mgr, _ := testManager(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		n := atomic.AddInt64(&calls, 1)
		if n == 1 {
			if got := r.Form.Get("refresh_token"); got != "rt-cached" {
				t.Errorf("first attempt must use cached chain, got %q", got)
			}
			// 缓存链（rt-cached）已被上游撤销。
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		if got := r.Form.Get("refresh_token"); got != "rt-header" {
			t.Errorf("fallback attempt must use header token, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt-header-new","expires_in":3600}`, testJWT(t, time.Now().Add(time.Hour)))
	})

	header, err := credential.FromMap(map[string]any{
		"access_token":  testJWT(t, time.Now().Add(-time.Hour)),
		"refresh_token": "rt-header",
		"email":         "fallback@example.com",
	})
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}

	// 预置一条持有旧轮换链（rt-cached）的缓存记录，且已过期。
	cached, err := credential.FromMap(map[string]any{
		"access_token":  testJWT(t, time.Now().Add(-2*time.Hour)),
		"refresh_token": "rt-cached",
		"email":         "fallback@example.com",
	})
	if err != nil {
		t.Fatalf("build cached credential: %v", err)
	}
	if err := mgr.store.Save(header.CacheKey(), cached); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	resolved, err := mgr.Resolve(context.Background(), header, "", nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.RefreshToken != "rt-header-new" {
		t.Fatalf("fallback refresh did not take effect: %+v", resolved)
	}
	if atomic.LoadInt64(&calls) != 2 {
		t.Fatalf("expected 2 refresh attempts (cached then fallback), got %d", calls)
	}
}
