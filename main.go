// oai-mini-proxy 是 Codex OAuth 订阅凭证的轻量中转服务。
//
// 定位：把 sub2api 中「Codex OAuth 转发 + 风控伪装」的核心内核剥离出来，
// 做成一个无数据库、无管理端的单二进制：
//
//   - 凭证：调用方每个请求通过 X-Credentials 头传入 base64(JSON)；proxy 通过
//     X-Proxy-URL 头传入（base64 或明文）。
//   - 刷新：以凭证中的 email 为缓存键把刷新后的 token 落盘；调用方无需关心
//     refresh_token 轮换，oai-mini-proxy 内部完成「缓存优先 → 过期刷新 → 回写 → 401 重试」。
//   - 风控伪装：Codex 官方身份头收口（originator/UA/version 同源自洽）、引擎
//     指纹兜底（x-codex-window-id 等）、utls TLS 指纹（直连/HTTP CONNECT/SOCKS5）。
//
// 使用示例：
//
//	CRED=$(printf '%s' '{"access_token":"...","refresh_token":"...","email":"a@b.com"}' | base64)
//	curl -N http://127.0.0.1:8317/v1/responses \
//	  -H "X-Credentials: $CRED" \
//	  -H "X-Proxy-URL: c29ja3M1aDovLzEyNy4wLjAuMTo4MTA4" \
//	  -H 'Content-Type: application/json' \
//	  -d '{"model":"gpt-5.3-codex","stream":true,"input":"hello"}'
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"oai-mini-proxy/internal/config"
	"oai-mini-proxy/internal/server"
)

func main() {
	cfg := config.Load()
	logger := log.New(os.Stdout, "", log.LstdFlags)

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Fatalf("[oai-mini-proxy] init failed: %v", err)
	}

	identity := srv.Kit().Canonical()
	logger.Printf("[oai-mini-proxy] listening on %s", cfg.Addr)
	logger.Printf("[oai-mini-proxy] upstream: %s (Host: %s)", cfg.UpstreamBase, cfg.UpstreamHost)
	logger.Printf("[oai-mini-proxy] codex identity: ua=%q originator=%q version=%q",
		identity.UserAgent, identity.Originator, identity.Version)
	logger.Printf("[oai-mini-proxy] tls fingerprint: %v | credential cache: %s | refresh skew: %s",
		cfg.TLSFingerprint, srv.StoreDir(), cfg.RefreshSkew)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		logger.Fatalf("[oai-mini-proxy] server error: %v", err)
	case <-ctx.Done():
		logger.Printf("[oai-mini-proxy] shutting down...")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("[oai-mini-proxy] shutdown error: %v", err)
	}
}
