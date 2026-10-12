// Package server 提供 oai-mini-proxy 的 HTTP 入口：Codex OAuth 凭证中转 +
// 风控伪装（身份头收口、引擎指纹兜底、TLS 指纹）+ email 维度凭证缓存刷新。
package server

import (
	"fmt"
	"log"
	"net/http"

	"oai-mini-proxy/internal/codex"
	"oai-mini-proxy/internal/config"
	"oai-mini-proxy/internal/credential"
	"oai-mini-proxy/internal/manager"
	"oai-mini-proxy/internal/upstream"
)

// fallbackCodexVersion 是版本配置非法时的编译期兜底（对齐 sub2api codexCLIVersion 语义：
// 必须跟随官方 CLI 当前发布版本，落后会稳定落在被优先降载的一侧）。
const fallbackCodexVersion = "0.146.0"

// Server 持有全部依赖并暴露 HTTP 路由。
type Server struct {
	cfg     *config.Config
	logger  *log.Logger
	store   *credential.Store
	pool    *upstream.Pool
	kit     *codex.Kit
	manager *manager.Manager
}

// New 装配服务依赖。
func New(cfg *config.Config, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}

	store, err := credential.NewStore(cfg.CacheDir)
	if err != nil {
		return nil, err
	}

	pool := upstream.NewPool(cfg)
	kit := codex.NewKit(cfg.CodexVersion, cfg.CodexUserAgent, fallbackCodexVersion)

	return &Server{
		cfg:     cfg,
		logger:  logger,
		store:   store,
		pool:    pool,
		kit:     kit,
		manager: manager.New(cfg, store, pool, kit),
	}, nil
}

// Kit 返回身份套件（供启动日志展示）。
func (s *Server) Kit() *codex.Kit { return s.kit }

// StoreDir 返回凭证缓存目录（供启动日志展示）。
func (s *Server) StoreDir() string { return s.store.Dir() }

// Handler 返回路由表。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Responses 主端点与子路径（/compact、/input_tokens 等按 suffix 透传）。
	mux.HandleFunc("POST /v1/responses", s.handleResponses)
	mux.HandleFunc("POST /v1/responses/", s.handleResponses)
	mux.HandleFunc("POST /backend-api/codex/responses", s.handleResponses)
	mux.HandleFunc("POST /backend-api/codex/responses/", s.handleResponses)

	// Models 清单端点：Codex CLI 的 custom provider 模式（/v1/models、/models）
	// 与 chatgpt_base_url 模式（/backend-api/codex/models）统一映射到上游 /models。
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("GET /models", s.handleModels)
	mux.HandleFunc("GET /backend-api/codex/models", s.handleModels)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","upstream":%q}`+"\n", s.cfg.UpstreamBase)
	})

	return mux
}

// logf 输出带前缀的运行日志。
func (s *Server) logf(format string, args ...any) {
	s.logger.Printf("[oai-mini-proxy] "+format, args...)
}
