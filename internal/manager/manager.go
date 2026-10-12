// Package manager 编排「凭证解析 → 缓存命中 → 过期刷新 → 回写」的完整生命周期。
//
// 核心语义（对齐用户要求）：
//   - 传入的凭证里有 email（几乎唯一），以其为缓存键把刷新后的凭证落盘；
//   - 请求进来先读本地缓存，有则用缓存的（refresh_token 轮换链的最新态）；
//   - 缓存缺失时用传入凭证，传入地址无效则刷新重试；
//   - 刷新发生在 email 维度的 single-flight 锁内，并发请求不会各自刷新
//     （rolling refresh 只允许一个赢家，其余请求复用刷新结果）。
package manager

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"oai-mini-proxy/internal/codex"
	"oai-mini-proxy/internal/config"
	"oai-mini-proxy/internal/credential"
	"oai-mini-proxy/internal/oauth"
	"oai-mini-proxy/internal/upstream"
)

// ErrNoRefreshToken 表示凭证与缓存都不含 refresh_token，无法刷新。
var ErrNoRefreshToken = fmt.Errorf("no refresh_token available (credential is not refreshable)")

// Manager 是凭证生命周期管理器。
type Manager struct {
	cfg   *config.Config
	store *credential.Store
	pool  *upstream.Pool
	kit   *codex.Kit
}

// New 创建管理器。
func New(cfg *config.Config, store *credential.Store, pool *upstream.Pool, kit *codex.Kit) *Manager {
	return &Manager{cfg: cfg, store: store, pool: pool, kit: kit}
}

// Resolve 解析本次请求实际应使用的凭证。
// 快路径直接命中未过期缓存；未命中或已过期则在 single-flight 锁内合并/刷新。
func (m *Manager) Resolve(ctx context.Context, header *credential.Credential, proxyKey string, proxyURL *url.URL) (*credential.Credential, error) {
	if header == nil {
		return nil, fmt.Errorf("nil credential")
	}
	key := header.CacheKey()

	if cached, ok := m.store.Load(key); ok && !cached.IsExpired(time.Now(), m.cfg.RefreshSkew) {
		return cached, nil
	}

	var result *credential.Credential
	err := m.store.WithLock(key, func() error {
		// double-check：锁内重读，可能已被并发的先到请求刷新。
		base := header
		if cached, ok := m.store.Load(key); ok {
			base = mergeCredentials(header, cached)
		}
		if !base.IsExpired(time.Now(), m.cfg.RefreshSkew) {
			result = base
			return nil
		}

		refreshed, err := m.refresh(ctx, key, base, header, proxyKey, proxyURL)
		if err != nil {
			return err
		}
		result = refreshed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ForceRefresh 在处理上游 401 时强制刷新（忽略缓存 token 的新鲜度）。
// 若锁内发现缓存 token 已被其它请求更新（与 current 不同），直接复用缓存，
// 避免对同一失败 token 做重复刷新。
func (m *Manager) ForceRefresh(ctx context.Context, header, current *credential.Credential, proxyKey string, proxyURL *url.URL) (*credential.Credential, error) {
	key := header.CacheKey()

	var result *credential.Credential
	err := m.store.WithLock(key, func() error {
		base := header
		if cached, ok := m.store.Load(key); ok {
			base = mergeCredentials(header, cached)
			if current != nil && cached.AccessToken != "" && cached.AccessToken != current.AccessToken {
				// 其他请求已完成刷新，直接用新结果。
				result = base
				return nil
			}
		}
		refreshed, err := m.refresh(ctx, key, base, header, proxyKey, proxyURL)
		if err != nil {
			return err
		}
		result = refreshed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// refresh 在已持锁的上下文中执行刷新并回写缓存。
// 刷新 token 的选择：缓存的轮换链优先，其次传入值；主选失败且两者不同时
// 用传入值再试一次（覆盖「缓存链已被上游撤销、调用方重新登录」的场景）。
func (m *Manager) refresh(ctx context.Context, key string, base, header *credential.Credential, proxyKey string, proxyURL *url.URL) (*credential.Credential, error) {
	candidates := make([]string, 0, 2)
	if base.RefreshToken != "" {
		candidates = append(candidates, base.RefreshToken)
	}
	if header.RefreshToken != "" && header.RefreshToken != base.RefreshToken {
		candidates = append(candidates, header.RefreshToken)
	}
	if len(candidates) == 0 {
		return nil, ErrNoRefreshToken
	}

	client, err := m.pool.RefreshClient(proxyKey, proxyURL)
	if err != nil {
		return nil, err
	}
	identity := m.kit.Canonical()
	refresher := oauth.NewRefresher(client, identity.UserAgent, identity.Originator)

	clientID := base.ClientID
	if clientID == "" {
		clientID = header.ClientID
	}

	var lastErr error
	for _, refreshToken := range candidates {
		resp, err := refresher.Refresh(ctx, refreshToken, clientID)
		if err != nil {
			lastErr = err
			continue
		}

		now := time.Now()
		base.MergeInto(resp.AccessToken, resp.RefreshToken, resp.IDToken, resp.ExpiresAt(now))
		if rebuilt, err := credential.FromMap(base.Raw); err == nil {
			base = rebuilt
		}
		m.store.Stamp(key, base, now)
		if err := m.store.Save(key, base); err != nil {
			// 刷新成功但落盘失败：本次仍可用，只影响下次请求的缓存命中。
			return base, nil
		}
		return base, nil
	}
	return nil, fmt.Errorf("refresh failed for all candidate tokens: %w", lastErr)
}

// mergeCredentials 合并传入凭证与缓存凭证：
// 以缓存为基底（持有最新的 refresh_token 轮换链），仅当缓存缺失时用传入值补齐。
func mergeCredentials(header, cached *credential.Credential) *credential.Credential {
	if cached == nil {
		return header
	}
	if cached.Raw == nil {
		cached.Raw = make(map[string]any)
	}
	if cached.AccessToken == "" {
		cached.AccessToken = header.AccessToken
		cached.Raw["access_token"] = header.AccessToken
	}
	if cached.RefreshToken == "" && header.RefreshToken != "" {
		cached.RefreshToken = header.RefreshToken
		cached.Raw["refresh_token"] = header.RefreshToken
	}
	if cached.ClientID == "" && header.ClientID != "" {
		cached.ClientID = header.ClientID
		cached.Raw["client_id"] = header.ClientID
	}
	if cached.Email == "" && header.Email != "" {
		cached.Email = header.Email
		cached.Raw["email"] = header.Email
	}
	if cached.ChatGPTAccountID == "" && header.ChatGPTAccountID != "" {
		cached.ChatGPTAccountID = header.ChatGPTAccountID
		cached.Raw["chatgpt_account_id"] = header.ChatGPTAccountID
	}
	if cached.ChatGPTUserID == "" && header.ChatGPTUserID != "" {
		cached.ChatGPTUserID = header.ChatGPTUserID
		cached.Raw["chatgpt_user_id"] = header.ChatGPTUserID
	}
	return cached
}
