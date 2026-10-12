// Package credential 负责「外部传入凭证」的解码、规整与身份提取。
//
// 入站凭证以 base64(JSON) 放在 X-Credentials 头中。为最大限度兼容调用方，
// 解析器同时接受三种形态：
//  1. 扁平形态（sub2api 账号 credentials 原样）：{"access_token":..., "email":..., ...}
//  2. 嵌套形态：{"credentials": {...}}
//  3. Codex CLI auth.json 形态：{"tokens": {"access_token":..., "account_id":...}}
//
// email 用作本地缓存的唯一键（refresh_token 轮换后每次刷新的凭证都回写
// 该键，调用方无需关心刷新）；缺失时依次回退到 id_token / access_token 的
// JWT claims、chatgpt_account_id、token 指纹，保证任何凭证都有稳定键。
package credential

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Credential 是规整后的运行期凭证视图。
// Raw 保留原始字段集合，刷新回写时在其上合并更新，不丢失调用方放入的自定义字段。
type Credential struct {
	AccessToken      string
	RefreshToken     string
	IDToken          string
	ClientID         string
	Email            string
	ChatGPTAccountID string
	ChatGPTUserID    string
	PlanType         string
	IsFedRAMP        bool
	ExpiresAt        time.Time // 零值表示未知
	Raw              map[string]any
}

// jwtClaims 是 access_token / id_token 的宽松 claims 视图。
type jwtClaims struct {
	Email string `json:"email"`
	Sub   string `json:"sub"`
	Exp   int64  `json:"exp"`
	Auth  *struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
		ChatGPTUserID    string `json:"chatgpt_user_id"`
		ChatGPTPlanType  string `json:"chatgpt_plan_type"`
	} `json:"https://api.openai.com/auth"`
}

// Decode 解码 X-Credentials 头中的 base64(JSON)。
// base64 标准/URL 编码与有无 padding 均接受。
func Decode(encoded string) (*Credential, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("credentials header is empty")
	}
	raw, err := decodeBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("credentials header is not valid base64: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("credentials payload is not a JSON object: %w", err)
	}
	return FromMap(payload)
}

// FromMap 从任意形态的凭证 map 构建 Credential。
func FromMap(payload map[string]any) (*Credential, error) {
	if payload == nil {
		return nil, fmt.Errorf("credentials payload is empty")
	}

	flat := flattenCredentialPayload(payload)
	cred := &Credential{
		AccessToken:      stringField(flat, "access_token"),
		RefreshToken:     stringField(flat, "refresh_token"),
		IDToken:          stringField(flat, "id_token"),
		ClientID:         stringField(flat, "client_id"),
		Email:            stringField(flat, "email"),
		ChatGPTAccountID: stringField(flat, "chatgpt_account_id"),
		ChatGPTUserID:    stringField(flat, "chatgpt_user_id"),
		PlanType:         stringField(flat, "chatgpt_plan_type"),
		IsFedRAMP:        boolField(flat, "chatgpt_account_is_fedramp"),
		Raw:              payload,
	}

	// account_id 是 Codex CLI auth.json 中 chatgpt_account_id 的别名。
	if cred.ChatGPTAccountID == "" {
		cred.ChatGPTAccountID = stringField(flat, "account_id")
	}
	// openai_auth_mode / auth_mode 为 sub2api 的辅助字段，不影响转发。
	if cred.PlanType == "" {
		cred.PlanType = stringField(flat, "plan_type")
	}

	// JWT 兜底：access_token 的 claims 与 credential 字段互为印证/补充。
	accessClaims := parseJWTClaims(cred.AccessToken)
	idClaims := parseJWTClaims(cred.IDToken)
	if idClaims != nil {
		if cred.Email == "" {
			cred.Email = strings.TrimSpace(idClaims.Email)
		}
		if cred.ChatGPTAccountID == "" && idClaims.Auth != nil {
			cred.ChatGPTAccountID = strings.TrimSpace(idClaims.Auth.ChatGPTAccountID)
		}
		if cred.ChatGPTUserID == "" && idClaims.Auth != nil {
			cred.ChatGPTUserID = strings.TrimSpace(idClaims.Auth.ChatGPTUserID)
		}
		if cred.PlanType == "" && idClaims.Auth != nil {
			cred.PlanType = strings.TrimSpace(idClaims.Auth.ChatGPTPlanType)
		}
	}
	if accessClaims != nil {
		if cred.Email == "" {
			cred.Email = strings.TrimSpace(accessClaims.Email)
		}
		if cred.ChatGPTAccountID == "" && accessClaims.Auth != nil {
			cred.ChatGPTAccountID = strings.TrimSpace(accessClaims.Auth.ChatGPTAccountID)
		}
		if cred.ChatGPTUserID == "" && accessClaims.Auth != nil {
			cred.ChatGPTUserID = strings.TrimSpace(accessClaims.Auth.ChatGPTUserID)
		}
	}
	// expires_at（ISO8601）优先，其次 access_token JWT exp，最后 expires_in 相对时间。
	cred.ExpiresAt = resolveExpiry(flat, accessClaims)

	if cred.AccessToken == "" {
		return nil, fmt.Errorf("credentials payload has no access_token")
	}
	return cred, nil
}

// CacheKey 返回 email 维度的缓存键（sha256 十六进制，不落原始 email 到文件名）。
// 依次回退：email → id_token/access_token 的 JWT email → chatgpt_account_id
// → refresh_token 指纹 → access_token 指纹。只要任一回退值稳定，缓存即稳定。
func (c *Credential) CacheKey() string {
	seed := strings.ToLower(strings.TrimSpace(c.Email))
	if seed == "" {
		seed = "acct:" + strings.TrimSpace(c.ChatGPTAccountID)
	}
	if seed == "acct:" || seed == "" {
		token := strings.TrimSpace(c.RefreshToken)
		if token == "" {
			token = strings.TrimSpace(c.AccessToken)
		}
		seed = "token:" + token
	}
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%x", sum[:16])
}

// IsExpired 报告 access_token 是否已过期（或将在 skew 内过期）。
// 无法解析到期时间时保守返回 false，由上游 401 驱动强制刷新。
func (c *Credential) IsExpired(now time.Time, skew time.Duration) bool {
	if c == nil || c.ExpiresAt.IsZero() {
		return false
	}
	return now.Add(skew).After(c.ExpiresAt)
}

// MergeInto 把刷新的 token 写回 Raw（保留其余字段），并更新视图。
// 这是刷新后回写缓存与出站的唯一入口，保证字段一致。
func (c *Credential) MergeInto(accessToken, refreshToken, idToken string, expiresAt time.Time) {
	if c.Raw == nil {
		c.Raw = make(map[string]any)
	}
	if accessToken != "" {
		c.AccessToken = accessToken
		c.Raw["access_token"] = accessToken
	}
	if refreshToken != "" {
		c.RefreshToken = refreshToken
		c.Raw["refresh_token"] = refreshToken
	}
	if idToken != "" {
		c.IDToken = idToken
		c.Raw["id_token"] = idToken
	}
	if !expiresAt.IsZero() {
		c.ExpiresAt = expiresAt
		c.Raw["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if c.Email != "" {
		c.Raw["email"] = c.Email
	}
	if c.ChatGPTAccountID != "" {
		c.Raw["chatgpt_account_id"] = c.ChatGPTAccountID
	}
}

// flattenCredentialPayload 将三种已知形态归一为扁平视图。
// 优先级：顶层键 > credentials 子对象 > tokens 子对象。
func flattenCredentialPayload(payload map[string]any) map[string]any {
	flat := make(map[string]any, len(payload)+8)
	for k, v := range payload {
		flat[k] = v
	}
	for _, key := range []string{"credentials", "tokens"} {
		if nested, ok := payload[key].(map[string]any); ok {
			for k, v := range nested {
				if _, exists := flat[k]; !exists {
					flat[k] = v
				}
			}
		}
	}
	return flat
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return strings.TrimSpace(v.String())
	}
	return ""
}

func boolField(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

// parseJWTClaims 解码 JWT payload（不校验签名，仅做提取）。
func parseJWTClaims(token string) *jwtClaims {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	decoded, err := decodeBase64(parts[1])
	if err != nil {
		return nil
	}
	var claims jwtClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil
	}
	return &claims
}

// resolveExpiry 解析 access_token 到期时间。
// 顺序：expires_at（RFC3339）→ access_token 的 exp → 忽略 expires_in。
// 注意刷新响应里的 expires_in 由调用方换算后再 MergeInto，这里不重复处理。
func resolveExpiry(flat map[string]any, accessClaims *jwtClaims) time.Time {
	if raw := stringField(flat, "expires_at"); raw != "" {
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			return ts
		}
	}
	if accessClaims != nil && accessClaims.Exp > 0 {
		return time.Unix(accessClaims.Exp, 0)
	}
	return time.Time{}
}

// decodeBase64 尝试多种 base64 编码（标准/URL、带/不带 padding）。
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64 string")
	}
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
