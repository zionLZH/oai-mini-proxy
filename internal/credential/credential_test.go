package credential

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func makeTestJWT(t *testing.T, claims map[string]any) string {
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

func TestDecodeFlatPayload(t *testing.T) {
	header := encodeCredential(t, map[string]any{
		"access_token":       "at-1",
		"refresh_token":      "rt-1",
		"email":              "user@example.com",
		"chatgpt_account_id": "acct-1",
	})
	cred, err := Decode(header)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cred.AccessToken != "at-1" || cred.RefreshToken != "rt-1" {
		t.Fatalf("unexpected tokens: %+v", cred)
	}
	if cred.Email != "user@example.com" || cred.ChatGPTAccountID != "acct-1" {
		t.Fatalf("unexpected identity: %+v", cred)
	}
}

func TestDecodeNestedCredentialsPayload(t *testing.T) {
	header := encodeCredential(t, map[string]any{
		"credentials": map[string]any{
			"access_token":  "at-nested",
			"refresh_token": "rt-nested",
			"email":         "nested@example.com",
		},
	})
	cred, err := Decode(header)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cred.AccessToken != "at-nested" || cred.Email != "nested@example.com" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestDecodeCodexAuthJSONPayload(t *testing.T) {
	header := encodeCredential(t, map[string]any{
		"tokens": map[string]any{
			"access_token":  "at-codex",
			"refresh_token": "rt-codex",
			"id_token":      "id-codex",
			"account_id":    "acct-codex",
		},
	})
	cred, err := Decode(header)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cred.AccessToken != "at-codex" || cred.ChatGPTAccountID != "acct-codex" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestDecodeURLSafeBase64(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"access_token": "at", "email": "u@e.com"})
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	cred, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode url-safe: %v", err)
	}
	if cred.AccessToken != "at" {
		t.Fatalf("unexpected access token: %q", cred.AccessToken)
	}
}

func TestDecodeRejectsInvalid(t *testing.T) {
	if _, err := Decode("not-base64!!!###"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if _, err := Decode(encodeCredential(t, map[string]any{"email": "x@y.z"})); err == nil {
		t.Fatal("expected error when access_token is missing")
	}
}

func TestJWTExtractionFillsMissingFields(t *testing.T) {
	accessJWT := makeTestJWT(t, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-jwt",
			"chatgpt_user_id":    "user-jwt",
		},
	})
	idJWT := makeTestJWT(t, map[string]any{
		"email": "jwt@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	header := encodeCredential(t, map[string]any{
		"access_token":  accessJWT,
		"id_token":      idJWT,
		"refresh_token": "rt",
	})
	cred, err := Decode(header)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cred.Email != "jwt@example.com" {
		t.Fatalf("email not extracted from id_token: %q", cred.Email)
	}
	if cred.ChatGPTAccountID != "acct-jwt" || cred.ChatGPTUserID != "user-jwt" {
		t.Fatalf("account id not extracted from access_token: %+v", cred)
	}
	if cred.ExpiresAt.IsZero() {
		t.Fatal("expires_at not extracted from access_token exp")
	}
}

func TestCacheKeyStableByEmail(t *testing.T) {
	a := &Credential{Email: "user@example.com", AccessToken: "at-1"}
	b := &Credential{Email: "USER@example.com", AccessToken: "at-2"}
	if a.CacheKey() != b.CacheKey() {
		t.Fatalf("cache key should be case-insensitive email based: %s vs %s", a.CacheKey(), b.CacheKey())
	}

	c := &Credential{Email: "other@example.com", AccessToken: "at-1"}
	if a.CacheKey() == c.CacheKey() {
		t.Fatal("different emails must produce different cache keys")
	}
}

func TestCacheKeyFallbacks(t *testing.T) {
	noEmail := &Credential{RefreshToken: "rt-1", AccessToken: "at-1"}
	if noEmail.CacheKey() == "" {
		t.Fatal("fallback cache key must not be empty")
	}
	if noEmail.CacheKey() != (&Credential{RefreshToken: "rt-1", AccessToken: "at-different"}).CacheKey() {
		t.Fatal("fallback should prefer refresh_token fingerprint")
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		expiresAt time.Time
		skew      time.Duration
		want      bool
	}{
		{"unknown expiry is not expired", time.Time{}, 5 * time.Minute, false},
		{"far future", now.Add(time.Hour), 5 * time.Minute, false},
		{"within skew", now.Add(2 * time.Minute), 5 * time.Minute, true},
		{"already expired", now.Add(-time.Minute), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := &Credential{ExpiresAt: tc.expiresAt}
			if got := cred.IsExpired(now, tc.skew); got != tc.want {
				t.Fatalf("IsExpired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMergeIntoUpdatesRaw(t *testing.T) {
	cred := &Credential{
		AccessToken:  "old-at",
		RefreshToken: "old-rt",
		Email:        "u@e.com",
		Raw:          map[string]any{"access_token": "old-at", "custom": "keep-me"},
	}
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	cred.MergeInto("new-at", "new-rt", "new-id", expiry)

	if cred.AccessToken != "new-at" || cred.RefreshToken != "new-rt" || cred.IDToken != "new-id" {
		t.Fatalf("view not updated: %+v", cred)
	}
	if cred.Raw["access_token"] != "new-at" || cred.Raw["refresh_token"] != "new-rt" {
		t.Fatalf("raw not updated: %+v", cred.Raw)
	}
	if cred.Raw["custom"] != "keep-me" {
		t.Fatal("custom fields must be preserved on merge")
	}
	rebuilt, err := FromMap(cred.Raw)
	if err != nil {
		t.Fatalf("rebuild after merge: %v", err)
	}
	if rebuilt.AccessToken != "new-at" || !rebuilt.ExpiresAt.Equal(expiry) {
		t.Fatalf("rebuilt view mismatch: %+v", rebuilt)
	}
}
