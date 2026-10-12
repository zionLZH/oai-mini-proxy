package codex

import (
	"net/http"
	"strings"
)

// Identity 是自洽的出站身份三元组：originator 与 User-Agent 首段配套，
// version 等于 UA 版本段且不低于上游门槛。
type Identity struct {
	UserAgent  string
	Originator string
	Version    string
}

// Kit 由配置解析出规范出站身份；对所有出站路径共用一份快照。
type Kit struct {
	canonical Identity
}

// NewKit 构建身份套件。
//   - version 为期望声明的 Codex 客户端版本，非法或低于上游门槛时回退 fallbackVersion；
//   - overrideUA 非空时优先采用（只贡献客户端名与 OS/架构/终端指纹，版本段与
//     originator 一律由规范身份重建，避免历史版本 UA 把出站身份钉死在陈旧版本）。
func NewKit(version, overrideUA, fallbackVersion string) *Kit {
	effective := NormalizeCodexClientVersion(version)
	fallback := NormalizeCodexClientVersion(fallbackVersion)
	if fallback == "" {
		fallback = "0.146.0"
	}
	if effective == "" || CompareVersions(effective, codexUpstreamMinVersion) < 0 {
		effective = fallback
	}
	if CompareVersions(effective, codexUpstreamMinVersion) < 0 {
		effective = codexUpstreamMinVersion
	}

	canonicalUA := CodexDefaultOriginator + "/" + effective + CodexCLIUserAgentSuffix
	kit := &Kit{
		canonical: Identity{
			UserAgent:  canonicalUA,
			Originator: CodexDefaultOriginator,
			Version:    effective,
		},
	}

	if override := strings.TrimSpace(overrideUA); override != "" {
		if id, ok := kit.resolveFromUA(override); ok {
			kit.canonical = id
		}
	}
	return kit
}

// Canonical 返回规范出站身份。
func (k *Kit) Canonical() Identity {
	if k == nil {
		return Identity{}
	}
	return k.canonical
}

// Resolve 由候选 UA 推导自洽身份；推导失败时整体回退规范身份。
// 候选 UA 的客户端名会被保留（真实身份骨架），但版本段与 originator 同源重建。
func (k *Kit) Resolve(candidateUA string) Identity {
	if k == nil {
		return Identity{}
	}
	candidate := strings.TrimSpace(candidateUA)
	if candidate == "" {
		return k.canonical
	}
	if id, ok := k.resolveFromUA(candidate); ok {
		return id
	}
	return k.canonical
}

// resolveFromUA 用规范版本的版本段重建候选 UA 的版本声明。
func (k *Kit) resolveFromUA(ua string) (Identity, bool) {
	originator, pairedUA, ok := PairCodexClientIdentity(ua)
	if !ok {
		return Identity{}, false
	}
	if rebuilt := SetCodexUserAgentVersion(pairedUA, k.canonical.Version); rebuilt != "" {
		pairedUA = rebuilt
	}
	return Identity{
		UserAgent:  pairedUA,
		Originator: originator,
		Version:    k.canonical.Version,
	}, true
}

// VersionHeader 协商 models 请求的 Version 头（对齐 sub2api FetchCodexModelsManifest）：
// 客户端自报版本合法且不低于上游门槛时原样使用，否则回退规范版本，
// 避免陈旧 version 触发上游 404（issue #3901）。
func (k *Kit) VersionHeader(candidate string) string {
	if k == nil {
		return ""
	}
	version := NormalizeCodexClientVersion(candidate)
	if version == "" || CompareVersions(version, codexUpstreamMinVersion) < 0 {
		return k.canonical.Version
	}
	return version
}

// ApplyUpstreamIdentity 收口出站身份（对齐 sub2api 的 enforceCodexIdentityHeaders：
// 强制统一 User-Agent / originator / version，客户端自报身份不参与构造）。
func ApplyUpstreamIdentity(h http.Header, id Identity) {
	if h == nil || id.UserAgent == "" {
		return
	}
	h.Set("user-agent", id.UserAgent)
	h.Set("originator", id.Originator)
	h.Set("version", id.Version)
}
