// Package codex 负责 Codex 出站身份与风控头构造。
//
// 移植自 sub2api 的 pkg/openai/request.go + service/openai_codex_identity.go：
// 上游 /backend-api/codex 校验 originator 与 UA 首段（首个 '/' 前的 client 名）
// 是否配套，错配一律 404（issue #3901）；version 头必须与 UA 版本段逐字一致且
// 不低于上游门槛 codexUpstreamMinVersion，否则同样 404。
package codex

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// codexUpstreamMinVersion 上游接受的最低 version 头。
const codexUpstreamMinVersion = "0.144.0"

// CodexDefaultOriginator 是网关默认使用的 Codex TUI originator。
const CodexDefaultOriginator = "codex-tui"

// CodexCLIUserAgentSuffix 是规范 TUI UA 的 OS/终端指纹段。
const CodexCLIUserAgentSuffix = " (Ubuntu 22.4.0; x86_64) xterm-256color"

// codexOfficialClientUAPrefixes 是 Codex 官方客户端家族 UA 前缀。
var codexOfficialClientUAPrefixes = []string{
	"codex_cli_rs/",
	"codex-tui/",
	"codex_vscode/",
	"codex_vscode_copilot/",
	"codex_app/",
	"codex_chatgpt_desktop/",
	"codex_atlas/",
	"codex_exec/",
	"codex_sdk_ts/",
}

// codexOfficialClientFamilyPrefix 覆盖 `Codex ` 前缀家族（保留尾随空格）。
const codexOfficialClientFamilyPrefix = "codex "

// codexOfficialClientOriginators 是官方客户端 originator 精确集合。
var codexOfficialClientOriginators = map[string]bool{
	"codex_cli_rs":          true,
	"codex-tui":             true,
	"codex_vscode":          true,
	"codex_vscode_copilot":  true,
	"codex_app":             true,
	"codex_chatgpt_desktop": true,
	"codex_atlas":           true,
	"codex_exec":            true,
	"codex_sdk_ts":          true,
}

// codexClientVersionPattern 允许 0.146.0 与 0.147.0-alpha.4 两类官方形态。
var codexClientVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z.]+)?$`)

// codexEngineVersionPattern 提取版本段开头的三段数字 X.Y.Z（忽略 -alpha 等后缀）。
var codexEngineVersionPattern = regexp.MustCompile(`^(\d+\.\d+\.\d+)`)

const codexOriginatorMaxLen = 64
const codexClientVersionMaxLen = 64

func normalizeCodexClientHeader(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// IsCodexOfficialClientOriginator 判断 originator 是否为官方客户端身份。
func IsCodexOfficialClientOriginator(originator string) bool {
	v := normalizeCodexClientHeader(originator)
	if v == "" {
		return false
	}
	if codexOfficialClientOriginators[v] {
		return true
	}
	return strings.HasPrefix(v, codexOfficialClientFamilyPrefix)
}

func matchCodexClientHeaderPrefixes(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		normalizedPrefix := normalizeCodexClientHeader(prefix)
		if normalizedPrefix == "" {
			continue
		}
		if strings.HasPrefix(value, normalizedPrefix) || strings.Contains(value, normalizedPrefix) {
			return true
		}
	}
	return false
}

// codexUATrailerName 提取 codex-rs UA 最后一个括号组 `(name; version)` 的 name。
func codexUATrailerName(ua string) string {
	last := strings.LastIndex(ua, "(")
	if last < 0 {
		return ""
	}
	rest := ua[last+1:]
	closeIdx := strings.Index(rest, ")")
	if closeIdx < 0 {
		return ""
	}
	inner := strings.TrimSpace(rest[:closeIdx])
	if semi := strings.Index(inner, ";"); semi >= 0 {
		inner = strings.TrimSpace(inner[:semi])
	}
	return inner
}

func validCodexUserAgentValue(value string) bool {
	if !httpguts.ValidHeaderFieldValue(value) {
		return false
	}
	return !strings.ContainsAny(value, "\r\n")
}

func isSaneCodexOriginator(name string) bool {
	if name == "" || len(name) > codexOriginatorMaxLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func canonicalizeCodexOriginator(name string) string {
	if lower := normalizeCodexClientHeader(name); codexOfficialClientOriginators[lower] {
		return lower
	}
	return name
}

// PairCodexClientIdentity 由最终出站 User-Agent 推导与其配套的 originator。
// 推导优先级：
//  1. UA 首段是官方 originator → 直接配对，UA 原样保留；
//  2. UA 尾部括号组的 name 是官方 originator（CODEX_INTERNAL_ORIGINATOR_OVERRIDE
//     只改前缀不改尾部）→ 用尾部 name 重写首段后配对；
//  3. 均不命中 → ok=false，调用方应以规范身份整体回退。
func PairCodexClientIdentity(userAgent string) (originator string, pairedUA string, ok bool) {
	if !validCodexUserAgentValue(userAgent) {
		return "", "", false
	}
	ua := strings.TrimSpace(userAgent)
	slash := strings.IndexByte(ua, '/')
	if slash <= 0 {
		return "", "", false
	}
	if leading := strings.TrimSpace(ua[:slash]); isSaneCodexOriginator(leading) && IsCodexOfficialClientOriginator(leading) {
		leading = canonicalizeCodexOriginator(leading)
		return leading, leading + ua[slash:], true
	}
	if trailer := codexUATrailerName(ua); trailer != "" && !strings.ContainsRune(trailer, '/') &&
		isSaneCodexOriginator(trailer) && IsCodexOfficialClientOriginator(trailer) {
		trailer = canonicalizeCodexOriginator(trailer)
		return trailer, trailer + ua[slash:], true
	}
	return "", "", false
}

// NormalizeCodexClientVersion 校验并归一化 Codex 客户端版本号，非法值返回空串。
func NormalizeCodexClientVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || len(version) > codexClientVersionMaxLen || !codexClientVersionPattern.MatchString(version) {
		return ""
	}
	return version
}

// CodexUserAgentVersion 提取 UA 的完整版本段（保留 -alpha.4 之类后缀）。
func CodexUserAgentVersion(userAgent string) string {
	ua := strings.TrimSpace(userAgent)
	slash := strings.IndexByte(ua, '/')
	if slash <= 0 {
		return ""
	}
	rest := ua[slash+1:]
	if space := strings.IndexByte(rest, ' '); space >= 0 {
		rest = rest[:space]
	}
	return strings.TrimSpace(rest)
}

// SetCodexUserAgentVersion 用 version 重建 UA 的版本声明，其余部分原样保留；
// 尾部 `(name; version)` 组与首段同步更新，避免身份自相矛盾。
func SetCodexUserAgentVersion(userAgent, version string) string {
	ua := strings.TrimSpace(userAgent)
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	slash := strings.IndexByte(ua, '/')
	if slash <= 0 {
		return ""
	}
	client := strings.TrimSpace(ua[:slash])
	if client == "" {
		return ""
	}
	rest := ua[slash+1:]
	tail := ""
	if space := strings.IndexByte(rest, ' '); space >= 0 {
		tail = rest[space:]
	} else if strings.TrimSpace(rest) == "" {
		return ""
	}
	return rewriteCodexUATrailerVersion(client+"/"+version+tail, version)
}

// rewriteCodexUATrailerVersion 把尾部官方客户端标识组的版本改成 version。
func rewriteCodexUATrailerVersion(ua, version string) string {
	open := strings.LastIndex(ua, "(")
	if open < 0 {
		return ua
	}
	closeIdx := strings.Index(ua[open+1:], ")")
	if closeIdx < 0 {
		return ua
	}
	inner := ua[open+1 : open+1+closeIdx]
	semi := strings.Index(inner, ";")
	if semi < 0 {
		return ua
	}
	name := strings.TrimSpace(inner[:semi])
	if name == "" || !IsCodexOfficialClientOriginator(name) {
		return ua
	}
	return ua[:open+1] + name + "; " + version + ua[open+1+closeIdx:]
}

// ParseCodexEngineVersion 从 UA 取引擎版本 X.Y.Z。
func ParseCodexEngineVersion(ua string) (string, bool) {
	ua = strings.TrimSpace(ua)
	slash := strings.IndexByte(ua, '/')
	if slash < 0 {
		return "", false
	}
	rest := ua[slash+1:]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == ' ' || rest[i] == '(' {
			end = i
			break
		}
	}
	m := codexEngineVersionPattern.FindString(strings.TrimSpace(rest[:end]))
	if m == "" {
		return "", false
	}
	return m, true
}

// CompareVersions 对比 semver 三段数字，a<b 返回 -1，a>b 返回 1，相等返回 0。
func CompareVersions(a, b string) int {
	aParts := parseSemver(a)
	bParts := parseSemver(b)
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	result := [3]int{0, 0, 0}
	for i := 0; i < len(parts) && i < 3; i++ {
		if parsed, err := strconv.Atoi(parts[i]); err == nil {
			result[i] = parsed
		}
	}
	return result
}
