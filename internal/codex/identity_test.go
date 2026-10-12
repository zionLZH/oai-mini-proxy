package codex

import (
	"net/http"
	"strings"
	"testing"
)

func TestPairCodexClientIdentityLeadingSegment(t *testing.T) {
	ua := "codex-tui/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color"
	originator, paired, ok := PairCodexClientIdentity(ua)
	if !ok {
		t.Fatal("expected pairing to succeed")
	}
	if originator != "codex-tui" || paired != ua {
		t.Fatalf("unexpected pair: %q %q", originator, paired)
	}
}

func TestPairCodexClientIdentityTrailerRecovery(t *testing.T) {
	// CODEX_INTERNAL_ORIGINATOR_OVERRIDE 场景：首段被改成 cccc，尾部保留真实客户端。
	ua := "cccc/0.142.0 (Mac OS 15.3.0; arm64) xterm-256color (codex-tui; 0.142.0)"
	originator, paired, ok := PairCodexClientIdentity(ua)
	if !ok {
		t.Fatal("expected trailer recovery to succeed")
	}
	if originator != "codex-tui" {
		t.Fatalf("expected recovered originator codex-tui, got %q", originator)
	}
	if !strings.HasPrefix(paired, "codex-tui/0.142.0 ") {
		t.Fatalf("UA leading segment not rewritten: %q", paired)
	}
}

func TestPairCodexClientIdentityRejectsForeignUA(t *testing.T) {
	if _, _, ok := PairCodexClientIdentity("curl/8.0.1"); ok {
		t.Fatal("foreign UA must not pair")
	}
	if _, _, ok := PairCodexClientIdentity("evil/bash/1.0"); ok {
		t.Fatal("non-official client must not pair")
	}
	if _, _, ok := PairCodexClientIdentity("codex_cli_rs\ninjection"); ok {
		t.Fatal("UA with CR/LF must not pair")
	}
}

func TestPairCodexClientIdentityCaseCanonicalization(t *testing.T) {
	originator, paired, ok := PairCodexClientIdentity("CODEX_CLI_RS/0.146.0 (Linux) bash")
	if !ok {
		t.Fatal("expected case variant to pair")
	}
	if originator != "codex_cli_rs" {
		t.Fatalf("expected canonical lowercase originator, got %q", originator)
	}
	if !strings.HasPrefix(paired, "codex_cli_rs/") {
		t.Fatalf("leading segment must be canonicalized: %q", paired)
	}
}

func TestSetCodexUserAgentVersionRebuildsBothSegments(t *testing.T) {
	ua := "cccc/0.142.0 (Mac OS 15.3.0; arm64) xterm-256color (codex-tui; 0.142.0)"
	rebuilt := SetCodexUserAgentVersion(ua, "0.147.0")
	if rebuilt == "" {
		t.Fatal("expected rebuild to succeed")
	}
	if !strings.Contains(rebuilt, "cccc/0.147.0 ") {
		t.Fatalf("leading version not updated: %q", rebuilt)
	}
	if !strings.Contains(rebuilt, "(codex-tui; 0.147.0)") {
		t.Fatalf("trailer version not updated: %q", rebuilt)
	}
}

func TestKitDefaultIdentity(t *testing.T) {
	kit := NewKit("0.146.0", "", "0.146.0")
	id := kit.Canonical()
	if id.Originator != "codex-tui" || id.Version != "0.146.0" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if !strings.HasPrefix(id.UserAgent, "codex-tui/0.146.0 ") {
		t.Fatalf("unexpected canonical UA: %q", id.UserAgent)
	}

	// 低于上游门槛的版本必须回退。
	kitOld := NewKit("0.100.0", "", "0.146.0")
	if kitOld.Canonical().Version != "0.146.0" {
		t.Fatalf("sub-threshold version must fall back: %+v", kitOld.Canonical())
	}

	// 非法版本必须回退。
	kitBad := NewKit("not-a-version", "", "0.146.0")
	if kitBad.Canonical().Version != "0.146.0" {
		t.Fatalf("invalid version must fall back: %+v", kitBad.Canonical())
	}
}

func TestKitOverrideUAKeepsSkeletonButRebuildsVersion(t *testing.T) {
	kit := NewKit("0.146.0", "codex_vscode/0.140.0 (Windows 11; x64) powershell", "0.146.0")
	id := kit.Canonical()
	if id.Originator != "codex_vscode" {
		t.Fatalf("originator must follow override skeleton: %+v", id)
	}
	if !strings.HasPrefix(id.UserAgent, "codex_vscode/0.146.0 ") {
		t.Fatalf("override version must be rebuilt from canonical: %q", id.UserAgent)
	}
	if id.Version != "0.146.0" {
		t.Fatalf("version must be canonical: %+v", id)
	}
}

func TestApplyUpstreamIdentityEnforcesTriple(t *testing.T) {
	h := http.Header{}
	h.Set("user-agent", "client-supplied/1.0")
	h.Set("originator", "client-supplied")
	ApplyUpstreamIdentity(h, Identity{
		UserAgent:  "codex-tui/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color",
		Originator: "codex-tui",
		Version:    "0.146.0",
	})
	if h.Get("user-agent") != "codex-tui/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color" {
		t.Fatalf("UA not enforced: %q", h.Get("user-agent"))
	}
	if h.Get("originator") != "codex-tui" || h.Get("version") != "0.146.0" {
		t.Fatalf("identity not enforced: %+v", h)
	}
}

func TestVersionHeaderNegotiation(t *testing.T) {
	kit := NewKit("0.146.0", "", "0.146.0")

	// 合法且不低于上游门槛：原样使用。
	if got := kit.VersionHeader("0.147.0"); got != "0.147.0" {
		t.Fatalf("valid client version must pass through: %q", got)
	}
	if got := kit.VersionHeader("0.146.0"); got != "0.146.0" {
		t.Fatalf("floor version must pass through: %q", got)
	}

	// 低于门槛 / 缺失 / 非法：回退规范版本。
	for _, candidate := range []string{"0.140.0", "", "not-a-version", "  "} {
		if got := kit.VersionHeader(candidate); got != "0.146.0" {
			t.Fatalf("VersionHeader(%q) = %q, want canonical 0.146.0", candidate, got)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	if CompareVersions("0.146.0", "0.144.0") <= 0 {
		t.Fatal("0.146.0 must be greater than 0.144.0")
	}
	if CompareVersions("0.144.0", "0.144.0") != 0 {
		t.Fatal("equal versions must compare equal")
	}
	if CompareVersions("0.143.9", "0.144.0") >= 0 {
		t.Fatal("0.143.9 must be less than 0.144.0")
	}
}
