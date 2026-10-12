package proxyurl

import "testing"

func TestParseEmptyMeansDirect(t *testing.T) {
	trimmed, parsed, err := Parse("   ")
	if err != nil || trimmed != "" || parsed != nil {
		t.Fatalf("empty input must mean direct: %q %v %v", trimmed, parsed, err)
	}
}

func TestParseUpgradesSocks5ToSocks5h(t *testing.T) {
	trimmed, parsed, err := Parse("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Scheme != "socks5h" {
		t.Fatalf("socks5 must upgrade to socks5h, got %q", parsed.Scheme)
	}
	if trimmed != "socks5h://user:pass@127.0.0.1:1080" {
		t.Fatalf("unexpected trimmed form: %q", trimmed)
	}
}

func TestParseAcceptance(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:7890",
		"https://proxy.example.com:443",
		"socks5h://127.0.0.1:1080",
		"http://user:pass@proxy.example.com:3128",
	} {
		if _, _, err := Parse(raw); err != nil {
			t.Fatalf("expected %q to be valid: %v", raw, err)
		}
	}
}

func TestParseFailFast(t *testing.T) {
	for _, raw := range []string{
		"ftp://proxy.example.com:21",
		"http://",
		"://missing-scheme",
		"not a url at all",
	} {
		if _, _, err := Parse(raw); err == nil {
			t.Fatalf("expected %q to fail fast", raw)
		}
	}
}
