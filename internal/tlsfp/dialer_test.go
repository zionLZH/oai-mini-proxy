package tlsfp

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"
)

// TestDialerFailsFastOnUnreachableAddress 验证直连指纹 dialer 的 TCP 建连
// 受 DialTimeout 约束（回归：曾因兜底 dialer 无超时导致直连不可达时永久挂起）。
func TestDialerFailsFastOnUnreachableAddress(t *testing.T) {
	base := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext
	dialer := NewDialer(nil, base, 300*time.Millisecond)

	start := time.Now()
	conn, err := dialer.DialTLSContext(context.Background(), "tcp", "10.255.255.1:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial failure to unreachable address")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("dial must fail fast, took %s: %v", elapsed, err)
	}
}

// TestHTTPProxyDialerFailsFastOnUnreachableProxy 验证代理不可达时快速失败。
func TestHTTPProxyDialerFailsFastOnUnreachableProxy(t *testing.T) {
	proxyURL, err := url.Parse("http://10.255.255.1:8080")
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	dialer := NewHTTPProxyDialer(nil, proxyURL, 300*time.Millisecond)

	start := time.Now()
	conn, err := dialer.DialTLSContext(context.Background(), "tcp", "chatgpt.com:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial failure to unreachable proxy")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("proxy dial must fail fast, took %s: %v", elapsed, err)
	}
}

// TestSOCKS5ProxyDialerFailsFastOnUnreachableProxy 验证 SOCKS5 代理不可达时快速失败。
func TestSOCKS5ProxyDialerFailsFastOnUnreachableProxy(t *testing.T) {
	proxyURL, err := url.Parse("socks5h://10.255.255.1:1080")
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	dialer := NewSOCKS5ProxyDialer(nil, proxyURL, 300*time.Millisecond)

	start := time.Now()
	conn, err := dialer.DialTLSContext(context.Background(), "tcp", "chatgpt.com:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial failure to unreachable proxy")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("socks5 proxy dial must fail fast, took %s: %v", elapsed, err)
	}
}
