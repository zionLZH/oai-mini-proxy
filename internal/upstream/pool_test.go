package upstream

import (
	"context"
	"testing"
	"time"

	"oai-mini-proxy/internal/config"
)

// TestFingerprintDirectDialTimeout 回归测试：指纹直连 transport 的
// DialTLSContext 必须有界（曾因兜底 dialer 无超时导致直连不可达时永久挂起）。
func TestFingerprintDirectDialTimeout(t *testing.T) {
	cfg := &config.Config{DialTimeout: 300 * time.Millisecond, ResponseHeaderTimeout: time.Second}
	transport, err := buildTransport(cfg, nil, true)
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	if transport.DialTLSContext == nil {
		t.Fatal("fingerprint direct transport must set DialTLSContext")
	}

	start := time.Now()
	conn, err := transport.DialTLSContext(context.Background(), "tcp", "10.255.255.1:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial failure to unreachable address")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("fingerprint direct dial must fail fast, took %s: %v", elapsed, err)
	}
}
