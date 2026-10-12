package codex

import (
	"encoding/json"
	"testing"
)

func decodeMap(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal normalized body: %v (%s)", err, body)
	}
	return m
}

// TestNormalizeResponsesBodyCherryStudioShape 验证通用客户端形态（无 store）
// 被补全为 store=false + stream=true，且 model/input 语义保持不变。
func TestNormalizeResponsesBodyCherryStudioShape(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","input":[{"role":"system","content":"test"},{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"stream":true}`)
	out, modified := NormalizeResponsesBody(body)
	if modified == 0 {
		t.Fatal("expected modification for body without store")
	}
	m := decodeMap(t, out)
	if string(m["store"]) != "false" {
		t.Fatalf("store = %s, want false", m["store"])
	}
	if string(m["stream"]) != "true" {
		t.Fatalf("stream = %s, want true", m["stream"])
	}
	var inputLen int
	if err := json.Unmarshal(m["input"], &[]json.RawMessage{}); err == nil {
		var items []json.RawMessage
		_ = json.Unmarshal(m["input"], &items)
		inputLen = len(items)
	}
	if inputLen != 2 {
		t.Fatalf("input must be preserved, len = %d", inputLen)
	}
}

// TestNormalizeResponsesBodyAlreadyValidIsByteIdentical 验证已合法请求零改动、
// 逐字节原样（真实 Codex CLI 请求不受影响）。
func TestNormalizeResponsesBodyAlreadyValidIsByteIdentical(t *testing.T) {
	body := []byte(`{"model":"gpt-5.3-codex","stream":true,"store":false,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"reasoning":{"effort":"high"},"include":["reasoning.encrypted_content"]}`)
	out, modified := NormalizeResponsesBody(body)
	if modified != 0 {
		t.Fatalf("modified = %d, want 0", modified)
	}
	if string(out) != string(body) {
		t.Fatalf("body must be byte-identical\n got: %s\nwant: %s", out, body)
	}
}

// TestNormalizeResponsesBodyForcesStoreAndStream 验证显式 store:true / stream:false
// 被强制修正（对齐 sub2api "显式 true 也会强制覆盖"）。
func TestNormalizeResponsesBodyForcesStoreAndStream(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","store":true,"stream":false,"input":"hi"}`)
	out, modified := NormalizeResponsesBody(body)
	if modified == 0 {
		t.Fatal("expected modification")
	}
	m := decodeMap(t, out)
	if string(m["store"]) != "false" || string(m["stream"]) != "true" {
		t.Fatalf("store/stream = %s/%s, want false/true", m["store"], m["stream"])
	}
}

// TestNormalizeResponsesBodyStripsUnsupportedFields 验证内网端点不支持的字段
// 全部被剥离（temperature 等），同时保留支持字段。
func TestNormalizeResponsesBodyStripsUnsupportedFields(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","stream":true,"store":false,"temperature":0.7,"top_p":0.9,"max_output_tokens":100,"metadata":{"a":1},"truncation":"auto","stream_options":{"include_usage":true},"input":"hi"}`)
	out, modified := NormalizeResponsesBody(body)
	if modified == 0 {
		t.Fatal("expected modification")
	}
	m := decodeMap(t, out)
	for _, key := range []string{"temperature", "top_p", "max_output_tokens", "metadata", "truncation", "stream_options"} {
		if _, ok := m[key]; ok {
			t.Fatalf("unsupported field %q must be stripped", key)
		}
	}
	if _, ok := m["model"]; !ok {
		t.Fatal("model must be preserved")
	}
}

// TestNormalizeResponsesBodyPromotesPrompt 验证 prompt 迁移为 input 后删除。
func TestNormalizeResponsesBodyPromotesPrompt(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","stream":true,"store":false,"prompt":"hello","input":null}`)
	out, _ := NormalizeResponsesBody(body)
	m := decodeMap(t, out)
	if string(m["input"]) != `"hello"` {
		t.Fatalf("input = %s, want \"hello\"", m["input"])
	}
	if _, ok := m["prompt"]; ok {
		t.Fatal("prompt must be removed")
	}

	// input 已存在时 prompt 仅删除，不覆盖 input。
	body2 := []byte(`{"model":"gpt-5.5","stream":true,"store":false,"prompt":"hello","input":"keep"}`)
	out2, _ := NormalizeResponsesBody(body2)
	m2 := decodeMap(t, out2)
	if string(m2["input"]) != `"keep"` {
		t.Fatalf("input = %s, want \"keep\"", m2["input"])
	}
	if _, ok := m2["prompt"]; ok {
		t.Fatal("prompt must be removed")
	}
}

// TestNormalizeResponsesBodyEnsuresReasoningInclude 验证带 reasoning 时补齐
// include，已有、重复调用均幂等。
func TestNormalizeResponsesBodyEnsuresReasoningInclude(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","stream":true,"store":false,"reasoning":{"effort":"high"},"input":"hi"}`)
	out, modified := NormalizeResponsesBody(body)
	if modified == 0 {
		t.Fatal("expected include injection")
	}
	m := decodeMap(t, out)
	var include []string
	if err := json.Unmarshal(m["include"], &include); err != nil {
		t.Fatalf("include unmarshal: %v", err)
	}
	if len(include) != 1 || include[0] != "reasoning.encrypted_content" {
		t.Fatalf("include = %v, want [reasoning.encrypted_content]", include)
	}

	// 幂等：对归一化结果再跑一次，零修改。
	out2, modified2 := NormalizeResponsesBody(out)
	if modified2 != 0 || string(out2) != string(out) {
		t.Fatalf("second pass must be no-op, modified=%d", modified2)
	}

	// include 已含目标值时不重复追加。
	bodyWith := []byte(`{"model":"gpt-5.5","stream":true,"store":false,"reasoning":{"effort":"low"},"include":["reasoning.encrypted_content"],"input":"hi"}`)
	out3, modified3 := NormalizeResponsesBody(bodyWith)
	var include3 []string
	_ = json.Unmarshal(decodeMap(t, out3)["include"], &include3)
	if modified3 != 0 || len(include3) != 1 {
		t.Fatalf("existing include must stay untouched, modified=%d include=%v", modified3, include3)
	}

	// 空 reasoning 对象不触发补齐。
	bodyEmpty := []byte(`{"model":"gpt-5.5","stream":true,"store":false,"reasoning":{},"input":"hi"}`)
	_, modified4 := NormalizeResponsesBody(bodyEmpty)
	if modified4 != 0 {
		t.Fatalf("empty reasoning must not trigger include, modified=%d", modified4)
	}
}

// TestNormalizeResponsesBodyPreservesLargeNumbers 验证嵌套大整数逐字节保真
// （RawMessage 不重新编码），避免精度丢失。
func TestNormalizeResponsesBodyPreservesLargeNumbers(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","input":[{"opaque":9007199254740993}]}`)
	out, _ := NormalizeResponsesBody(body)
	if !json.Valid(out) {
		t.Fatalf("normalized body must be valid JSON: %s", out)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(out, &m)
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(m["input"], &items); err != nil {
		t.Fatalf("input unmarshal: %v", err)
	}
	if string(items[0]["opaque"]) != "9007199254740993" {
		t.Fatalf("opaque = %s, want 9007199254740993", items[0]["opaque"])
	}
}

// TestNormalizeResponsesBodyInvalidInput 验证非 JSON / 非对象输入原样返回。
func TestNormalizeResponsesBodyInvalidInput(t *testing.T) {
	for _, body := range []string{"", "not-json", `["array"]`, `"string"`} {
		out, modified := NormalizeResponsesBody([]byte(body))
		if modified != 0 || string(out) != body {
			t.Fatalf("body %q must pass through, got %q modified=%d", body, out, modified)
		}
	}
}
