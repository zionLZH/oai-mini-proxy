// 本文件把 responses 请求体合法化为 ChatGPT 内部 Codex 端点可接受的形态。
//
// 语义对齐 sub2api 的 applyCodexOAuthTransform（OAuth 分支）与
// ensureCodexReasoningInclude：通用 OpenAI 客户端（Cherry Studio 等）构造的
// 请求缺少内网端点要求的字段时会被上游拒绝（典型报错 "Store must be set to
// false"），这里做最小必要的补齐与剥离；真实 Codex CLI 请求已是合法形态，
// 归一化计数为 0，保持逐字节原样透传。
package codex

import (
	"bytes"
	"encoding/json"
)

// codexOAuthUnsupportedFields 是 ChatGPT 内部 Codex 端点不接受的请求体字段，
// 转发前统一剥离（对齐 sub2api openAICodexOAuthUnsupportedFields）。
var codexOAuthUnsupportedFields = []string{
	"max_output_tokens",
	"max_completion_tokens",
	"temperature",
	"top_p",
	"frequency_penalty",
	"presence_penalty",
	"chat_template_kwargs",
	"user",
	"metadata",
	"prompt_cache_retention",
	"safety_identifier",
	"stream_options",
	"truncation",
	"stop_sequences",
}

const reasoningEncryptedContentInclude = "reasoning.encrypted_content"

// NormalizeResponsesBody 归一化 responses 请求体：
//   - store 必须为 false（缺失 / true / 非布尔都强制为 false，否则上游返回
//     "Store must be set to false"）；
//   - stream 必须为 true（ChatGPT 内网 Codex 端点仅接受流式请求）；
//   - 剥离内网端点不支持的字段（temperature、max_output_tokens 等）；
//   - prompt 迁移为 input（内网不认 prompt 字段）；
//   - 剥离 Codex CLI 私有 commands 字段；
//   - 带 reasoning 时补齐 include:["reasoning.encrypted_content"]，与真实
//     Codex 请求形态对齐（已有该值时不动；include 为非预期类型时保持原样）。
//
// 返回修改后的 body 与修改计数；计数为 0 时返回原始字节（请求已是合法形态，
// 未做任何改动）。JSON 解析失败或非对象时同样原样返回，由上游给出权威错误。
// 顶层的修改经 RawMessage 完成，嵌套值（含大整数）不会被重新编码破坏精度；
// 仅在确有修改时才重新序列化，此时顶层字段顺序可能变化（JSON 语义不变）。
func NormalizeResponsesBody(body []byte) ([]byte, int) {
	if len(body) == 0 {
		return body, 0
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return body, 0
	}

	modified := 0

	if !isJSONBool(raw["store"], false) {
		raw["store"] = json.RawMessage("false")
		modified++
	}
	if !isJSONBool(raw["stream"], true) {
		raw["stream"] = json.RawMessage("true")
		modified++
	}

	for _, key := range codexOAuthUnsupportedFields {
		if _, ok := raw[key]; ok {
			delete(raw, key)
			modified++
		}
	}

	// prompt → input（仅当 input 缺失或为 null），随后删除 prompt。
	if prompt, ok := raw["prompt"]; ok {
		if input, hasInput := raw["input"]; !hasInput || isJSONNull(input) {
			if !isJSONNull(prompt) {
				raw["input"] = prompt
			}
		}
		delete(raw, "prompt")
		modified++
	}

	if _, ok := raw["commands"]; ok {
		delete(raw, "commands")
		modified++
	}

	if ensureReasoningInclude(raw) {
		modified++
	}

	if modified == 0 {
		return body, 0
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return body, 0
	}
	return out, modified
}

// ensureReasoningInclude 在请求带非空 reasoning 对象且 include 中缺少
// reasoning.encrypted_content 时补齐；返回是否做了修改。
func ensureReasoningInclude(raw map[string]json.RawMessage) bool {
	reasoning, ok := raw["reasoning"]
	if !ok || !isNonEmptyJSONObject(reasoning) {
		return false
	}

	includeRaw, hasInclude := raw["include"]
	if !hasInclude {
		raw["include"] = json.RawMessage(`["` + reasoningEncryptedContentInclude + `"]`)
		return true
	}

	// 用 RawMessage 解析数组元素，任何类型的元素都逐字节保真。
	var include []json.RawMessage
	if err := json.Unmarshal(includeRaw, &include); err != nil {
		// include 非数组（非预期类型）：保持原样，不破坏调用方意图。
		return false
	}
	wanted := json.RawMessage(`"` + reasoningEncryptedContentInclude + `"`)
	for _, item := range include {
		if bytes.Equal(bytes.TrimSpace(item), wanted) {
			return false
		}
	}
	include = append(include, wanted)
	encoded, err := json.Marshal(include)
	if err != nil {
		return false
	}
	raw["include"] = encoded
	return true
}

// isJSONBool 判断原始值是否为指定布尔值（缺失、非布尔、其它布尔均返回 false）。
func isJSONBool(raw json.RawMessage, want bool) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false
	}
	return b == want
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func isNonEmptyJSONObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && len(m) > 0
}
