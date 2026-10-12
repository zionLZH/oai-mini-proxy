# oai-mini-proxy

Codex OAuth 订阅凭证的轻量中转服务。把 [sub2api](https://github.com/Wei-Shaw/sub2api) 中「Codex OAuth 转发 + 风控伪装」的核心内核剥离出来，做成一个**无数据库、无管理端**的单二进制：凭证与代理由调用方按请求传入，服务本身不存储任何账号配置。

[![CI](https://github.com/zionLZH/oai-mini-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zionLZH/oai-mini-proxy/actions/workflows/ci.yml)
[![Release](https://github.com/zionLZH/oai-mini-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/zionLZH/oai-mini-proxy/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/zionLZH/oai-mini-proxy/blob/main/LICENSE)

## 特性

- **凭证按请求传入**：调用方在每个请求里通过 `X-Credentials` 头传 `base64(凭证 JSON)`，服务端以 email 为键做本地缓存与自动刷新，调用方无需关心 `refresh_token` 轮换。
- **代理按请求传入**：`X-Proxy-URL` 头传代理（base64 或明文），支持 `http` / `https` / `socks5` / `socks5h`；`socks5://` 自动升级为 `socks5h://`（DNS 由代理端解析，避免泄漏）。无效代理**直接报错，绝不静默回退直连**。
- **风控伪装**：Codex 官方身份头收口（originator / UA / version 同源自洽）、引擎指纹兜底、uTLS TLS 指纹（直连 / HTTP CONNECT / SOCKS5 三种链路）。
- **自动刷新**：缓存优先（`refresh_token` 轮换链的最新态）→ 临近过期自动刷新 → 回写缓存 → 上游 401 时强制刷新并重试一次。刷新在 email 维度 single-flight 锁内执行，并发请求不会各自刷新。
- **SSE 流式透传**：上游分块到达即 Flush，无额外缓冲延迟。
- **请求体自动归一化**：通用 OpenAI 客户端（不发 `store` 字段等）的请求会自动补齐为 ChatGPT 内网 Codex 端点的合法形态；已是合法形态的请求逐字节原样透传。
- **纯透传、零协议互转**：只转发 Responses API 语义的请求，不提供 `/v1/chat/completions` 兼容层。

## 快速开始

### 方式一：下载预编译二进制

到 [Releases](https://github.com/zionLZH/oai-mini-proxy/releases/latest) 下载对应平台产物（linux / darwin 为 `.tar.gz`，windows 为 `.zip`；含 `checksums.txt` 校验）：

```bash
tar -xzf oai-mini-proxy_*_linux_amd64.tar.gz
chmod +x oai-mini-proxy
./oai-mini-proxy
```

### 方式二：源码编译

要求 Go 1.24+：

```bash
git clone https://github.com/zionLZH/oai-mini-proxy.git
cd oai-mini-proxy
go build -o oai-mini-proxy .
./oai-mini-proxy
```

交叉编译（与 Release CI 一致，5 个平台）：

```bash
# 以 linux/amd64 为例，替换 GOOS/GOARCH 即可编译其它平台
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o oai-mini-proxy .
```

| GOOS | GOARCH | 产物 |
|---|---|---|
| linux | amd64 / arm64 | `oai-mini-proxy_<版本>_linux_<架构>.tar.gz` |
| darwin | amd64 / arm64 | `oai-mini-proxy_<版本>_darwin_<架构>.tar.gz` |
| windows | amd64 | `oai-mini-proxy_<版本>_windows_amd64.zip` |

启动后默认监听 `:8317`：

```
[oai-mini-proxy] listening on :8317
[oai-mini-proxy] upstream: https://chatgpt.com/backend-api/codex (Host: chatgpt.com)
[oai-mini-proxy] tls fingerprint: true | credential cache: ./data/credentials | refresh skew: 5m0s
```

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OAI_MINI_PROXY_ADDR` | `:8317` | HTTP 监听地址 |
| `OAI_MINI_PROXY_CACHE_DIR` | `./data/credentials` | 凭证缓存目录 |
| `OAI_MINI_PROXY_UPSTREAM_BASE` | `https://chatgpt.com/backend-api/codex` | 上游 base |
| `OAI_MINI_PROXY_UPSTREAM_HOST` | `chatgpt.com` | 上游 `Host` 头（OAuth 透传必须为 `chatgpt.com`） |
| `OAI_MINI_PROXY_CODEX_VERSION` | `0.146.0` | 出站声明的 Codex 客户端版本（决定 UA 与 version 头，需跟随官方 CLI 版本） |
| `OAI_MINI_PROXY_CODEX_USER_AGENT` | 空 | 完整出站 UA 覆写；为空时按版本拼接规范 TUI UA |
| `OAI_MINI_PROXY_TLS_FINGERPRINT` | `true` | 是否启用 uTLS TLS 指纹 |
| `OAI_MINI_PROXY_REFRESH_SKEW` | `5m` | access_token 到期前多久视为需要刷新 |
| `OAI_MINI_PROXY_RESPONSE_HEADER_TIMEOUT` | `300s` | 等待上游响应头的超时（SSE 长流只约束首包） |
| `OAI_MINI_PROXY_DIAL_TIMEOUT` | `10s` | TCP 拨号 / TLS 握手 / 代理 CONNECT 超时 |
| `OAI_MINI_PROXY_MAX_BODY_BYTES` | `67108864`（64 MiB） | 入站请求体大小上限 |
| `OAI_MINI_PROXY_DEBUG` | `false` | 打开详细日志 |

## HTTP 接口

### 请求头

| 头 | 必需 | 说明 |
|---|---|---|
| `X-Credentials` | 是 | `base64(凭证 JSON)`，标准/URL base64、带不带 padding 均可 |
| `X-Proxy-URL` | 否 | 代理 URL，base64 或明文；缺省 = 直连 |
| `Authorization` | 否 | 兼容通道：`Bearer <base64(凭证 JSON)>`（方便只支持单一 API Key 字段的客户端） |

#### 凭证 JSON 形态

`access_token` 必需；强烈建议同时提供 `refresh_token`（否则 token 过期后无法自动刷新）和 `email`（缓存键，缺失时自动回退到 JWT claims / `chatgpt_account_id` / token 指纹）。支持三种形态：

```jsonc
// 1. 扁平形态
{"access_token": "...", "refresh_token": "...", "email": "you@example.com"}

// 2. sub2api 账号 credentials 嵌套形态
{"credentials": {"access_token": "...", "refresh_token": "...", "email": "you@example.com"}}

// 3. Codex CLI auth.json 形态
{"tokens": {"access_token": "...", "refresh_token": "...", "account_id": "..."}}
```

### 路由

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/responses`、`/v1/responses/*` | Responses API 转发（SSE 流式）；`/compact`、`/input_tokens` 等子路径按后缀透传 |
| `POST` | `/backend-api/codex/responses`、`/backend-api/codex/responses/*` | 同上（Codex CLI `chatgpt_base_url` 模式） |
| `GET` | `/v1/models`、`/models`、`/backend-api/codex/models` | 模型清单；支持 `client_version` 协商与 `ETag`/`If-None-Match` 304 续期 |
| `GET` | `/healthz` | 健康检查 |

> 不支持 `/v1/chat/completions`（本项目不做协议互转）。

### curl 示例

```bash
# 准备凭证与代理（CRED 必须是单行 base64）
CRED=$(base64 < credential.json | tr -d '\n')
PROXY=$(printf '%s' 'socks5://user:pass@127.0.0.1:1080' | base64)   # 可选

# 查询模型列表
curl http://127.0.0.1:8317/v1/models \
  -H "X-Credentials: $CRED" \
  -H "X-Proxy-URL: $PROXY"

# 发起一次流式对话（模型名以 /v1/models 返回为准）
curl -N http://127.0.0.1:8317/v1/responses \
  -H "X-Credentials: $CRED" \
  -H "X-Proxy-URL: $PROXY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5.5","stream":true,"input":"hello"}'
```

### 客户端接入（以 Cherry Studio 为例）

在支持自定义请求头的 OpenAI 兼容客户端中：

1. API 地址：`http://127.0.0.1:8317/v1`（模型列表会自动请求 `/v1/models`）
2. API 密钥：任意非空占位值（如 `1`；凭证走自定义头）
3. 自定义请求头：
   - `X-Credentials: <base64 凭证>`
   - `X-Proxy-URL: <代理地址>`（可选）
4. 模型 ID 填 `/v1/models` 返回列表中的模型名

请求体是否带 `store` / `stream` 字段无需操心，服务端会自动归一化。

### 错误响应

统一格式：

```json
{"error": {"type": "oai_mini_proxy_<code>", "message": "..."}}
```

| type | HTTP | 场景 |
|---|---|---|
| `oai_mini_proxy_invalid_credentials` | 401 | `X-Credentials` 缺失或非法 |
| `oai_mini_proxy_invalid_proxy` | 400 | `X-Proxy-URL` 非法 |
| `oai_mini_proxy_body_too_large` | 413 | 请求体超过上限 |
| `oai_mini_proxy_credential_error` | 401 / 502 | 无 `refresh_token` 可刷新（401）或刷新失败（502） |
| `oai_mini_proxy_upstream_request_failed` | 502 | 上游连接失败（超时、代理不可达等） |
| `oai_mini_proxy_upstream_read_failed` | 502 | 读取上游响应失败 |

## 工作原理

```
客户端 ── X-Credentials / X-Proxy-URL ──▶ oai-mini-proxy ── uTLS 指纹 + 身份头收口 ──▶ chatgpt.com/backend-api/codex
                                              │
                                              ├─ 凭证缓存：./data/credentials/<hash>.json（0600 权限，原子写）
                                              └─ 上游 401 → 强制刷新 → 重试一次
```

凭证处理流程：

1. 解码 `X-Credentials`，以 email（回退链）计算缓存键；
2. 缓存命中且未过期 → 直接使用（快路径，`refresh_token` 轮换链的最新态）；
3. 未命中或临近过期 → 在单飞锁内合并缓存与传入凭证，执行刷新并回写；
4. 上游返回 401 → 强制刷新一次并重试；刷新失败则原样回放上游 401。

刷新响应中的 token 轮换会完整落盘，**调用方持有的原始凭证无需更新**——即使原 `refresh_token` 已被上游撤销，只要缓存链仍然有效，请求就能持续成功。

## 注意事项

- **同一账号请只使用一份缓存目录**：`refresh_token` 轮换是单链的，多实例/多机共享同一账号时如各自维护缓存会造成轮换链分叉，导致凭证失效。让所有请求指向同一个服务实例或同一份 `CACHE_DIR`（共享存储）。
- **不要暴露到公网**：服务本身**无鉴权**，任何能访问它的人都能使用你传入的凭证额度。仅限本机或内网使用。
- **缓存即凭证**：`data/credentials/*.json` 保存着 access/refresh token，请妥善保护（目录 0700、文件 0600），不要提交到 Git（仓库已自带 `.gitignore` 排除）。
- **模型名以上游为准**：`/v1/models` 返回的内容随订阅与上游发布变化，示例中的模型名仅作演示。

## 开发

```bash
go vet ./...
go test ./...            # 全部用例
go test -race ./...      # 竞态检测
gofmt -l .               # 格式检查
```

CI（GitHub Actions）：

- **CI**：push / PR 到 `main` 时执行 gofmt + vet + `go test -race`；
- **Release**：推送 `v*` tag 时交叉编译 5 平台产物、生成 `checksums.txt` 并自动创建 GitHub Release。

发布新版本：

```bash
git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0
```

## License

[MIT](LICENSE)
