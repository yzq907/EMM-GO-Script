# SPA-test-server HTTP QUIC/TLS 压测代理服务

## 功能

该工具现在作为 HTTP 服务启动，供 JMeter 调用。JMeter 负责并发、循环次数和参数化；本服务负责把 HTTP JSON 请求转换成后端 QUIC 认证和自定义 TLS 网关请求。

链路分为两步：

1. `POST /auth`：执行 QUIC SPA 认证，返回 `token_id`。
2. `POST /proxy`：接收 JMeter 传入的 `token_id` 和 `session_id`，执行 TLS ClientHello 自定义扩展 `15001`、TCP 初始化头和业务请求。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | HTTP 服务源码，包含 QUIC 认证和 TLS 代理逻辑 |
| `config.json` | 运行配置 |
| `config.example.json` | 配置示例 |
| `main_test.go` | 单元测试 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `listen_addr` | HTTP 服务监听地址，例如 `:8080` |
| `quic_host` | QUIC 认证服务地址 |
| `quic_port` | QUIC 认证服务端口 |
| `tls_host` | TLS 网关地址 |
| `tls_port` | TLS 网关端口 |
| `tls_server_name` | TLS SNI / ServerName |
| `server_id` | TCP 初始化头中的 ServerID，默认 `9` |
| `app_name` | TCP 初始化头中的应用名，默认 `zjtXh9c5uOY8N7wa` |
| `local_port` | TCP 初始化头中的 LocalPort，默认 `9090` |
| `request_host` | TLS 隧道后的业务 Host |
| `request_port` | TLS 隧道后的业务端口 |
| `request_path` | TLS 隧道后的业务路径 |
| `request_method` | 业务请求方法，默认 `GET` |
| `request_headers` | 业务请求头；`Content-Length` 会按请求体自动计算 |
| `request_body` | 业务请求体 |
| `use_raw_request` | 为 `true` 时直接发送 `raw_request` |
| `raw_request` | 完整原始 HTTP 请求文本 |
| `log_file` | 日志文件路径，默认 `spa-test-server.log`；日志只写入文件，不输出到 stdout |
| `log_level` | 日志级别，可选 `error`、`warn`、`info`、`debug`，默认 `error` |
| `http_read_header_timeout_s` | HTTP 服务读取请求头超时，默认 `2` 秒 |
| `http_read_timeout_s` | HTTP 服务读取完整请求超时，默认 `5` 秒 |
| `http_write_timeout_s` | HTTP 服务写响应超时，默认 `15` 秒 |
| `http_idle_timeout_s` | HTTP keep-alive 空闲超时，默认 `60` 秒 |
| `max_auth_concurrency` | `/auth` 最大并发，默认 `1000` |
| `max_proxy_concurrency` | `/proxy` 最大并发，默认 `12000` |
| `tcp_connect_timeout_ms` | `/proxy` 连接 TLS 网关超时，默认 `2000` 毫秒 |
| `tcp_operation_timeout_ms` | `/proxy` TLS 握手、初始化头和业务请求读写超时，默认 `3000` 毫秒 |
| `quic_dial_timeout_ms` | `/auth` 连接 QUIC 服务超时，默认 `3000` 毫秒 |
| `quic_stream_timeout_ms` | `/auth` QUIC stream 读写超时，默认 `2000` 毫秒 |
| `return_upstream_body` | 是否在 `/proxy` JSON 响应里返回第三方业务 body；JMeter 断言第三方响应时配置为 `true` |
| `upstream_body_max_bytes` | 返回或调试记录第三方业务 body 时的最大字节数，默认 `4096`，最大 `1048576` |

业务请求默认由 `request_method/request_host/request_port/request_path/request_headers/request_body` 拼出。如果 `use_raw_request=true`，服务会跳过拼装，直接发送 `raw_request`。

日志只输出到 `log_file`，不会输出到 stdout。建议正式压测使用 `log_level=error`，只记录配置、服务和请求失败；排查请求结果时使用 `info`，会额外记录 `/auth`、`/proxy` 成功状态和耗时；深入排查链路时使用 `debug`，会额外记录 QUIC/TLS 处理阶段和第三方业务响应片段。日志不会记录密码或完整 token。日志使用有界异步队列，故障流量过大时不会阻塞请求线程；队列满会写入 `event=log_dropped count=N` 汇总记录。`debug` 日志量较大，不建议在正式压测时开启。

日志采用 `时间 级别 源码位置 消息 字段` 格式，例如：

```text
2026-07-17 09:40:51.709720      error   SPA-test-server/main.go:910          proxy request failed event=proxy_failed status=400 duration_ms=0
```

## 接口

### QUIC 认证

```http
POST /auth
Content-Type: application/json

{
  "username": "tester1",
  "devid": "d89f3a35931c386956c1a402a8e09941",
  "password": "your-real-password"
}
```

成功响应：

```json
{
  "success": true,
  "token_id": "base64-token-data",
  "duration_ms": 18,
  "error": ""
}
```

### TLS 代理请求

```http
POST /proxy
Content-Type: application/json

{
  "token_id": "base64-token-data",
  "session_id": "si:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

成功响应：

```json
{
  "success": true,
  "duration_ms": 12,
  "upstream_status": "HTTP/1.1 200 OK",
  "upstream_status_code": 200,
  "upstream_body": "business response body",
  "upstream_bytes": 22,
  "upstream_body_truncated": false,
  "error": ""
}
```

`upstream_*` 字段来自 TLS 隧道后的第三方业务响应。`upstream_bytes` 是实际返回给 JMeter 的 body 字节数；body 超过配置上限时，`upstream_body_truncated=true`。服务使用标准 HTTP 解析处理 `Content-Length` 和 Chunked 响应。失败响应会返回 `success=false` 和 `error` 字段；如果已经收到第三方业务响应，也会带上对应的 `upstream_*` 字段。参数错误返回 HTTP `400`，请求体超过 64 KiB 返回 HTTP `413`，后端 QUIC/TLS/业务请求失败返回 HTTP `502`。

业务断言由 JMeter 完成，服务端只负责转发并返回第三方业务响应。建议配置 `return_upstream_body=true`，这样 `/proxy` 会把第三方业务响应 body 放到 `upstream_body` 字段，JMeter 可以直接对 `$.upstream_body` 做断言。`upstream_body_max_bytes` 控制最多返回多少字节，如果第三方响应较大，需要把断言关键字放在这个范围内，或者调大该值，并检查 `$.upstream_body_truncated` 是否为 `false`。

## JMeter 使用建议

1. 使用 CSV Data Set Config 提供 `username`、`devid`、`session_id` 等参数。
2. 第一个 HTTP Request 调 `POST /auth`。
3. 用 JSON Extractor 提取 `$.token_id` 到变量，例如 `token_id`。
4. 第二个 HTTP Request 调 `POST /proxy`，请求体使用 `${token_id}` 和 `${session_id}`。

## 5000 TPS 压测建议

- 业务转发 TPS 建议主要压 `/proxy`；`/auth` 是 QUIC 认证链路，性能特征和业务转发不同。
- JMeter 做第三方业务断言时，保持 `return_upstream_body=true`；正式压测建议使用 `log_level=error`。
- 分析压测失败时查看 `spa-test-server.log`；截图中的 `读取响应头失败: deadline exceeded` 通常表示 QUIC 认证服务在 `quic_stream_timeout_ms` 内没有返回 SPA 响应头。
- 如果出现 HTTP `429`，说明达到了本服务配置的并发保护上限，可以根据机器资源调大 `max_proxy_concurrency`。
- 如果出现大量 `502`，优先检查网关、Redis session、目标业务服务和本机端口资源，而不是继续盲目增加 JMeter 线程。
- 当前 `/proxy` 每次请求都会新建一条到 TLS 网关的连接，这是为了真实压测网关业务转发链路；同一目标地址下，本机临时端口范围也会影响极限并发。
- JMeter 中止或客户端连接断开时，服务会立即取消对应的 TCP/QUIC 上游操作并释放并发槽。

## 使用方法

启动服务：

```bash
go run .
```

或使用已编译二进制：

```bash
./SPA-test-server
```

重新编译：

```bash
go build -o SPA-test-server .
```

查看帮助：

```bash
./SPA-test-server --help
```

## 注意事项

- TLS 和 QUIC 证书校验默认关闭，适合测试环境使用。
- 服务端不再内部控制压测并发，JMeter 是压测入口。
- `/proxy` 的 `token_id` 和 `session_id` 都必须由 JMeter 请求传入。
- `session_id` 受网关协议字段限制，最长为 40 字节；超长参数会直接返回 HTTP `400`，不会静默截断。
- `/auth` 的 `password` 必须由 JMeter 请求体传入，服务不会从配置文件读取密码。
- `/auth` 返回的 `token_id` 是对 `devid/timestamp/nonce/token` JSON 的 base64 编码，格式兼容原 TLS 测试逻辑。
- `/proxy` 的 TCP 初始化头使用 `server_id`、`app_name`、`local_port`，业务请求使用 `request_*` 或 `raw_request` 配置。
- 进程收到 SIGINT 或 SIGTERM 后会停止接收新连接，并等待在途 HTTP 请求完成后退出。
