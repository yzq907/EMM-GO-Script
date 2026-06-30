# TLS-Test 自定义 TLS 扩展压测工具

## 功能

该工具用于测试带自定义 TLS ClientHello 扩展的 EMM 网关链路。程序从 `session_id.csv` 读取会话 ID，从 `token_client.csv` 读取 token，在 TLS 握手阶段通过自定义扩展 `15001` 携带 token，随后发送 TCP 初始化头和固定业务请求，统计成功率和 TPS。

适用场景：

- 验证需要 token 扩展的 TLS 接入流程。
- 对 EMM 网关 TCP 隧道做持续并发压测。
- 配合 `quic-client` 生成的 `token_client.csv` 做后续链路测试。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.json` | 运行配置 |
| `session_id.csv` | 会话 ID 数据，必须包含 `session_id` 列 |
| `token_client.csv` | token 数据，必须包含 `token_id` 列 |
| `TLS-test` | 已编译的可执行文件 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `host` | 目标网关地址，必填 |
| `port` | 目标网关端口，必填 |
| `client_count` | 并发客户端数，默认 `1` |
| `run_duration_s` | 持续运行时间，单位秒，默认 `1` |

## 输入文件格式

`session_id.csv` 示例：

```csv
session_id
si:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

`token_client.csv` 示例：

```csv
token_id
base64-token-data
```

## 使用方法

在当前目录运行：

```bash
go run .
```

或使用已编译二进制：

```bash
./TLS-test
```

如需重新编译：

```bash
go build -o TLS-test .
```

## 输出结果

程序结束后会输出实际运行时间、成功次数、失败次数、成功率和 TPS。

## 注意事项

- 必须在 `TLS-Test` 目录内运行，程序会从当前目录读取 `config.json`、`session_id.csv` 和 `token_client.csv`。
- 业务请求在代码中固定为 `GET /hello`，Host 固定为 `10.10.27.97:9090`。
- TLS 证书校验默认关闭，适合测试环境使用。
- `token_client.csv` 可以由 `quic-client` 认证成功后生成，再按需复制到本目录。
