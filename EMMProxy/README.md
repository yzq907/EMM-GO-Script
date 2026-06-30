# EMMProxy 隧道转发压测工具

## 功能

该工具用于测试 EMM 安全网关 TCP/TLS 隧道转发链路。程序会读取 `session_id.csv`，按配置并发建立 TLS 连接，发送 160 字节 TCP 初始化头，然后通过隧道发起 HTTP 业务请求，并统计成功率和 TPS。

适用场景：

- 验证 EMM 代理隧道是否可用。
- 对网关转发到后端 HTTP 服务的链路做并发压测。
- 可选生成 JMeter JTL 格式结果文件，便于后续分析。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.json` | 运行配置 |
| `session_id.csv` | 会话 ID 数据，必须包含 `session_id` 列 |
| `test_results.jtl` | 未禁用 JTL 时生成的测试结果文件 |
| `Emm-test` | 已编译的可执行文件 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `host` | EMM 网关地址，必填 |
| `port` | EMM 网关端口，必填 |
| `client_count` | 并发 worker 数，默认 `1` |
| `run_duration_s` | 持续运行时间，单位秒，默认 `1` |
| `server_id` | TCP 初始化头中的 ServerID，默认 `8400` |
| `app_name` | TCP 初始化头中的应用名 |
| `request_host` | 隧道后端业务 Host |
| `request_port` | 隧道后端业务端口 |
| `request_path` | 隧道后端业务路径 |
| `disable_jtl` | 是否禁用 JTL 文件写入，`true` 表示禁用 |
| `pool_size` | 连接池配置字段，当前代码仅设置默认值 |

## 输入文件格式

`session_id.csv` 示例：

```csv
session_id
si:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## 使用方法

在当前目录运行：

```bash
go run .
```

或使用已编译二进制：

```bash
./Emm-test
```

如需重新编译：

```bash
go build -o Emm-test .
```

## 输出结果

程序结束后会输出实际运行时间、成功次数、失败次数、成功率、成功 TPS 和总 TPS。未禁用 JTL 时，会额外生成 `test_results.jtl`。

## 注意事项

- 必须在 `EMMProxy` 目录内运行，程序会从当前目录读取 `config.json` 和 `session_id.csv`。
- TLS 证书校验默认关闭，适合测试环境使用。
- `session_id.csv` 可包含 BOM，程序会自动处理表头中的 BOM。
- 当前业务请求由 `request_host`、`request_port`、`request_path` 拼出 GET 请求。
