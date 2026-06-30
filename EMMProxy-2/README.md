# EMMProxy-2 国密 TLS 下载测试工具

## 功能

该工具用于测试 EMM 安全网关国密 TLS 隧道下的文件下载链路。程序读取 `session_id.csv`，并发建立国密 TLS 连接，发送 TCP 初始化头，然后通过隧道发送配置中的 HTTP 下载请求。下载数据可只统计到内存，也可保存到磁盘。

适用场景：

- 国密 TLS 网关连通性验证。
- 通过 EMM 隧道下载文件的功能测试。
- 按固定次数执行下载请求，统计成功率和 TPS。
- 验证 `200` 和 `206` 分片响应的下载完整性。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.json` | 运行配置 |
| `session_id.csv` | 会话 ID 数据，必须包含 `session_id` 列 |
| `download_test.log` | 示例日志文件 |
| `EMMProxy-download-file` | 已编译的可执行文件 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `host` | EMM 网关地址，必填 |
| `port` | EMM 网关端口，必填 |
| `client_count` | 并发 worker 数，默认 `1` |
| `run_count` | 每轮总任务倍数，实际总任务数为 `client_count * run_count` |
| `timeout_s` | 下载读取超时时间，单位秒，默认 `60` |
| `server_id` | TCP 初始化头中的 ServerID，默认 `8400` |
| `app_name` | TCP 初始化头中的应用名 |
| `http_request` | 单个 HTTP 请求模板 |
| `http_requests` | 多个 HTTP 请求模板数组；配置后会轮询发送 |
| `test_mode` | 下载模式，`memory` 只统计字节，`disk` 写入磁盘 |
| `save_path` | `disk` 模式下的文件保存目录，默认 `./downloads` |
| `log_file_path` | 详细日志文件路径 |

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
./EMMProxy-download-file
```

如需重新编译：

```bash
go build -o EMMProxy-download-file .
```

## 输出结果

程序结束后会输出总运行次数、实际运行时间、成功次数、失败次数、成功率和 TPS。配置了 `log_file_path` 时，会记录连接、握手、响应头、下载字节数和错误详情。

## 注意事项

- 必须在 `EMMProxy-2` 目录内运行，程序会从当前目录读取 `config.json` 和 `session_id.csv`。
- `test_mode` 使用 `disk` 时会真实写文件，压测前请确认 `save_path` 所在磁盘空间充足。
- HTTP 请求模板需要包含完整的请求行、Host 头和结尾空行。
- 国密 TLS 证书校验默认关闭，适合测试环境使用。
