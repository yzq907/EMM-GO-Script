# QUIC 认证压测工具

## 功能

该工具用于通过 QUIC 连接发送 SPA 认证请求，读取服务端返回的 `timestamp`、`nonce`、`token`，将 token 信息编码后追加写入 `token_client.csv`。它可以用于批量生成后续 TLS 隧道测试需要的 token，也可以用于 QUIC 认证接口压测。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.json` | 运行配置 |
| `userinfo.csv` | 用户和设备数据，必须包含 `username`、`devid` 列 |
| `token_client.csv` | 认证成功后追加生成的 token 文件 |
| `quic-test` | 已编译的可执行文件 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `host` | QUIC 服务地址，必填 |
| `port` | QUIC 服务端口，必填 |
| `client_count` | 并发客户端数，默认 `1` |
| `run_duration_s` | 持续运行时间，单位秒，默认 `1` |
| `auth_password` | 认证请求中的密码字段，必填 |

当前示例配置里使用了 `run_duration_ms`，但代码实际读取字段是 `run_duration_s`。如需调整运行时长，请使用 `run_duration_s`。

## 输入文件格式

`userinfo.csv` 示例：

```csv
username,devid
tester1,replace-with-device-id
```

## 使用方法

在当前目录运行：

```bash
go run .
```

或使用已编译二进制：

```bash
./quic-test
```

如需重新编译：

```bash
go build -o quic-test .
```

## 输出结果

程序结束后会输出实际运行时间、成功次数、失败次数、成功率和 TPS。认证成功时，会向 `token_client.csv` 追加一行 `token_id` 数据。

## 注意事项

- 必须在 `quic-client` 目录内运行，程序会从当前目录读取 `config.json` 和 `userinfo.csv`。
- `token_client.csv` 会追加写入，多次运行前如需重新生成，请先备份或清空旧文件。
- 请求体中的包名、认证类型和版本当前写在代码中；密码通过 `config.json` 的 `auth_password` 配置。
- TLS 证书校验默认关闭，适合测试环境使用。
