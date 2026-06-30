# EMM 持续下载压测工具

## 功能

该工具用于对指定下载地址持续发起 HTTP/HTTPS 下载请求。与 `emm-download` 的单批并发下载不同，本工具会在配置的持续时间内让每个 worker 循环下载，可用于观察长时间下载链路的稳定性、吞吐和失败率。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.json` | 运行配置 |
| `download.log` | 配置了 `log_file` 后生成的运行日志 |
| `emm-download-arm64` | 已编译的 ARM64 可执行文件 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `download_url` | 下载地址，必填 |
| `cookie` | 请求携带的 Cookie，必填 |
| `concurrency` | 并发 worker 数，默认 `5` |
| `duration` | 持续运行时间，单位秒，默认 `60` |
| `interval` | 每个 worker 两次下载之间的间隔，单位秒，默认 `0` |
| `max_idle_conns` | HTTP 连接池最大空闲连接数，默认 `200` |
| `request_timeout` | 单次请求超时时间，单位秒，默认 `1800` |
| `connect_timeout` | 建立连接超时时间，单位秒，默认 `60` |
| `log_file` | 日志文件路径，留空则只输出到终端 |
| `log_level` | 日志级别，`DEBUG` 会输出更多连接和内存信息 |

## 使用方法

在当前目录运行：

```bash
go run .
```

或使用已编译二进制：

```bash
./emm-download-arm64
```

如需重新编译：

```bash
go build -o emm-download-arm64 .
```

## 输出结果

程序结束后会打印下载统计报告，包括实际完成的下载任务数、成功数、失败数、成功率、累计下载数据和总耗时。

## 注意事项

- 必须在 `emm-download-2` 目录内运行，程序会从当前目录读取 `config.json`。
- HTTPS 请求默认跳过证书校验，适合测试环境使用。
- 到达 `duration` 后，程序会等待当前正在执行的下载结束再退出。
- 响应体只用于统计字节数，不会保存到磁盘。
