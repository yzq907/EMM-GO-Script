# ARMS 直连协议压测工具

该工具从压力机直接连接 ARMS TCP 端口，模拟完整应用交易，验证以下链路：

```text
压力机 -> ARMS -> Kafka -> ssa-dataAI -> Doris -> 后台页面
```

程序只读取当前目录的 `config.json`，不接受命令行压测参数。这样可以在执行前审核配置，并将每轮配置和结果一起归档。

## 交易口径

一笔交易包含四个连续的 ARMS 协议帧：

1. 交易元数据帧。
2. HTTP 请求帧。
3. HTTP 响应帧。
4. 交易完成帧（`cmd=99`）。ARMS 收到该帧后才解析并上报 Kafka。

四个帧使用相同的 UUID。`target_tps=25000` 表示每秒发送 25000 笔交易，即约 100000 个 ARMS 帧。正常交易首先写入 `gateway_all_log`，并由 ARMS 生成分钟聚合数据。

## 编译

```bash
cd /root/go/src/arms-load-generator
go test -race ./...
go build -trimpath -o arms-load-generator .
```

## 启动

先检查 `config.json`，然后运行：

```bash
cd /root/go/src/arms-load-generator
./arms-load-generator
```

按 `Ctrl+C` 可以停止。程序会停止发放新交易，等待当前写操作结束，刷新 `results.csv`，然后输出汇总结果。

## 主要配置

| 字段 | 含义 |
| --- | --- |
| `host` | ARMS TCP 地址，当前为 `10.10.27.219:8104` |
| `threads` | 并发虚拟用户数，每个线程维护一条 TCP 长连接 |
| `duration` | 压测持续时间，例如 `1m`、`10m`、`1h` |
| `target_tps` | 所有线程合计交易 TPS；`0` 表示全速发送 |
| `ramp_up` | 从 0 线性升到目标 TPS 的时间；`0s` 表示立即升压 |
| `connect_timeout` | TCP 建连超时 |
| `write_timeout` | 单次写入超时 |
| `heartbeat_interval` | 空闲连接心跳间隔 |
| `stats_interval` | 终端和 CSV 统计间隔 |
| `results_file` | 统计结果 CSV 文件 |
| `app_name` | 写入交易数据的应用包名，必须使用平台已经注册的应用 |
| `server_id` | 写入交易元数据的服务编号 |
| `request_*` | 模拟 HTTP 请求内容 |
| `response_*` | 模拟 HTTP 响应内容 |
| `response_body_size` | 模拟响应 body 总字节数；`0` 表示直接使用 `response_body` |
| `response_chunk_size` | 单个 `63/03` 响应帧 body 分片字节数；`0` 表示不拆分，建议大流量使用 `32768` |

`threads` 与 TPS 不是同一个指标。建议范围如下：

| 目标 TPS | 建议 threads |
| ---: | ---: |
| 5000 | 32 |
| 10000 | 32-64 |
| 25000 | 64-128 |
| 30000 | 128-256 |

程序允许 `1-25000` 个线程。超过 20000 时会警告，因为当前压力机到单一目标端口可用的临时源端口约为 28232 个。

## 冒烟测试

第一次接入 ARMS 时先将配置改为：

```json
"threads": 4,
"duration": "1m",
"target_tps": 100,
"ramp_up": "5s"
```

运行后检查：

- ARMS 无协议解析错误。
- Kafka 正常交易消息增速约为 200 条/秒。
- Kafka consumer lag 没有持续增长。
- ssa-dataAI 日志没有批量写入错误。
- Doris 和后台页面能查到配置的已注册应用包名数据。

## 正式压测顺序

冒烟测试通过后依次测试 `5000`、`10000`、`15000`、`20000`、`25000` 和 `30000 TPS`。每个阶段先运行 10 分钟并观察 ARMS、Kafka、ssa-dataAI 和 Doris；稳定性测试应在确认 Kafka 没有持续积压后再执行。

发送成功只表示三个帧已经写入 ARMS TCP 连接，不表示数据已经落入 Doris。端到端结果必须同时核对 Kafka 生产速率、consumer lag、ssa-dataAI 消费速率、Doris 数据量和后台页面展示。

## 大流量响应模拟

真实应用的大响应会拆成多个 `63/03` 响应帧上报。需要模拟大流量时，可以配置每笔交易的响应 body 大小和分片大小，例如每笔约 600KB：

```json
"response_body": "ARMS load test success",
"response_body_size": 614400,
"response_chunk_size": 32768
```

此时每笔交易会发送一个元数据帧、一个请求帧、多个 `63/03` 响应帧和一个完成帧。`response_body_size=0`、`response_chunk_size=0` 时保持原有行为，只发送一个小响应帧。

## 结果文件

`results.csv` 每个统计周期写一行，不记录逐交易明细。主要字段包括目标 TPS、实际 TPS、累计成功/失败交易、帧数、字节数、活动连接、重连、调度积压和错误分类。

如 `scheduler_backlog` 持续增长或实际 TPS 长期低于目标值，说明压力机、网络或者 ARMS 已经无法跟上配置速率，需要结合资源监控判断瓶颈。
