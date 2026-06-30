# Redis 测试数据工具

## 功能

该工具用于向 Redis 写入指定规模的测试 Hash 数据，并支持检查和清理测试 key。可用于 Redis 容量、内存占用、连接模式和批量清理能力测试。

支持模式：

- `standalone`：单实例 Redis。
- `cluster`：Redis Cluster，会遍历 master 节点统计和清理。
- `sentinel`：配置字段已保留，但当前代码按普通 `redis.Client` 连接 `addr`。

## 文件说明

```
redis-test/
├── config.yaml    # 配置文件
├── main.go        # 主程序
├── go.mod         # Go 模块文件
├── redis-tool-arm64 # 已编译 ARM64 可执行文件
└── README.md      # 使用文档
```

## 配置说明

```yaml
redis:
  addr: "127.0.0.1:6379"
  password: ""
  db: 15
  mode: "standalone"

app:
  target_bytes: 2147483648
  estimated_per_key: 2000
  key_prefix: "test:fill:"
  batch_size: 100
  concurrent: 4
```

| 参数 | 说明 | 示例值 |
|------|------|--------|
| `redis.addr` | Redis 服务地址 | 127.0.0.1:6379 |
| `redis.password` | Redis 密码，空字符串表示无密码 | "" |
| `redis.db` | Redis 数据库编号 | 15 |
| `redis.mode` | 连接模式：`standalone`、`cluster`、`sentinel` | standalone |
| `app.target_bytes` | 写入数据的目标大小（字节） | 2147483648 (2GB) |
| `app.estimated_per_key` | 每条 Hash 数据的预估大小 | 2000 |
| `app.key_prefix` | 测试数据的 key 前缀 | test:fill: |
| `app.batch_size` | 批量清理时的批大小配置，当前写入逻辑未直接使用 | 100 |
| `app.concurrent` | 写入并发数 | 4 |

## 快速开始

### 1. 检查 DB 状态

```bash
go run . check
```

或使用已编译二进制：

```bash
./redis-tool-arm64 check
```

### 2. 写入测试数据

```bash
go run . write
```

工具会先检查目标 DB 或测试 key 前缀，避免重复写入覆盖已有数据。

### 3. 清理测试数据

```bash
go run . clean
```

只会删除以 `app.key_prefix` 开头的 key。

## 完整操作流程

```bash
go run . check
go run . clean
go run . write
go run . clean
```

## 重新编译

```bash
go build -o redis-tool-arm64 .
```

## 注意事项

- 必须在 `redis-test` 目录内运行，程序会从当前目录读取 `config.yaml`。
- 写入前建议先执行 `check`，确认不会误向已有业务库写入数据。
- `clean` 仅按 `key_prefix` 删除测试 key，请确保不同测试任务使用不同前缀。
- `target_bytes` 是估算值，实际 Redis 内存占用会受编码、过期策略、集群槽位和 Redis 版本影响。
