# CPU 负载控制工具

## 功能

该工具用于在本机制造指定比例的 CPU 负载。程序会按 CPU 核数启动相同数量的 goroutine，每个 goroutine 按配置的百分比循环忙等和休眠，用于模拟测试环境中的 CPU 压力。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.json` | CPU 负载配置 |
| `cpu_load_controlle-arm64` | 已编译的 ARM64 可执行文件 |

## 配置说明

`config.json` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `cpu_percent` | 每个 CPU 核心目标负载百分比，例如 `30` 表示约 30% |

## 使用方法

在当前目录运行：

```bash
go run .
```

或使用已编译二进制：

```bash
./cpu_load_controlle-arm64
```

如需重新编译：

```bash
go build -o cpu_load_controlle-arm64 .
```

## 停止方法

该程序会一直运行，需要手动停止：

```bash
Ctrl+C
```

或通过 `kill` 结束进程。

## 注意事项

- 必须在 `cpu_load_controlle` 目录内运行，程序会从当前目录读取 `config.json`。
- `cpu_percent` 是每核目标负载，不是全机总负载。
- 建议先从较低比例开始，避免影响同机其他测试进程。
