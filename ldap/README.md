# LDAP 认证压力测试工具

## 功能

该工具用于对 LDAP 服务执行批量 Bind 认证压力测试。程序从配置文件读取 LDAP 地址、用户 DN 模板、固定密码和并发参数，从用户文件读取用户名列表，在指定时长内循环发起认证请求并统计成功率、失败率、TPS 和响应时间。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 工具源码 |
| `config.yaml` | Linux/通用测试配置 |
| `config.yaml-windows` | Windows 环境示例配置 |
| `data.csv` | 用户名列表 |
| `data-windows.csv` | Windows 环境用户名列表示例 |

## 配置说明

`config.yaml` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `ldap.address` | LDAP 服务地址，例如 `ldap://host:389` |
| `ldap.bind_dn` | 管理账号 DN，当前代码未直接使用 |
| `ldap.password` | 认证密码，所有测试用户共用 |
| `ldap.base_dn` | Base DN，当前代码未直接搜索使用 |
| `ldap.user_filter` | 用户过滤器，当前代码未直接搜索使用 |
| `ldap.user_dn_template` | 用户 DN 模板，必须包含一个 `%s` 用于填入用户名 |
| `stress_test.concurrent_users` | 并发 worker 数 |
| `stress_test.duration_seconds` | 压测持续时间，单位秒 |
| `stress_test.user_data_file` | 用户名文件路径 |

## 输入文件格式

用户数据文件每行一个用户名，不需要表头：

```text
u00_000000
u00_000001
```

程序会用 `user_dn_template` 拼出完整用户 DN，再使用 `ldap.password` 执行 Bind。

## 使用方法

在当前目录运行：

```bash
go run .
```

如需编译：

```bash
go build -o ldap-stress-test .
./ldap-stress-test
```

## 输出结果

程序结束后会输出测试时长、总请求数、成功数、失败数、成功率、失败率、TPS、平均响应时间、最小响应时间、最大响应时间和错误详情。

## 注意事项

- 必须在 `ldap` 目录内运行，程序会从当前目录读取 `config.yaml`。
- 当前代码不会先用 `bind_dn` 搜索用户，而是直接按 `user_dn_template` 拼接用户 DN 后 Bind。
- 如果不同用户密码不同，需要调整代码或生成对应的认证逻辑。
- 压测前建议确认账号锁定策略，避免大量失败认证触发锁定。
