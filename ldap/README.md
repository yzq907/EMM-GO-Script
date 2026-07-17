# LDAP 认证压力测试工具

## 功能

该工具用于对 LDAP 服务执行批量认证、认证后查询、认证后查询并写入的压力测试。程序从配置文件读取 LDAP 地址、用户 DN 模板、查询/写入参数和并发参数，从用户文件读取用户名列表，在指定时长内循环执行场景并统计成功率、失败率、TPS 和响应时间。

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
| `ldap.bind_dn` | 管理账号 DN；写入场景未配置 `admin_bind_dn` 时使用该值 |
| `ldap.password` | 普通用户认证密码；写入场景未配置 `admin_password` 时也作为管理员密码 |
| `ldap.admin_bind_dn` | 管理员 DN，用于 `bind_search_modify` 场景的绑定 |
| `ldap.admin_password` | 管理员密码，用于 `bind_search_modify` 场景的绑定 |
| `ldap.base_dn` | Base DN，当前代码未直接搜索使用 |
| `ldap.user_filter` | 用户过滤器，当前代码未直接搜索使用 |
| `ldap.user_dn_template` | 用户 DN 模板，必须包含一个 `%s` 用于填入用户名 |
| `ldap.search_base_template` | 查询 Base DN 模板，必须包含一个 `%s` 用于填入用户名 |
| `ldap.search_filter_template` | 查询过滤器模板，必须包含一个 `%s` 用于填入用户名 |
| `ldap.search_attributes` | 查询返回属性列表 |
| `ldap.search_scope` | 查询范围：`0` 当前对象，`1` 单层，`2` 子树 |
| `ldap.search_count_limit` | 查询返回数量限制 |
| `ldap.modify_attribute` | 写入属性，默认 `description` |
| `ldap.modify_operation` | 写入操作：`replace`、`add`、`delete` |
| `ldap.modify_value_template` | 写入值模板，默认 `go-write-%s-%d`，分别填入用户名和毫秒时间戳 |
| `ldap.verify_modify` | 写入后是否再次查询并验证写入值 |
| `ldap.connection_timeout_seconds` | LDAP 建连超时时间 |
| `ldap.operation_timeout_seconds` | LDAP 操作超时时间 |
| `stress_test.concurrent_users` | 并发 worker 数 |
| `stress_test.duration_seconds` | 压测持续时间，单位秒 |
| `stress_test.user_data_file` | 用户名文件路径 |
| `stress_test.scenario` | 测试场景：`bind`、`search`、`modify`、`bind_search`、`bind_search_modify`、`mixed` |
| `stress_test.read_concurrent_users` | `mixed` 场景读 worker 数，默认继承 `concurrent_users` |
| `stress_test.write_concurrent_users` | `mixed` 场景写 worker 数，只控制并发消费能力，不会乘以写入速率，默认 `1` |
| `stress_test.write_schedule` | `mixed` 写入调度策略：`ratio` 或 `rate`，默认 `ratio` |
| `stress_test.write_interval_requests` | `ratio` 策略下每多少次读请求触发一次写请求，默认 `1000` |
| `stress_test.write_rate_per_second` | `rate` 策略下全局每秒写入次数，默认 `1` |

## 场景说明

`stress_test.scenario` 支持六种模式。LDAP 查询和修改操作本身都需要先绑定账号，独立 `search`/`modify` 模式会使用管理员账号绑定，但统计目标只对应查询或修改场景。

```yaml
scenario: "bind"
```

只执行用户 Bind。程序使用 `user_dn_template` 拼出用户 DN，并使用 `ldap.password` 认证。

```yaml
scenario: "search"
```

使用管理员账号绑定，然后按 `search_base_template`、`search_filter_template` 查询当前用户。适合单独压测查询能力。

```yaml
scenario: "modify"
```

使用管理员账号绑定，然后直接写入 `modify_attribute`。适合单独压测写入能力。该模式不会先查询用户，也不会做写后验证。

```yaml
scenario: "bind_search"
```

先执行用户 Bind，成功后使用 `search_base_template`、`search_filter_template` 查询当前用户。

```yaml
scenario: "bind_search_modify"
```

使用管理员账号绑定，查询当前用户，写入 `modify_attribute`，然后在 `verify_modify: true` 时再次查询并确认写入值。该模式适合普通用户没有修改权限、需要管理员执行写入的场景。

```yaml
scenario: "mixed"
read_concurrent_users: 50
write_concurrent_users: 1
write_schedule: "ratio"
write_interval_requests: 1000
```

混合真实业务负载。读 worker 持续执行 `bind_search`，写 worker 执行 `modify`。`write_interval_requests: 1000` 表示每发送 1000 次读请求触发 1 次写请求，适合读写比例约 `1000:1` 的 LDAP/AD 场景。输出会分别展示读场景、写场景和合计指标。

如果希望读压测期间持续有稳定写入压力，可以使用定速写入：

```yaml
scenario: "mixed"
read_concurrent_users: 50
write_concurrent_users: 5
write_schedule: "rate"
write_rate_per_second: 5
```

`write_rate_per_second` 是全局写入速率，不会乘以 `write_concurrent_users`。上面的配置表示总共约每秒 5 次写入，5 个写 worker 只是并发处理这些写任务，避免单个写请求变慢时堆积。

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
- `bind` 和 `bind_search` 场景直接按 `user_dn_template` 拼接用户 DN 后 Bind。
- `search`、`modify`、`bind_search_modify`、`mixed` 中的写 worker 默认使用 `admin_bind_dn`/`admin_password` 绑定，未配置时回退到 `bind_dn`/`password`。
- 如果不同用户密码不同，需要调整代码或生成对应的认证逻辑。
- 压测前建议确认账号锁定策略，避免大量失败认证触发锁定。
- 写入压测会修改 LDAP 用户属性，建议只在测试 OU 或测试账号上执行。
