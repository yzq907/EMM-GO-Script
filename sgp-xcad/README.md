# SGP-XCAD KDC 认证压力测试工具

## 功能

该工具用于对 Kerberos KDC 执行批量密码认证压力测试。程序读取 `config.yaml` 和用户列表文件，按指定总请求数和并发数循环执行 AS 登录认证，并统计成功率、失败数、响应时间和 TPS。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `sgp-xcad.go` | 工具源码 |
| `config.yaml` | KDC 和压测配置 |
| `users.dat` | 用户名列表 |
| `xcad-test` | 已编译的可执行文件 |
| `config.yaml-*`、`users.dat-*` | 不同环境的备份配置和用户数据 |

## 配置说明

`config.yaml` 字段如下：

| 字段 | 说明 |
| --- | --- |
| `realm` | Kerberos Realm |
| `kdc` | KDC 域名配置字段，当前生成 krb5 配置时主要使用 `kdc_ip` |
| `admin_server` | admin server 地址 |
| `kpasswd_server` | kpasswd server 地址，当前代码未直接使用 |
| `kdc_ip` | KDC IP，生成 krb5 配置时用于 `kdc = <kdc_ip>:88` |
| `timeout` | KDC 超时时间，默认 `5s` |
| `username` | 单用户字段，当前批量逻辑不直接使用 |
| `password` | 所有测试用户共用的认证密码 |
| `total_requests` | 总认证请求数，默认 `100` |
| `concurrency` | 并发数，默认 `20` |
| `user_file` | 用户列表文件，默认 `users.dat` |
| `max_retries` | Kerberos 配置中的最大重试次数，默认 `1` |
| `udp_preference_limit` | Kerberos 配置中的 UDP 偏好阈值，默认 `1` |

配置文件中还保留了 `keytab_path`、`cache_path`、`config_path`、`cache_timeout` 等字段，但当前代码未直接使用。

## 输入文件格式

`users.dat` 每行一个用户名，空行和以 `#` 开头的行会被忽略：

```text
u00_000000
u00_000001
```

## 使用方法

在当前目录运行：

```bash
go run sgp-xcad.go
```

或使用已编译二进制：

```bash
./xcad-test
```

如需重新编译：

```bash
go build -o xcad-test sgp-xcad.go
```

## 输出结果

程序结束后会输出总请求数、成功请求数、失败请求数、平均响应时间、最大响应时间、最小响应时间、总运行时间和 TPS。

## 注意事项

- 必须在 `sgp-xcad` 目录内运行，程序会从当前目录读取 `config.yaml` 和 `users.dat`。
- 当前所有用户共用 `config.yaml` 中的 `password`。
- 程序会在内存中动态生成 krb5 配置，不依赖系统 `/etc/krb5.conf`。
- 压测前建议确认 KDC 账号锁定策略，避免大量失败认证触发锁定。
