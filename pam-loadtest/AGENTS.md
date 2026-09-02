# AGENTS.md

本文档是给后续接手本项目的 agent / Codex 使用的项目记忆和操作规范。目标是避免重复排查已经完成的问题，避免覆盖用户已有成果，并让后续工作从正确入口继续。

更新时间：2026-09-02

## 1. 项目定位

本项目是 `pam-loadtest`，用于 SGP-PAM 容量、稳定性和后续网络吞吐能力测试。

当前工具主要能力：

- 批量生成 PAM 测试资产计划。
- 批量导入 PAM 资产并生成 manifest。
- 启动分布式 agent。
- controller 按 manifest 分配资产，执行 SSH/RDP/VNC/Web/MySQL 等场景。
- 输出 JSON 报告、错误文件和 timeline。
- 支持标准 Linux 现场交付包。

当前稳定验证过的主要场景：

- `1000 SSH + 200 RDP` 混合场景。
- `ramp 1200s + hold 2h`。
- `ssh_activity_mode=keepalive`。
- SSH 1000 maintained=1000。
- RDP 200 maintained=200。
- 总会话 maintained=1200/1200。

## 2. 关键路径

本地工作区：

```text
D:\Documents\PAM测试
```

代码服务器：

```text
root@10.8.83.146:/root/go/src/pam-loadtest
```

控制端历史测试机：

```text
root@10.8.83.146
```

当前最终 Linux 标准交付包目录：

```text
D:\Documents\PAM测试\release\pam-loadtest-linux-package
```

当前最终 Linux 标准交付压缩包：

```text
D:\Documents\PAM测试\release\pam-loadtest-linux-package-20260902-final-20260902-113859.tar.gz
```

最终交付包 SHA256：

```text
E40EDA0B762B281B25BB858669A16BA182280BD8AB04F2E744CC62125CA99486
```

交付包主说明文档：

```text
D:\Documents\PAM测试\release\pam-loadtest-linux-package\SGP-PAM压测程序使用方案.md
D:\Documents\PAM测试\release\pam-loadtest-linux-package\SGP-PAM-loadtest-guide.md
```

冒烟测试证据：

```text
D:\Documents\PAM测试\release\smoke-evidence
```

## 3. 已完成事项，不要重复从零做

### 3.1 共享 PAM 登录态问题已处理

历史问题：

- agent 各自登录 PAM 时，曾出现 `400 登录密码加密信息无效`。
- 这不是简单并发量导致，因为 4 个 agent 登录量很小。

处理结论：

- 当前分布式 controller 会先登录 PAM。
- controller 向 agent 下发共享 PAM token/cookie。
- agent 不再各自重复走 PAM 登录。
- 该逻辑已在 `1000 SSH + 200 RDP` 2h 稳定性中验证通过。

后续不要重复把这个问题当作新问题从零排查。若再次出现 400，先确认当前执行的二进制是否是新版本、是否仍然使用共享认证链路。

### 3.2 SSH 30 分钟断开问题已处理

历史问题：

- 原始 SSH 活动模式在长时间 hold 中，SSH 会话约 30 分钟后被 PAM 空闲策略批量断开。

处理结论：

- `ssh_activity_mode=keepalive` 可以维持 SSH 会话越过 30 分钟、60 分钟和 2h。
- 当前混合稳定性测试默认使用 `keepalive`。

后续长稳场景优先使用：

```yaml
ssh_activity_interval: 5s
ssh_activity_mode: keepalive
```

不要再默认使用 `output` 作为 2h 稳定性验收口径，除非用户明确要求比较两种模式。

### 3.3 1000 SSH + 200 RDP 混合 2h 稳定性已通过

已通过正式场景：

```text
mixed-ssh1000-rdp200-keepalive-hold2h-20260901
```

关键配置：

```yaml
total: 1200
ramp: 1200s
hold: 2h
ssh_activity_interval: 5s
ssh_activity_mode: keepalive
graphical_activity_intervals:
  rdp: 2s
protocols:
  ssh: 1000
  rdp: 200
execution_modes:
  ssh:
    browser: 0
    direct: 1000
  rdp:
    browser: 0
    direct: 200
```

结果：

```text
controller_rc=0
status=completed
SSH maintained=1000
RDP maintained=200
total maintained=1200
```

本地报告：

```text
D:\Documents\PAM测试\docs\SGP-PAM容量稳定性测试结果-SSH1000-RDP200混合-2h-20260901.md
```

### 3.4 标准 Linux 交付包已生成

当前标准 Linux 包不包含 Go 源码，只包含：

- 可执行程序。
- 配置模板。
- 资产创建脚本。
- 后端模拟资产脚本。
- agent/controller 启停脚本。
- 冒烟测试脚本。
- 使用说明。

包内不应包含：

```text
cmd/
internal/
archive/
.git/
*.go
```

当前 `release` 目录只保留：

```text
pam-loadtest-linux-package
pam-loadtest-linux-package-20260902-final-20260902-113859.tar.gz
smoke-evidence
```

不要重新恢复旧的 release 压缩包。

### 3.5 标准包冒烟测试已通过

远端冒烟目录：

```text
root@10.8.83.146:/root/pam-loadtest-linux-package-smoke
```

成功冒烟：

```text
START_TIME=2026-09-02T10:40:47+08:00
END_TIME=2026-09-02T10:42:22+08:00
CONTROLLER_RC=0
status=completed
totals.maintained=2/2
ssh.maintained=1/1
rdp.maintained=1/1
```

证据：

```text
D:\Documents\PAM测试\release\smoke-evidence\smoke-ssh1-rdp1-20260902-104047.json
D:\Documents\PAM测试\release\smoke-evidence\smoke-ssh1-rdp1-20260902-104047.timeline.env
D:\Documents\PAM测试\release\smoke-evidence\smoke-ssh1-rdp1-20260902-104047.err
```

## 4. 已知问题，不要反复从零排查

### 4.1 RDP 高动态图形负载 Profile B 未通过

历史现象：

- 普通 Xorg RDP 200 场景可以通过。
- 高动态图形负载，例如类似持续刷新 `top`、监控看板、大面积变化画面，会使流量明显增加。
- 但 200 RDP 高动态图形负载下出现大量：

```text
guacamole inbound traffic inactive for 15s
```

判断：

- 不像 agent 主因。
- 不像后端资产全部异常。
- 更偏 PAM/guacd/RDP 下行链路在高动态图形压力下不稳定。

已有问题单：

```text
D:\Documents\PAM测试\docs\PAM-RDP动态画面负载问题单.md
```

后续不要把该问题当成 agent 启动失败或普通 RDP 场景失败来重复排查。若用户要求继续，优先围绕 PAM/guacd/RDP 下行链路和服务端日志收集证据。

### 4.2 PAM 慢 SQL 问题已整理

现象：

- `1000 SSH + 200 RDP` keepalive 2h 稳定性可以通过。
- 但 PAM 数据库出现大量慢 SQL。
- 慢 SQL 主要集中在 SSH keepalive 命令审计写入链路。

已有问题单：

```text
D:\Documents\PAM测试\docs\PAM-审计慢SQL问题单.md
```

判断：

- PAM 可能把 `ssh_activity_mode=keepalive` 发送的 `true` 命令作为命令审计持续写入 `tbl_sessioncommands`。
- 后续如果继续分析慢 SQL，应直接从问题单和慢 SQL 汇总结果继续，不要重新从日志搜索开始。

### 4.3 PAM/EMM license 403 超时属于服务侧依赖问题

标准包冒烟过程中曾出现：

```text
PAM POST /login returned 403
请求 EMM license 信息失败:
Post "http://10.19.88.148:7070/ztna-manager/global/licenceV1/getAppLicenseByPAM":
context deadline exceeded
```

连通性检查曾显示：

- controller 到 PAM 8088 TCP 可达。
- controller 到 EMM 7070 TCP 可达。
- PAM 主机到 EMM 7070 TCP 可达。

后续若再次出现该错误，优先判断为 PAM/EMM 服务侧 license 依赖超时，不要先改压测代码。

### 4.4 500Mbps 网络吞吐场景尚未完成

当前 `pam-loadtest` 主要验证会话容量和稳定性，不是精准吞吐发生器。

已有判断：

- SSH `output` 模式只是周期打印少量文本，不能代表 500Mbps。
- RDP 动态画面可以增加流量，但更像图形链路稳定性测试，不适合作为唯一网络吞吐验收。
- 500Mbps 应单独设计吞吐测试场景。

推荐后续方向：

- 优先实现或脚本化 SSH/SFTP 大文件下载吞吐场景。
- 用 `received_bytes / duration` 计算 Mbps。
- 报告中输出平均 Mbps、窗口 Mbps、p95 Mbps、是否达到 500Mbps。

## 5. 工作规范

### 5.1 先读代码和文档

开始新任务前优先阅读：

```text
AGENTS.md
docs\pam-loadtest代码阅读指南.md
release\pam-loadtest-linux-package\SGP-PAM压测程序使用方案.md
```

如果任务涉及具体问题单，先读对应问题单：

```text
docs\PAM-RDP动态画面负载问题单.md
docs\PAM-审计慢SQL问题单.md
docs\PAM-RDP并发上限问题单.md
```

### 5.2 不要覆盖用户已有变更

工作区可能存在用户或前序 agent 的变更。

要求：

- 不要执行 `git reset --hard`。
- 不要执行 `git checkout -- <file>` 来回滚用户文件。
- 不要删除不理解的测试证据。
- 清理文件前必须确认保留哪些最终结果。

### 5.3 测试必须记录时间线

每个正式场景至少记录：

```text
case_name
start_time
expected_ramp_end_time
expected_hold_end_time
end_time
controller_rc
result_json
stderr_file
timeline_file
agent_list
```

当前脚本会生成：

```text
runtime/results/<case>-<timestamp>.json
runtime/results/<case>-<timestamp>.err
runtime/results/<case>-<timestamp>.timeline.env
runtime/results/<case>-<timestamp>.pid
```

测试时必须关注 `.err` 是否为空，以及 PAM 侧是否出现：

```text
400
403
502
Bad Gateway
系统异常
record not found
error
```

### 5.4 成功判定要严格

容量/稳定性场景成功条件：

```text
controller_rc=0
status=completed
totals.planned == 目标总会话数
totals.maintained == 目标总会话数
各协议 maintained == 各协议目标数
totals.start_failures == 0
totals.runtime_failures == 0
totals.duplicates == 0
```

例如 `1000 SSH + 200 RDP`：

```text
totals.maintained=1200
protocols.ssh.maintained=1000
protocols.rdp.maintained=200
```

如果未满足，不要说测试通过。

### 5.5 用户要求停止时必须立刻停止并清理

如果用户说：

```text
停止测试
服务出现问题
清理环境
```

必须立即：

1. 停止 controller。
2. 取消 agent 当前 run。
3. 清理残留进程。
4. 保留已有结果和错误文件。
5. 告知用户当前停止状态。

不要继续等待测试自然结束。

## 6. 代码阅读入口

当前源码主目录：

```text
D:\Documents\PAM测试\internal
```

推荐阅读顺序：

1. `internal/config/config.go`：YAML 配置结构和校验。
2. `internal/app/runtime.go`：local/controller/agent 运行链路、目标构建、SSH 活动模式。
3. `internal/app/distributed.go`：controller 分发任务、共享 PAM token/cookie。
4. `internal/engine/runner.go`：按协议执行 direct/browser 会话。
5. `internal/protocol/guacamole.go`：RDP/VNC Guacamole direct 链路。
6. `internal/transport/websocket.go`：WebSocket 传输统计和 inactivity 判断。
7. `internal/runreport/report.go`：报告聚合和成功判定。
8. `internal/inventory/`：资产 plan/apply/verify 逻辑。

更详细说明：

```text
D:\Documents\PAM测试\docs\pam-loadtest代码阅读指南.md
```

## 7. 常用命令

### 7.1 本地构建

```bash
go test ./...
go build -o bin/pam-loadtest ./cmd/pam-loadtest
```

### 7.2 远端控制端常用路径

```bash
cd /root/go/src/pam-loadtest
```

### 7.3 标准包冒烟

```bash
cd /root/pam-loadtest-linux-package-smoke
scripts/00-check-env.sh
scripts/06-check-agent.sh
scripts/07-run-smoke.sh
```

### 7.4 标准包正式场景

```bash
cd /opt/pam-loadtest
bin/pam-loadtest validate configs/<scenario>.yaml
scripts/08-run-controller.sh configs/<scenario>.yaml
tail -f runtime/results/<scenario>-<timestamp>.err
```

## 8. 交付包规范

标准 Linux 交付包面向实施人员，不能包含源码。

交付包应包含：

```text
bin/pam-loadtest
configs/env.example
configs/*.yaml
scripts/*.sh
browser-worker/
docs/
README.md
SGP-PAM压测程序使用方案.md
SGP-PAM-loadtest-guide.md
```

打包后必须验证：

```powershell
tar -tzf <archive> | Select-String -Pattern '(^|/)cmd/|(^|/)internal/|(^|/)archive/|(^|/)\.git/|\.go$'
```

该命令应无输出。

交付包主说明文档必须讲清楚：

- 部署步骤。
- `.env` 修改项。
- PAM 资产创建。
- 后端模拟资产。
- agent 启动和检查。
- 冒烟测试。
- 任意正式场景如何修改 YAML。
- 结果如何判断。
- 常见问题排查。

## 9. 后续 500Mbps 吞吐任务入口

如果用户继续要求验证 `PAM 整体网络吞吐量 >= 500Mbps`，不要直接套用 `1000 SSH + 200 RDP` 稳定性结论。

推荐设计：

1. 先确认验收口径：
   - 是 PAM 总入口/出口吞吐，还是单协议吞吐。
   - 是上行、下行、双向还是总和。
   - 需要持续多久，例如 10 分钟或 30 分钟。
   - 统计位置是在 PAM 网卡、agent 侧报告，还是两者都要。

2. 推荐优先做 SSH/SFTP 大文件下载吞吐：
   - 后端准备 1GB 或更大的测试文件。
   - 多个 SSH/SFTP 会话通过 PAM 持续下载。
   - 统计总 received bytes 和测试窗口 Mbps。

3. 阶梯验证：

```text
20 并发下载，hold 5m
50 并发下载，hold 10m
100 并发下载，hold 10m
达到 500Mbps 后保持 30m
```

4. 成功标准示例：

```text
avg_mbps >= 500
p95_window_mbps >= 500
controller_rc=0
status=completed
runtime_failures=0
PAM 无 400/403/502/系统异常
```

5. 当前工具缺口：
   - 需要新增专门吞吐模式，或者先用外部脚本通过 PAM 通道做 SFTP 下载。
   - 不要把 SSH `output` 或 RDP 高动态图形负载当作精准 500Mbps 吞吐发生器。

## 10. 给后续 agent 的提醒

- 用户希望中文沟通。
- 用户重视“不要重复已完成工作”。
- 用户重视测试时间线记录。
- 用户会明确要求停止测试；看到停止要求要优先停止和清理。
- 代码服务器只保留最新代码，不要堆历史目录。
- Windows 本地可以保留测试报告和证据。
- 交付给客户的包要面向不懂代码的实施人员，步骤必须可复制、只改变量即可。
- 做出结论前必须有最新验证证据。
