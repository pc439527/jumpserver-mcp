---
name: jumpserver
description: 通过 JumpServer 堡垒机对内网资产执行运维命令、采集结构化主机清单与拓扑、运行 Runbook 与基线漂移对比。当用户提到堡垒机、JumpServer、内网服务器、资产巡检、批量执行命令、查看某台服务器的磁盘/内存/端口/进程、对比多台主机差异时使用。
---

# JumpServer 堡垒机

所有远端操作都经 JumpServer 的 SSH 网关（KoKo）转发，并在本机留全量审计。

## 前置条件

会话是一个显式状态机，`jumpserver_exec` 只在最后一个状态可用：

```
DISCONNECTED  --connect-->  JUMPSERVER_MENU  --enter(target)-->  ASSET_SHELL
     ^                            |                                  |
     +-------- close -------------+------------ leave --------------+
```

`COMMAND_RUNNING` 是执行期间的过渡态，另有 `UNKNOWN` / `ERROR` 两种异常态——遇到后者先 `jumpserver_status` 看当前状态再决定动作。

不必手动逐级推进——`jumpserver_run` / `jumpserver_inspect` / `jumpserver_batch` 会自动连接、切换目标、校验后再执行。只有需要连续手敲多条命令时，才先 `connect` + `enter`。

执行前可用 `jumpserver_status` 查看：是否已连接、当前在哪台资产、权限模式、控制台 URL 与令牌有效期。

## 权限模式（由 config.json 的 permissionMode 决定，用户控制）

| 模式 | 行为 |
|---|---|
| `READ_ONLY`（默认） | 只自动执行纯只读命令；写操作被拒绝 |
| `AUTO` | 只读与低风险写操作自动执行 |
| `FULL_ACCESS` | 不再逐条拦截，仍记录审计 |

命令按风险分级：`READ` / `PRIVILEGED_READ` / `UNKNOWN` / `MODIFY` / `DANGEROUS`。无法安全解析的复合语法一律判为 `UNKNOWN` 并拦截——**优先用单条简单命令，不要用 `;`、`&&`、管道套娃去绕**。

## 工具速查

### 会话
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_connect` | 无 | 建立 SSH 会话并等待菜单出现；已连接则直接返回当前状态 |
| `jumpserver_close` | 无 | 释放 PTY、通道与定时器，回到 DISCONNECTED |
| `jumpserver_status` | 无 | 当前状态、目标资产、权限模式、控制台 URL |

### 资产
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_assets` | `filter?` `group?` `refresh?` `includeRawText?` | 列出账号有权访问的资产，**不进入**任何一台 |
| `jumpserver_enter` | `target` `accountIndex?` | 通过菜单进入指定资产；`accountIndex` 用于 KoKo 多用户选择屏（详见下方）。内部跑探针校验后才报告成功 |
| `jumpserver_leave` | 无 | 退出当前资产，回到菜单 |

> **多用户选择屏（V0.5.3）**：当某台资产在堡垒机上绑定了多个用户账号（例如 admin/ops/root），KoKo 不会直接进入资产 shell，而是先打印一份编号列表 + `ID>` 提示符等调用方挑一个。连接器看到这种屏幕会按下面处理：
>
> - 调用方传了 `accountIndex: N`（**就是 KoKo 屏上显示的编号**，通常是 1 或 2，不是数组下标）：连接器自动写入 `N` 然后等 shell。
> - 调用方没传：连接器抛 `ACCOUNT_SELECTION_REQUIRED` 错误，`detail` 字段里附 `accounts=0:admin \| 1:ops \| 2:deploy` 这样的解析结果；模型据此问用户后再用对的 `accountIndex` 重试。
> - **重试就在同一个会话上做，不要重连（V0.5.6）**：抛 `ACCOUNT_SELECTION_REQUIRED` 之后会话**仍然活着并停在那块 `ID>` 屏上**（状态 `ENTERING_ASSET`）。紧接着把 `accountIndex` 传给 `jumpserver_enter` / `jumpserver_run` / `jumpserver_batch` / `jumpserver_job_start` 再调一次即可 —— 连接器把编号写进**已经打开的那块屏**：同一条 SSH 链路、不重发资产行、**不需要先 `connect`**。
>   - 那块屏已经不在了（KoKo 选择超时、链路断掉）时才抛 `ACCOUNT_SELECTION_EXPIRED`，这时才重连后重新 `enter`。
>   - `accountIndex` 不在列表里同样是 `ACCOUNT_SELECTION_REQUIRED`（`detail` 带 `requested accountIndex=N`），屏还在，直接用合法编号重试。
>   - ⚠️ 若看到 `CONNECTION_LOST` + `no live JumpServer session`：那是 ≤ V0.5.5 的旧行为（抛错时把会话打成 `UNKNOWN`，导致"带账号重试"被拒），已修复。别再把它理解成"会话掉了"而去重连。
> - 连接器**永不自动选** —— fail-closed，避免误登。
>
> 多目标的批量工具（`jumpserver_batch` 每个 task、`jumpserver_inspect/topology/compare/baseline_*/profile_run` 全局）用 `accountByTarget: { "<ip>": <index> }` 这个 map 来分别指定；`jumpserver_job_start` 单点直接传 `accountIndex`。

> **资产网络不通 = 立刻停（V0.5.5）**：堡垒机连不上目标资产时 KoKo 会打印 `开始连接到 root(root)@<ip> error: 网络不通（连接超时）` 然后退回自己的菜单提示符。这时连接器抛 `ASSET_UNREACHABLE`，`detail` 里是**完整那句 KoKo 横幅**（不是匹配到的关键词）和 `retryAfterMs`。
>
> - **不要重试、不要继续排查**：这不是配置/账号/`accountIndex` 问题，重试只会再等 KoKo 自己的 ~15 秒拨号超时。工具结果里会带 `next: STOP` 一行，照做：直接告诉用户「该服务器暂时无法联通」，然后换目标或等用户确认网络恢复。
> - 会话本身是好的：状态回到 `JUMPSERVER_MENU`，换一台资产**不需要重连**。
> - 同一台资产在 2 分钟内会被**直接拒绝（不写 PTY）**；已确认网络已修复时，`jumpserver_close` 会清掉这个冷却。
> - 非网络的失败（例如 `资产不存在`）仍是 `ASSET_ENTER_TIMEOUT`，可以正常重试/换参数。

### 执行
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_exec` | `command` `timeout?` `confirm?` | 在当前已进入的资产上跑**一条**简单命令 |
| `jumpserver_run` | `target` `command` `timeout?` `confirm?` `accountIndex?` | 指定目标跑一条命令，自动处理连接与切换；`accountIndex` 同上 |
| `jumpserver_batch` | `tasks` `confirm?`（每个 task 含 `target` `commands` `accountIndex?` `timeout?`） | 多目标批量执行；每台进入一次、跑完该台所有命令再切走 |

### 结构化采集（优先用这些，而不是堆 `exec`）
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_inspect` | `targets` `profile?` `group?` `format?` `concurrency?` `accountByTarget?` | 用固定只读探针采集结构化主机画像 |
| `jumpserver_topology` | `targets?` `group?` `profiles?` `depth?` `format?` `concurrency?` `accountByTarget?` | 主机间关系图（谁连谁、哪个端口、证据来自哪） |
| `jumpserver_profile_run` | `runbook` `targets?` `group?` `format?` `concurrency?` `accountByTarget?` | 跑 config 里定义的命名 Runbook，带断言 |
| `jumpserver_compare` | `targets` `command?` `profile?` `stripPrefixes?` `format?` `concurrency?` `accountByTarget?` | 多台主机跑同一命令，只报**差异** |

`inspect` 的 profile：`basic` / `network` / `process` / `service` / `web` / `java` / `database` / `container` / `full`。
命令由连接器决定，**不要自己拼 shell**——这是固定探针，不是自由文本入口。

### 基线
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_baseline_capture` | `name` `targets` `group?` `profile?` `overwrite?` | 保存命名基线快照 |
| `jumpserver_baseline_compare` | `name` `profile?` `format?` | 与当前状态比对，报漂移 |

### 流式作业（给不会自己结束的命令用）
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_job_start` | `target` `command` `maxDuration?` `confirm?` | `tail -f` / `journalctl -f` / `tcpdump` / `top -b` 等 |
| `jumpserver_job_read` | `jobId` `sinceSeq?` `full?` `maxChars?` | 游标读，默认只返回上次之后的新输出 |
| `jumpserver_job_stop` | `jobId` | 发 Ctrl+C 结束作业 |
| `jumpserver_jobs` | 无 | 列出本对话的作业 |

### 观测与审计
| 工具 | 参数 | 用途 |
|---|---|---|
| `jumpserver_snapshot` | `sinceSeq?` `maxChars?` | 终端镜像：把 PTY 事件流读出来给用户看 |
| `jumpserver_audit` | `limit?` `filter?` | 本连接器的审计流水（命令已脱敏） |
| `jumpserver_interrupt` | 无 | 立即发 Ctrl+C，不等当前操作结束 |
| `jumpserver_console_rotate_token` | 无 | 换发控制台访问令牌（旧链接立即失效） |

## 标准工作流

**只问状态，别进机器**
`jumpserver_assets(filter="oa")` → 直接回答，不消耗会话。

**单台排查**
`jumpserver_inspect(targets=["oa-app-01"], profile="full")` → 拿到结构化事实。
缺具体细节时才补 `jumpserver_run(target="oa-app-01", command="df -h")`。

**多台对比**
`jumpserver_compare(targets=["oa-app-01","oa-app-02"], profile="network")` → 直接给差异。

**长期监控**
`jumpserver_baseline_capture(name="oa-baseline", group="OA")` 建档，之后 `jumpserver_baseline_compare(name="oa-baseline")` 看漂移。

**看日志**
`jumpserver_job_start(target="oa-app-01", command="journalctl -f -u nginx")` → 轮询 `jumpserver_job_read(jobId="...")` → 结束用 `jumpserver_job_stop`。

## 高风险操作规则

`exec` / `run` / `batch` / `job_start` 都带 `confirm` 参数。约定：

- **只有用户在对话里明确同意后才传 `confirm: true`**。绝不要自行推断同意。
- 工具返回 `confirmation required` 时，把命令原文和影响范围讲给用户，等回复。
- `DANGEROUS` 与 `UNKNOWN` 无论 `confirm` 为何都会被拦。
- 批量与写操作前，先用 `READ_ONLY` 口径的 `inspect` 确认目标是对的资产——打错 IP 的代价不可逆。

## 错误场景与恢复

| 现象 | 处理 |
|---|---|
| 启动即报连接信息不完整 | 用户尚未填 WorkBuddy 连接器表单；提示去连接器配置填地址/端口/账号/密码 |
| `HOST_KEY_MISMATCH` | 堡垒机主机密钥变了。可能是重装，也可能是中间人。**不要自动信任**，把新旧指纹给用户确认 |
| 会话超时/掉线 | 重新 `jumpserver_connect`；状态机会自愈 |
| 命令被判 `UNKNOWN` | 拆成单条简单命令，不要用 `;`、`&&`、命令替换 |
| 命令长时间不返回 | 用 `jumpserver_interrupt`，或改用 `job_start` + `job_read` |
| 控制台显示令牌已过期 | `jumpserver_console_rotate_token`，把新 URL 给用户 |
| 目标资产进不去 | 用 `jumpserver_assets` 确认账号确实有该资产权限 |

## 呈现给用户

- 控制台 URL 出现在工具结果里时，按其中的提示调用 `present_files` 打开（WorkBuddy 内置预览面板）。
- `jumpserver_snapshot` 的输出适合渲染成终端视图，而不是当纯文本贴出来。
- 报结论时带上证据来源：哪个 profile、哪条命令、哪台资产。
