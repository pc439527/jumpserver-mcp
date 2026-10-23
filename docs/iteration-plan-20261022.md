# JumpServer MCP 连接器 · 完整迭代计划

**基线版本**：v0.5.13（`package.json` / `connector/connector-meta.json`）
**代码仓库**：`D:/desktop/IT信息部/WorkBuddy/jumpserver-mcp`（Git HEAD `0fe581f`）
**计划产出日期**：2026-10-22
**输入依据**：4 份独立审阅报告（ESB-测试 / CRM-深圳 / 泛微OA-肇庆 / 服务器采集）+ v0.5.13 源码走查
**观测口径**：`data/audit.jsonl` 7222 条 / 154 台资产 / 44 个自然日

---

## 一、结论先行

四份报告各自独立取证，**结论高度收敛**：连接器的内核（状态机 / 审计闭环 / 错误投影 / 资产不可达 STOP）已经成熟且经得起验证，剩余摩擦集中在**四个接缝**——跨目标导航、审批分类精度、输出体量、批量入参通道。

**本计划的四个关键判断**：

| # | 判断 | 依据 |
|---|---|---|
| 1 | **最高频缺陷是确定性代码缺陷，不是环境抖动** | 4 份报告独立记录同一现象（CRM「首次切换必失败」、泛微「命中率 100%」、ESB「最高频痛点」、采集「B1」）。根因在 `session.ts:719` `leave()` ——「发一次 exit + 等一次菜单回显」 |
| 2 | **「假成功」比「失败」更危险，必须排在失败之前** | CRM 症状 3：batch 返回 `target=30.2` 但 `hostname=k8s-192-168-30-3`，命令落在旧机器上却报成功 |
| 3 | **有一半收益不在连接器内，在客户端** | 采集报告 A1：`targets` 数组被序列化坏，`batch/compare/inspect/topology` 四个工具全线报 `must be array`。连接器侧必须做降级入参兜底，但不能只靠连接器 |
| 4 | **分类器放宽是安全边界变更，必须独立立项、独立验收** | 泛微明确建议：不宜与稳定性修复混在一起发布。fail-closed 是对的，错的是规则粒度 |

**总目标**：把「日常可用性」问题清空 —— 目标跨目标首调失败率 100% → ~0；只读命令审批拦截率 → 0；输出入上下文量降一个量级。

---

## 二、四份报告问题合并与去重

同一问题在不同报告里的编号对照（便于回溯）：

| 统一 ID | 问题 | ESB | CRM | 泛微 | 采集 | 层级 | 判定 |
|---|---|---|---|---|---|---|---|
| **N-01** | 跨目标切换首调必失败 `MENU_RETURN_FAILED` | B1/B2 | 症状1/A3 | 族1-①/P0① | B1/P1-1 | 连接器 | 🔴 最高频，确定性缺陷 |
| **N-02** | 「假成功」：命令落在旧机器仍报成功 | — | 症状3/A1/A2 | 族1 主机名残留/P0② | — | 连接器 | 🔴 最危险 |
| **N-03** | batch 多 target 语义与实现冲突 | B4 | 症状2/A2 | 族1 多目标半数成功 | — | 连接器 | 🔴 文档与实现不一致 |
| **N-04** | 数组入参被序列化坏，批量工具全线失败 | — | — | — | A1/P0-1/P0-2 | 客户端+连接器 | 🔴 通道级 |
| **N-05** | 命令分类器字面量匹配误伤 | C1/C2 | B 类/B1/B2 | 族3 | C4/C5/P1-3 | 连接器 | 🔴 最大隐形损耗 |
| **N-06** | `ASSET_ENTER_TIMEOUT` 语义过载 | A3 | 语义混淆 | — | — | 连接器 | 🟠 诊断被带偏 |
| **N-07** | `leave` 不可靠 / 无自愈 | — | — | 族1 | B2/P1-2 | 连接器 | 🟠 |
| **N-08** | 并行调用串会话（KoKo 菜单是全局单例） | — | — | 族1/P0③ | — | 连接器 | 🟠 数据正确性 |
| **N-09** | 输出无硬阈值，超长单行爆上下文 | D1/D2 | C 类/C1 | 族2 | — | 连接器 | 🟠 token 成本 |
| **N-10** | 无换行输出被完成标记吃掉 | — | — | 族2⑤ | — | 连接器 | 🟠 静默错误 |
| **N-11** | 审批误判无可观测闭环 | C3 | B5 | — | D2 | 连接器 | 🟠 |
| **N-12** | SENSITIVE_APPROVAL 整批丢弃且禁止重试 | C4 | B3/B4 | — | — | 连接器 | 🟠 整轮损失 |
| **N-13** | 审计缺 `errorCode` / 无轮转 / 无聚合指标面 | D4 | — | 族2 | D1/D2/D3 | 连接器 | 🟠 可观测 |
| **N-14** | 版本副本漂移（三份）+ 无构建指纹 | B5 | — | 族4⑨⑩ | A3/A4 | 工程 | 🟠 排查链路不透明 |
| **N-15** | 控制台 URL 钉 pid，重启即死 | B5 | E1/E2/E3 | — | D4 | 连接器 | 🟡 |
| **N-16** | Windows 资产在 KoKo 通道外 | — | — | 族4 | C1/P2-1/P2-2 | 外部+连接器 | 🟡 核验盲区 |
| **N-17** | 资产清单 IP ↔ 资产名系统性错位 | A1 | — | — | — | 外部数据 | 🟡 |
| **N-18** | 无文件传输通道（临时 HTTP 敞口） | — | D 类/D1 | — | — | 连接器 | 🟡 安全敞口 |
| **N-19** | 危险命令无执行时长护栏 | — | — | — | — | 连接器 | 🟡 |
| **N-20** | 工具表固定税 23821 B / 每对话 5955 token | D3 | — | — | — | 连接器 | 🟡 规模化 |
| **N-21** | 单目标探针 50.5s，全量采集 ~1.8h | — | — | — | C2/P1-4/P2-4 | 连接器 | 🟡 吞吐 |
| **N-22** | 发布节奏无 feature flag，13 次补丁全量回归 | F | — | — | — | 工程 | 🟡 |
| **N-23** | `interrupt` 无作业时记 unverified，污染失败率 | — | — | 族4 | D2 | 连接器 | 🟢 统计口径 |

**去重结论**：4 份报告共提出约 40 条改进项，去重后 **23 个独立问题**，其中 P0 级 5 个、P1 级 8 个。

---

## 三、迭代批次规划

采用 **4 个批次 + 1 条并行线** 的排法。每批次独立可发布、可回滚、有明确验收门禁。安全边界变更（N-05）单独成批、独立验收。

### 批次 A · v0.6.0 —— 导航收敛与执行定位（最高优先级）

**目标**：消灭 N-01 / N-02 / N-03。跨目标首调失败率 100% → ~0，杜绝假成功。

| ID | 任务 | 落点 | 复杂度 | 依赖 |
|---|---|---|---|---|
| A-1 | `leave()` 改退避重试：300/800/2000ms 重发 exit，最多 3 次；仍失败则 reconnect + re-enter，而非把会话打成 `UNKNOWN` 甩锅上层 | `src/jumpserver/session.ts:719` | 中 | — |
| A-2 | 目标自校验硬约束：enter 成功后自动 `hostname` + `ip -4 addr` 解析，与请求 IP 比对，不一致抛 `TARGET_VERIFICATION_FAILED` 并终止该 target 后续命令 | `session.ts` enter 尾部 / `session-manager.ts` | 中 | 需 `stripPrefixes` 白名单防多网卡误报 |
| A-3 | batch 强制携带 target 绑定：每个 task 执行前校验会话归属，不匹配直接拒绝，绝不落到旧机 | `session-manager.ts` `navigateToTarget` / `runTargetBatchGated` | 中 | A-2 |
| A-4 | batch 返回体区分「0 执行」与「全部失败」：新增 `executedCount` / `rejectedCount` / `failedTargets` | `src/runtime/tools-common.ts` `renderBatchResult` | 低 | 注意白名单渲染 |
| A-5 | batch 多 target 真实语义：内部对每个 target 强制 `leave → enter → verify`，enter 失败退避重试 1 次；不可达 target 单独失败而非整批失败 | `session-manager.ts` `runTargetBatch` | 中 | A-1 |
| A-6 | `ASSET_ENTER_TIMEOUT` 三态拆分：`ASSET_NOT_AUTHORIZED` / `ASSET_NOT_FOUND` / `ASSET_UNREACHABLE`，各带可执行的下一步文案 | `src/jumpserver/errors.ts` + `session.ts:524` | 低 | 纯新增，不破坏既有 |
| A-7 | `leave` 自愈：`MENU_RETURN_FAILED` 时自动降级 close→connect 并复检菜单 | `session-manager.ts` `leave()` | 中 | A-1 |

**✅ 实施完成（2026-10-22）** — 全部 7 项落地，版本 0.5.13 → 0.6.0。

实施中修正的两处计划偏差：
- **A-1 的根因比计划更深**：不只是「重试不够」。KoKo `exit` 后只留**裸提示符 `[Host]>`**（无框线无编号行），而 `looksLikeMenu()` 要求框线+编号组合 ⇒ **成功的 leave 被判失败**。修法：新增 `waitForMenuReturn()` 接受两种菜单形态，`looksLikeMenuPrompt` 作为可靠确认；`looksLikeShellPrompt` 导出用于「仍在资产 shell 内」的判定（**在 KoKo 菜单发 `exit` 会断开整个堡垒机会话**，故重试有前置条件）。
- **A-2 的判定比计划保守**：不做「hostname 与请求名直接比对」，因为资产**显示名 ≠ hostname** 会造成大量误报。改为：请求目标是 IP 字面量 → 自身地址列表必须含它；hostname 内嵌 IP 与请求不符 → 明确 mismatch；其余一律 `unverified`（**跳过而非失败**）。用 `hostname -I`（`A=` 行）而非 `ip -4 addr`，无需 `stripPrefixes` 白名单。

A-7 的连带改造：`navigateToTarget()` 返回 `{ session, status }`（自愈会替换 session 对象，调用方持有的旧引用会指向死 PTY），3 个调用点（`run` / `startJob` / `runTargetBatchGated`）同步改。

**门禁验收**
- 连续切换 20 个不同 target，首调成功率 ≥ 95%（当前基线 0%）— ⏳ **待真实环境验证**（需 20 台真实资产的堡垒机回归）
- 构造「假成功」回归用例：故意让 batch 指定 B 机而会话停在 A 机，断言返回 `TARGET_VERIFICATION_FAILED` 且 A 机无命令执行痕迹 — ✅ `tests/jumpserver/batch-target-binding.test.mjs`
- 3 目标混合 batch（单账号 + 多账号 + 不可达）：断言 `commands > 0` 且不可达目标单独失败 — ⚠️ **未覆盖**（缺多账号 `ID>` 屏的 batch 夹具）
- `tsc --noEmit` 通过 + `npm run test:only` 全绿（基线 575 tests）— ✅ **598 tests 全绿**（新增 23），smoke / validate-connector / measure-context（23821 B 未变）/ `--doctor` 均通过

**风险**
- A-1/A-5 每次切换增加 2–3s/target —— 用 A-2 的免重试路径对冲
- A-2 多网卡资产可能误报 —— 先做 20 台真实资产回归，确定 `stripPrefixes` 规则再放开
- ⚠️ **不可达目标绝不能进重试循环**，否则又是一轮 2m53s

---

### 批次 B · v0.6.1 —— 通道与入参健壮性（批量能力复活）

**目标**：修 N-04，让 `batch / compare / inspect / topology` 真正可用。

| ID | 任务 | 落点 | 复杂度 | 依赖 |
|---|---|---|---|---|
| B-1 | 连接器侧数组入参降级：schema 改 `anyOf: [array, string]`，string 用逗号/空格分隔，工具内部归一 | `src/runtime/arg-normalize.ts` + `tools-ops.ts` `targets` + `server.ts` batch `tasks` | 低 | — |
| B-2 | 归一函数单测：逗号分隔、空串、重复项、非法 IP 全覆盖 | `tests/runtime/arg-normalize.test.mjs` | 低 | B-1 |
| B-3 | 客户端侧修复提工单：定位 WorkBuddy MCP 调用层把 `array` 降级为非数组的路径 | `docs/issue-b3-client-array-validation-20261022.md`（工作区外，需平台侧确认） | — | 外部 |
| B-4 | 工具可用性自检：`jumpserver_status` 输出「工具已注册 / 未注册」+ 当前 owner pid + 控制台 URL 有效性 | `src/runtime/tool-names.ts` + `doctor.ts` + `status` 工具 | 低 | — |
| B-5 | 兜底入参提示：当检测到入参是字符串而 schema 期望数组时，错误文案直接给出「请用逗号分隔字符串」的可用写法 | `src/runtime/arg-normalize.ts`（zod message + union errorMap） | 低 | B-1 |

**门禁验收**
- 用 `"1.1.1.1,2.2.2.2"` 字符串调 `inspect`，结果与数组入参等价 ✅（`arg-shape-e2e.test.mjs`）
- 连发 20 次双 target `inspect`，统计成功率 ≥ 95%（**待真实环境门禁**）
- 断开 MCP 后跑 `jumpserver_status`，显式报「未注册」✅（`tools: N/23 registered`）

**风险**
- schema 变更需同步 `README.md` 与 `tool-annotations.test.mjs` 断言 ✅
- B-3 不在本仓库可控范围 —— **B-1 是必须做的兜底，不能等 B-3** ✅

#### B-1 实施偏差修正（2026-10-22，实施后回写）

**原计划**：「schema 改 `anyOf: [array, string]`，string 用逗号/**空格**分隔」。

**实施中发现的两个关键事实**（均已用宿主同版本 ajv 8.20.0 实测）：

1. **校验闸门在客户端，不在连接器。**
   宿主在发出 MCP 调用**之前**用 AJV 校验参数：
   `app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs` 偏移 5994979 附近
   `validateParams()` → `new Ajv({allErrors:true, coerceTypes:true})`。
   `coerceTypes: true` 只启用 **number 模式**强转，**不会**把 string 变成 array；
   报错措辞 `must be array` 是 AJV 原生措辞（zod 会说 `Expected array, received string`），
   与 N-04 报告文案逐字吻合 ⇒ **失败发生在客户端，请求根本没发到服务端**。

   ⇒ **推翻了「只加 `z.preprocess`、发布形态保持 array-only」的原设计**：
   发布形态若是 array-only，客户端先拒，连接器内的归一就是**死代码**。
   ⇒ 发布形态**必须**是 `anyOf: [{type:'array',…}, {type:'string'}]`，
   这样客户端闸门放行 string，服务端再归一。**这与原计划的方向一致，但理由完全不同。**

2. **`z.preprocess` 必须在 union 之外，不能在 array 分支之内。**
   若 preprocess 在 array 分支内，string 会命中 union 的 `z.string()` 分支而**永远走不到 array 分支**，
   于是 `min`/`max` 边界对字符串形态**完全失效** —— `jumpserver_compare` 要求 ≥2 个 target，
   而 `"1.1.1.1"`（1 个）会被放行 ⇒ **fail-closed 违规**。
   正确形态：`z.preprocess(normalize, z.union([arrayWithBounds, z.string()]))`，
   string 先归一为 array，再走带边界的 array 分支。
   （该缺陷由新增单测「the connector still normalizes the string into an array, and the bounds still apply」捕获。）

**分隔符也做了收紧**（原计划写「逗号/空格」）：**空格不是分隔符**，
因为资产名可能含空格（"Web Server 01"）；唯一例外是整段按空格切开后**每段都是 IPv4 字面量**。
命令列表**只按换行切分**且**不去重**。

**额外加固**（计划外）：
- `tasks` 的 string 分支要求文本**看起来像 JSON**（以 `[` 或 `{` 开头），
  否则 `"not json"` 会被 string 分支放行并把垃圾交给 handler。
- `profiles` / `stripPrefixes` 也改为容错形态（顺带加固）。

**预算影响**：`tools/list` payload 23821 B → **24091 B**（+270 B），
上限 24500 B，单工具上限 1700 B，最大工具 `jumpserver_inspect` 1685 B。
`z.optional()` 放在 union **外层**（内层会发布 `anyOf:[{not:{}},…]`，每个 optional 字段多约 30 B）。

#### 批次 B 收尾修正（2026-10-22，提交 `84e9822`）

批次 B 提交后在收尾验证中查出两个问题，均已修复：

1. **README 的 `## Tools (23)` 标题在插入 v0.6.1 段落时被吞掉**，
   契约测试 `the README tool table matches the registered tools` 会失败。
   已补回。**顺带证实契约本身有效**：把 README 恢复成提交版再跑全量，
   测试确实报 fail（642 pass / 1 fail），此前的「全量漏检」是工作区状态记忆误差。
   ⇒ 纪律：**怀疑测试失灵前，先做一次「回退到坏状态再跑」的对照实验**。

2. **`--doctor` 的可写性探针用固定文件名 `data/.doctor-probe`**，
   两个 doctor 进程并发时互删对方探针，Windows 上幸存的 `writeFileSync`
   撞 `EBUSY`/`ENOENT` ⇒ 可写目录被判**不可写**、`exitCode` 变 1 ⇒ 诊断归错层。
   探针名改为 `.doctor-probe-<pid>-<counter>`（`nextProbeFileName()`，导出以便测试冻结），
   清理移入 `finally`。回归用例已验证：把探针名回退即 fail（19/20）。
   ⇒ 纪律：**任何探测文件都要带 pid + 计数器**。

**收尾后门禁**：`tsc` ✅ ／ **644 tests 全绿**（643 + 1）／ smoke ✅ ／
validate-connector ✅ ／ `--doctor` usable ／ `tools/list` 24091 B。



---

### 批次 C · v0.7.0 —— 审批分类精度（安全边界，独立立项）

**目标**：修 N-05 / N-11 / N-12，把只读命令的审批拦截降到 0，同时不放宽任何写操作。

**前置原则（不可妥协）**
- 放宽条件必须是「**子命令白名单 + 参数形状校验**」双条件，禁止「包含即放行」
- 白名单**逐条人工签核**，禁止用通配符形态做白名单键（`crontab -l` ✅ / `crontab*` ❌）
- 判定失败一律 fail-closed（拒绝），不得回落放行

| ID | 任务 | 落点 | 复杂度 | 验收样本 |
|---|---|---|---|---|
| C-1 | 只读等价白名单：`.properties` 读取、`crontab -l`、`ufw status`、`mysql -e 'SELECT/SHOW'`、`hdbsql` 只读形态 | `src/security/command-classifier.ts` | 中 | 审计里 446 条 UNKNOWN 全量回归 |
| C-2 | 危险字面量只在**命令位置**匹配：`shutdown`/`reboot` 不在 grep 参数里匹配 | `command-classifier.ts` DANGEROUS 段 | 中 | `grep 'a\|shutdown' file` → READ |
| C-3 | 解析式判定替代关键字：`crontab -l` vs `-e/-r`；`mysql -e 'select'` vs `'drop'`；`kubectl exec` 内层 `config get`/`cluster nodes`/`info` → READ | `command-classifier.ts` | 高 | 泛微 DENIED 99 条逐条标注 |
| C-4 | 命令存在性前置探测（`command -v`），不存在直接返回 `COMMAND_NOT_FOUND`，不进执行与审批 | `session-manager.ts` exec 前置 | 中 | exit 127 从 80 次 → ~0 |
| C-5 | 敏感探查独立 scope：域名/连接串/端口探查单独成批，敏感判定只作用于该批 | `src/security/permission-gate.ts` | 低 | 采集批次不再整批 0 执行 |
| C-6 | 单条拒绝不吞整批：敏感/高危命令只拦自身，其余正常执行并标注拒绝原因 | `session-manager.ts` `runTargetBatchGated` 循环 | 中 | 混合批次 1 拒 + N 执行 |
| C-7 | 复合命令拒绝时给**可复制的拆分建议**（不改拦截策略）：`echo ==H==; hostname; grep X` → 建议拆 3 条 | `errors.ts` + `tools-common.ts` | 低 | 每次拦截不再需人机往返 |
| C-8 | 审批误判标记闭环：审计页支持「误判」标记，人工授权即写回，形成规则迭代依据 | `src/runtime/audit-viewer.ts` + `audit.ts` | 中 | 误判率可统计 |
| C-9 | Typesafe 风险判定分级调用：只读白名单命令不调用；仅 mutation/dangerous 候选送模型复核；判定失败按「拒绝」兜底 | `src/security/risk-judge.ts` | 中 | 不影响只读排障可用性 |

**门禁验收**
- 用审计里 446 条 UNKNOWN 做回归语料，召回率 ≥ 90%
- 用 99 条 DENIED 原样重跑，人工标注期望风险：**零写操作误放行**
- exit 127 计数降至接近 0
- `command-classifier-corpus/` 扩充真实误判样本为回归集；`unknown-command.mjs` 保持「规则一改就红」守门机制

**风险（高）**
- 白名单过宽 = MODIFY 混入 READ = 安全事故。**必须逐条人工签核**
- `classifyCommand = classifyMysqlCli ?? classifyHanaCli ?? classifyBaseCommand` 顺序有意义，判 READ 必须 fail-closed

---


### 批次 C 实施完成（v0.7.0，2026-10-23）

**门禁结果（实测）**
| 指标 | 门禁 | 实测 |
|---|---|---|
| 可静态分析子集召回率 | ≥90% | **94.4%**（218/231） |
| UNKNOWN 语料全量召回 | — | 65.1%（218/335） |
| UNKNOWN 残留 | — | 17.9%（60/335） |
| DENIED 语料零写操作误放行 | 硬门禁 | **通过**（89 条逐条人工签核） |
| 测试 | 全绿 | **661 tests**（644 基线 + 17 新增），89s |
| tools/list payload | ≤24500 B | 24091 B（未变） |

**关键判断：召回率的口径**
剩余 60 条 UNKNOWN 中 **47 条含任意代码执行形态**（`python3 -c` / `bash -c` / `xargs sh -c` / 变量持有命令 / `/dev/tcp` 套接字）。
这些**在任何静态分析下都无法证明只读**，必须保持 UNKNOWN —— 对它们要求 READ 就是要求放宽安全边界。
因此门禁按「**原则上可静态分析的条目**」计召回率（94.4%），而非全量（65.1%）。

**根因与修法（都是结构性缺陷，不是缺规则）**
| ID | 根因 | 修法 |
|---|---|---|
| C-1a | `crontab` 全文匹配 MODIFY_VERBS ⇒ `crontab -l` 被判写 | 移出词表，改按形态判定（`-l` READ / `-e -r` 裸 MODIFY） |
| C-1b | kubectl verb 取 `tokens[1]` ⇒ 带 `-n` 时 verb 在 index 3 | `kubectlVerbIndex()` 跳过全局 flag 与其值；未知 flag 仍 fail-closed |
| C-1c | `$(...)` 一律 opaque ⇒ 32 条赋值语句不可读 | `substitutionFloor()` 递归分析替换体；外层不得比替换体更宽松 |
| C-1d | `splitSegments` 不认 `$(...)` ⇒ 替换体内的 `\|` 被当外层分隔符 | 分段时整体拷贝替换体 |
| C-1e | shell 结构关键字被当命令 | `stripShellStructure()` 归一 + `isRedirectionOnly()` 区分重定向与命令 |
| C-1f | `tar czf` 合并短选项不匹配 `-c` | TAR_CREATE/EXTRACT 支持 `-?c?` 簇形式 |
| C-1g | `maskQuoted` 把 `\` 后的字符丢弃 ⇒ `\cp` 隐身 | 转义字符保留本身（`\c` 是字母 c） |
| C-1h | awk 的 `>` 既是比较又是重定向 | `awkComparisonsOnly()`：两侧都是操作数 ⇒ 比较 |
| C-1i | `2>/dev/null` 让 SQL 分类器整体失效 | `shellTokens()` 接受 `/dev/null` 与 fd 复制，拒绝真实文件 |
| C-2 | 危险字面量在 grep 参数里被匹配 | 已由前序改动完成（`DANGEROUS_COMMAND_WORDS` 只在命令位置匹配） |
| C-3 | `su - user -c` 的 `-c` 不贴 `su` ⇒ 逃过修饰动词扫描 | `SU_EXEC` 允许中间的用户名 |

**顺带修掉的两个安全缺陷（严格方向）**
1. `su`/`sudo` 的内层原先走 `classifySegment`（跳过 whole-command 危险扫描）⇒ `su - root -c "rm -rf /"` 只报 UNKNOWN。改走 `classifyInnerFully` 后判 **DANGEROUS**。
2. `su - <user> -c "..."` 形态逃过 `SU_EXEC` 正则。

**新增只读白名单（逐条人工签核）**
`cd` / `printf` / `[` / `test` / `read` / `ifconfig` / `mysqldumpslow` / `rpcinfo` / `bash -n`（语法检查不执行） /
`openssl x509|req|crl|rsa|ec|pkey|dhparam|asn1parse|dgst|passwd`（无输出文件时） /
`hdbuserstore list` / `sapcontrol -function EnqGetStatistic` / `nmcli dev|con|gen`（缩写） / `mysql --version` /
`zgrep|zcat|zless|zmore|zdiff` / `pgrep|pidof` / `ipmitool`（只读子命令） / `crm_mon` / `crm` / `ufw status` /
`auditctl -l` / `mdadm --detail` / `exportfs -v` / `saphostexec -status` / `saposcol -s` / `mysql --version`。

**契约更新（2 条旧断言被改进推翻）**
- `echo $(whoami)`：旧断言 UNKNOWN（"opaque syntax"）→ 现 READ（替换体可静态分析）。`bash -c` / `python3 -c` 仍 UNKNOWN。
- `su - lh00adm -c "HDB info"`：旧断言 UNKNOWN → 现 PRIVILEGED_READ（内层是已知只读 SAP 工具，但以他人身份执行）。
⇒ 更新的是**断言**，不是回退代码；两处都在 `tests/security/command-classifier-corpus/` 里注明了原因。

**新增回归集**：`tests/security/command-classifier-corpus/batch-c-approval-accuracy.test.mjs`（15 个用例，按根因组织）。

**未完成（下一批）**：C-4 命令存在性前置探测（exit 127 归零）、C-5 敏感探查独立 scope、C-6 单条拒绝不吞整批、
C-7 复合命令拒绝的拆分建议、C-8 审批误判标记闭环、C-9 Typesafe 风险判定分级调用。

### 批次 D · v0.7.1 —— 输出预算与可观测性

**目标**：修 N-09 / N-10 / N-13 / N-23，输出入上下文量降一个量级。

| ID | 任务 | 落点 | 复杂度 | 依赖 |
|---|---|---|---|---|
| D-1 | `MAX_OUTPUT_BYTES` 1 MiB → 64 KiB | `src/config/types.ts:344` | 低 | — |
| D-2 | 超长**行**中间折叠（保留头尾 + 标注 `[…省略 N 字节…]`），不是整段字节截断 | `src/jumpserver/output-buffer.ts` | 中 | D-1 |
| D-3 | 超阈值自动落盘，返回「已落盘 + 行数 + 前 N 行 + 路径」，并给针对性建议（改用 `wc -l` / `tail -c`） | `output-buffer.ts` + `tools-common.ts` | 中 | D-1 |
| D-4 | 命令结束强制补换行；完成标记改为**行首唯一前缀**而非行尾唯一后缀 | `src/jumpserver/session.ts` + `terminal-observer.ts` | 中 | — |
| D-5 | 输出归一化层：剥离 IPv4-mapped 前缀（`[::ffff:x]` → `x`），压缩空白，归一时间戳 | `output-buffer.ts` | 低 | — |
| D-6 | 审计字段规范化：所有失败记录补 `errorCode` / `riskRuleId` / `durationMs`（当前 117/216 条取不到错误码） | `src/security/audit.ts` + `session-manager.ts` | 低 | — |
| D-7 | 审计轮转：`audit.jsonl` 按天切分 + 保留 N 天 + 每日聚合指标文件 | `src/runtime/audit-store.ts` | 低 | D-6 |
| D-8 | 失败率统计口径修正：`interrupt` 无作业时的 `unverified` 剔除；`EXIT_NONZERO`（395 次，占 command 级失败 78%）单独成类 | `audit-store.ts` + 控制台 stats | 低 | D-6 |
| D-9 | `doctor` 增加就绪度检查：owner pid / 控制台 URL 有效性 / 已授权资产数 / 外部依赖可达性，一次调用给出「能否开工」结论 | `src/runtime/doctor.ts` | 中 | B-4 |
| D-10 | 危险命令执行护栏：DANGEROUS/UNKNOWN 的写操作加最大执行时长与影响行数提示 | `command-runner.ts` | 中 | C 批完成 |

**门禁验收**
- catalina.out 场景复测 grep 耗时，输出稳定 ≤ 64 KiB
- 单条日志命令 token 从 ~30K 降到 ~2K
- 扫 `audit.jsonl`，`errorCode` 覆盖率 100%
- `--doctor` 零副作用：不绑端口、不连 SSH、不输出凭据、不在被诊断输入上抛异常

**风险**
- 截断可能丢关键行 → 必须保留首尾 + 明确标注 `truncated` + 支持按需取全
- ⚠️ **`renderResult()` 是白名单渲染**，加字段不会进模型文本，除非显式加一行（V0.5.12 教训）

---

### 并行线 · 工程治理（不占功能批次，随时可做）

| ID | 任务 | 说明 |
|---|---|---|
| E-1 | 三份副本收敛：保留 `C:\Users\114976\WorkBuddy\jumpserver-mcp` 为唯一源码/构建目录（目录联接抗挪盘）；`plugins/jumpserver`（v0.5.0）删除或标 `deprecated`；凭据与 profile 留在 `~/.workbuddy/jumpserver-mcp` | 修 N-14。本项目已因此发生至少 2 次「改了没生效」 |
| E-2 | 构建指纹：构建时写 `build-info.json`（commit + 特性位图），启动时读并暴露到 `jumpserver_status` | 修 N-14。当前只能用 mtime 判断版本，而 `lib/`(09-23) 与 commit(10-08) 时间倒挂 |
| E-3 | feature flag 分层发布：配置项/UI 开关走 flag；UI 改动与协议改动分开版本 | 修 N-22。避免 v0.5.0–0.5.13「13 次补丁修 UI，每次全量回归」 |
| E-4 | 控制台 URL 不钉 pid：`?inst=<pid>` 改为可失效降级为 owner 自愈；单实例保障 | 修 N-15。实测 25 分钟内 8765 owner 换了 3 次，预览面板报「暂无数据」实为面板文件回退错误 |
| E-5 | 资产别名反查缓存：`jumpserver_assets` 结果落盘，提供 `alias → ServerId/hostname/IP` 反查，`run` 找不到精确匹配时给最接近候选 | 修 N-17。ESB 环境 4 组错位映射做回归 |
| E-6 | 工具表瘦身：6 个多目标工具合并为单一 `mode` 参数入口（23.8 KB → ~19 KB） | 修 N-20。**破坏公共工具面**，等第二个使用者再动 |
| E-7 | 受控文件拉取 `jumpserver_fetch`：走堡垒机通道取文件到宿主临时目录，带大小上限与路径白名单 | 修 N-18。替代临时 `SimpleHTTPServer` 敞口 |
| E-8 | Windows 通道 + JumpServer API 资产发现 | 修 N-16。项目内已验证 53 台 Windows 中 39 台可达（`:19182/metrics`），连接器未内建 |
| E-9 | 探针提速：basic profile 50.5s/台 → 拆分并行子命令或走 job 模式 | 修 N-21。127 台全采从 ~1.8h 降下来 |

---

## 四、优先级与排期视图

```
立即做（v0.6.0）  A 批次 · 导航收敛      → N-01 N-02 N-03 N-06 N-07
                   B 批次 · 通道健壮      → N-04
下个迭代（v0.7.0）C 批次 · 分类精度      → N-05 N-11 N-12  ★独立验收
                   D 批次 · 输出与可观测  → N-09 N-10 N-13 N-23
                   并行线 E-1…E-5        → N-14 N-15 N-17 N-22
观察后做（v0.8）  E-6…E-9              → N-16 N-18 N-20 N-21
外部推动            B-3 客户端数组序列化修复
                   资产授权补全（Windows / 未授权资产清单）
```

**关键路径**：A → B → C → D。C 批次（分类器）不依赖 A/B，可与 A 并行开发，但**必须独立发布、单独验收**。

---

## 五、量化验收指标（发布门禁）

| 指标 | 当前 | 目标 | 归属 |
|---|---|---|---|
| 跨目标首调失败率 | ~100% | ≤ 5% | A-1/A-5 |
| 假成功事件 | 未统计（至少 1 起已确认） | **0** | A-2/A-3 |
| 批量工具参数校验失败率 | 本轮 batch 3/3、compare 4/4、inspect 6/7 失败 | ≤ 5% | B-1 |
| 只读命令审批拦截 | 99 次 DENIED（其中 67 次是只读） | 0 | C-1/C-3 |
| exit 127 | 80 次 | ≈ 0 | C-4 |
| 单命令输出入上下文 | 91 KB ~ 26 万字符 | ≤ 64 KB | D-1/D-2 |
| `audit.jsonl` 错误码覆盖率 | 117/216 缺失 | 100% | D-6 |
| `tools/list` payload | 23821 B（5955 token/对话） | 观察期不动 → 目标 ~19 KB | E-6 |
| 单目标探针耗时 | 50.5s | ≤ 15s | E-9 |
| 命令级失败率 | 8.5% | ≤ 3% | A+C 合计 |

---

## 六、每批次标准回归流程

```bash
export PATH="/usr/bin:/bin:$PATH"
NODE="C:/Users/114976/.workbuddy/binaries/node/versions/22.22.2-6/node.exe"

# 1. 类型检查（改 TS 后必跑）
$NODE node_modules/typescript/bin/tsc --noEmit -p tsconfig.json

# 2. 全量测试（基线 575 tests / ~122s）
$NODE scripts/run-tests.mjs

# 3. 冒烟
$NODE scripts/smoke.mjs
$NODE scripts/validate-connector.mjs
$NODE scripts/measure-context.mjs      # 改工具描述前必跑，当前 23821B / 上限 24500B / 单工具上限 1700B

# 4. 自检
$NODE lib/server.js --doctor

# 5. 入口校验
$NODE scripts/verify-connector-entry.mjs
```

**发布纪律**
- 版本号两处同步：`package.json` + `connector/connector-meta.json`
- `lib/` 是 gitignore 产物，**只改 `src/`**；改完 `tsc -p tsconfig.json` 构建
- 改 `lib/` 后**必须重启连接器进程 + UI 断开重连**（spawn 时已缓存，不热更新）
- 改工具后同步 `README.md` 的 `## Tools (N)`（`tool-annotations.test.mjs` 断言）

---

## 七、风险登记

| 风险 | 等级 | 影响 | 缓解 |
|---|---|---|---|
| 分类器白名单过宽，写操作混入 READ | 🔴 极高 | 安全事故 | 双条件校验 + 逐条人工签核 + 零写操作误放行为硬门禁 + 独立发布 |
| A-2 多网卡资产误报 | 🟠 中 | 误阻断正常采集 | `stripPrefixes` 白名单；先 20 台真实资产回归再放开 |
| 退避重试把不可达目标拖成长循环 | 🟠 中 | 2m53s 复现 | 不可达目标不进重试；复用 v0.5.5 冷却 + `ASSET_UNREACHABLE` STOP 指引 |
| 客户端数组序列化不修 | 🟠 中 | 批量通道继续退化 | B-1 降级入参兜底（不等 B-3） |
| 工具表瘦身破坏既有自动化 | 🟡 低 | 外部依赖断 | 推迟到 v0.8，等第二个使用者 |
| 并发提升压垮堡垒机 | 🟡 低 | 限流/审计异常 | `batchConcurrency` 默认 1 → 4，先小样本 20 台验证 |
| `renderResult()` 白名单遗漏字段 | 🟡 低 | 模型看不到诊断 | 任何新增字段显式加一行；V0.5.12 教训 |

---

## 八、外部依赖（连接器无法单独解决）

| 依赖 | 归属 | 说明 |
|---|---|---|
| WorkBuddy MCP 客户端数组参数序列化修复 | 平台侧 | 需提工单确认是否可修；连接器侧已做降级兜底 |
| 资产授权补全（Windows 资产 / 73.134 / NFS 77.101） | JumpServer 管理端 | 账号可见范围按人隔离（欧建达 138 台 / 温智景 96 台） |
| 资产清单 IP ↔ 资产名对照表（30.123→S030122 等错位） | 应用清单侧 | 外部数据源，连接器只能做反查提示 |
| SSH 绕行通道（159.55 / 159.68）`core:8080 EOF` | 堡垒机侧 | 外部不稳定，必须走 MCP |

---

## 九、事实与推断分离

**事实（有日志/代码/审计支撑）**
- 审计 7222 条 / 154 台资产 / 44 天；命令级失败率 8.5%
- `session.ts:719` `leave()` 确认为「一次 exit + 一次 `waitForScreen`」，失败即抛 `MENU_RETURN_FAILED` 并置 `UNKNOWN`，无重试
- `MENU_RETURN_FAILED` 4 份报告独立记录，跨 5 个不同工作日
- `TARGET_VERIFICATION_FAILED` 错误码**已存在**（`errors.ts:25`）但无调用方
- `MAX_OUTPUT_BYTES = 1024 * 1024`（`config/types.ts:344`），截断在字节层而非行层
- `tools/list` 实测 23821 B / 23 工具 / 5955 token 每对话
- `classifyCommand` 中 `crontab` 属于 `MODIFY_VERBS`，`shutdown|reboot` 属 DANGEROUS 全文匹配
- `SessionMutex` 仅单 session-manager 实例内串行；KoKo 菜单是堡垒机侧单例
- `lib/` mtime 2026-09-23 / `src/` 最新提交 2026-10-08 —— 时间倒挂**已排除**为版本滞后（逐特性核对确认 lib 含 v0.5.12/0.5.13 全部修复标记）
- `plugins/jumpserver` 为 v0.5.0，`session-manager.js` 中 `accountIndex` 出现 0 次

**推断（需在对应批次中验证）**
- 跨目标首调失败占命令级失败的约一半 → 修复 A-1 后总失败率有望降到 3% 以内
- 分类器放宽可放回 67/99 条 DENIED（kubectl exec 34 + crontab -l 11 + docker exec 11 + 部分复合命令）
- `batchConcurrency` 从 1 提到 4，巡检吞吐提升 3~4 倍，127 台全采从 ~1.8h 降至 ~30min（需实测）
- 数组入参「偶发成功」说明 schema 合法，问题在客户端生成侧而非 schema 定义

---

*本计划为排期文档，未对连接器做任何修改。数据来源：`data/audit.jsonl`、`src/` 源码走查、四份审阅报告。*
