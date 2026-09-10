/**
 * Embedded ops console (V0.4.0) — one local page served from inside the
 * MCP process. Tabs:
 *   实时终端  live per-conversation PTY mirror (redacted stream from TerminalObserver)
 *   拓扑      last jumpserver_topology result (nodes / edges / evidence)
 *   任务      streaming jobs (tail -f …) with progress and stop
 *   审计日志  audit table + filter + JSONL/CSV export (configured timezone)
 *   统计      risk / target / operation / daily aggregates
 *   会话      active sessions + interrupt / disconnect buttons
 *   设置      V0.5.0: live connection and where every value came from
 *             (ENV / config.json / default) — password value never shown
 *
 * Behaviour:
 *   - one console per conversation: when the configured port is taken (another
 *     conversation's MCP process holds it), fall back to an ephemeral port so
 *     every conversation gets its OWN live console with its OWN data.
 *   - NO external browser launch, ever. An MCP server has no way to raise UI in
 *     the host app; only the host (WorkBuddy) can open its preview panel, and
 *     that happens through the model handover, see consoleHintForModel().
 *   - every instance heartbeats a discovery file under data/consoles/<pid>.json
 *     so any external process can enumerate the live consoles and their ports.
 *   - the page detects a dead server (conversation ended => process gone) and
 *     shows an "expired" overlay, attempting to close itself.
 *   - audit reads go through the incremental AuditStore (no whole-file reads)
 *     and render in the configured timezone (storage stays UTC).
 */
import http from 'node:http'
import { randomBytes } from 'node:crypto'
import { mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { SessionRegistry } from '../jumpserver/session-registry.js'
import type { TerminalEvent } from '../jumpserver/terminal-observer.js'
import type { AuditStore } from './audit-store.js'
import type { JobStore } from './job-store.js'
import type { TopologyStore } from './topology-store.js'
import type { AssetStore } from './asset-store.js'
import type { BaselineStore } from './baseline-store.js'
import type { ConnectionView } from '../config/env.js'
import { interruptSession } from './interrupt.js'

export interface AuditViewerOptions {
  enabled: boolean
  port: number
  autoOpen: boolean
  /** EADDRINUSE => take an ephemeral port instead of sharing another process's console (default true). */
  portFallback: boolean
  /**
   * V0.4.2: minutes the console access token stays valid (default 720 = 12h).
   * Set 0 to disable expiry. An expired token forces a fresh handover URL.
   */
  tokenTtlMinutes?: number
  /**
   * V0.5.1: serve the console at a TOKEN-FREE, restart-stable address
   * (`http://127.0.0.1:<port>/`) and inject the access token into the page
   * instead of the URL (default true).
   *
   * Why: the per-process ephemeral port made every handover URL a dead end.
   * With two MCP processes alive (a custom `mcp.json` entry plus the installed
   * connector) the second one hit EADDRINUSE, fell back to a random port and
   * handed out THAT port's URL — then died on the next config reload, so the
   * already-open page showed 工作台已失效. A fixed address plus in-page token
   * injection means one stable URL per workspace that survives restarts.
   *
   * Set false to restore v0.5.0 behaviour (?token=… in the URL, ephemeral
   * fallback port). The token then also guards `GET /`.
   */
  stableUrl?: boolean
}

export interface AuditViewerServices {
  /** V0.4.0: incremental audit sink (null => fall back to whole-file reads). */
  audit?: AuditStore | null
  jobs?: JobStore | null
  topology?: TopologyStore | null
  /** V0.4.1: last asset listing, rendered by the 资产 tab. */
  assets?: AssetStore | null
  /** V0.4.1: named baselines (data/baselines) for the 资产 tab's drift column. */
  baselines?: BaselineStore | null
  /** IANA display zone for audit timestamps (default Asia/Shanghai). */
  timeZone?: string
  /**
   * V0.5.0: live connection provenance for the 设置 tab. Absent when the
   * console runs as an audit-only mirror without a runtime.
   */
  connection?: (() => ConnectionView) | null
  /** V0.5.0: policy knobs shown by the 设置 tab — values only config.json sets. */
  policy?: (() => Record<string, unknown>) | null
  /** V0.5.0: known_hosts records (path + entries) for the 设置 tab. */
  knownHosts?: (() => { path?: string; entries: Record<string, unknown> }) | null
}

/** Terminal events sent to the page per poll (tail; older events are dropped). */
const TERMINAL_TAIL_EVENTS = 400
/** Max lines kept per session in the page (client side). */
const TERMINAL_MAX_LINES = 2000
/** Consecutive failed polls before the page declares the server dead. */
const DEAD_AFTER_FAILURES = 6

let viewerUrl: string | null = null
/** Discovery-file dir + our own file, written on every heartbeat. */
let consoleDir: string | null = null
let consoleFile: string | null = null
/** Bound port + start time, kept for discovery-file rewrites on rotation. */
let consolePort = 0
let consoleStartedAt = new Date().toISOString()
/** V0.4.4: bound HTTP server and heartbeat timer, exposed via stopAuditViewer. */
let consoleServer: import('node:http').Server | null = null
let consoleHeartbeatTimer: ReturnType<typeof setInterval> | null = null
/** Whether this process hands its console URL to the model (config: auditViewer.autoOpen). */
let hintEnabled = true
/** V0.5.1: stable token-free address (config: auditViewer.stableUrl). */
let stableAddress = true
/** V0.5.1: true while THIS process owns the HTTP listener (false when adopting another's). */
let consoleBound = false
/** V0.5.1: true once a browser actually fetched the page (stops the hint nagging). */
let consoleOpened = false
/** V0.5.1: hints emitted so far, capped by CONSOLE_NAG_LIMIT. */
let hintEmitted = 0
/** V0.5.1: the configured port, kept so the heartbeat can retry a takeover. */
let consoleRequestedPort = 0
/** V0.5.1: log "served by another process" once, not on every retry tick. */
let consoleAdoptLogged = false
/** V0.5.1: max hints while the console has never been opened. */
const CONSOLE_NAG_LIMIT = 12
/**
 * V0.4.1: per-process random access token. The console binds to 127.0.0.1, but
 * any local process (or a browser tab) could otherwise read the audit trail and
 * drive /api/interrupt. Every request must carry ?token=… (or the X-Console-Token
 * header); requests without it get 403. The token lives only in memory and in
 * the handover URL, never in a log.
 *
 * V0.4.2: the token now EXPIRES (default 12h, configurable via
 * auditViewer.tokenTtlMinutes; 0 disables expiry) and can be ROTATED on demand.
 * An expired token is treated exactly like a wrong one — the page shows a
 * "console expired, ask the model to reopen it" overlay instead of silently
 * failing. Rotation invalidates the old token immediately and rewrites the
 * discovery file so the next handover URL carries the new one.
 */
let consoleToken: string | null = null
/** Epoch ms when the current token stops being valid; null = never expires. */
let consoleTokenExpiresAt: number | null = null
/** Token lifetime in ms (0 = no expiry). Set from config at start. */
let consoleTokenTtlMs = 12 * 60 * 60 * 1000
const TOKEN_HEADER = 'x-console-token'

/** Constant-time-ish compare (length is public; content comparison is cheap and adequate here). */
function tokenMatches(candidate: string | null): boolean {
  if (consoleToken === null) return true
  if (consoleTokenExpiresAt !== null && Date.now() >= consoleTokenExpiresAt) return false
  if (candidate === null || candidate.length !== consoleToken.length) return false
  let diff = 0
  for (let i = 0; i < candidate.length; i += 1) diff |= candidate.charCodeAt(i) ^ consoleToken.charCodeAt(i)
  return diff === 0
}

/** True when a token exists but has passed its expiry (drives the page overlay). */
function consoleTokenExpired(): boolean {
  return consoleToken !== null && consoleTokenExpiresAt !== null && Date.now() >= consoleTokenExpiresAt
}

/** Mint a fresh token, set its expiry, and refresh the handover URL + discovery file. */
function rotateConsoleToken(): string {
  consoleToken = randomBytes(16).toString('hex')
  consoleTokenExpiresAt = consoleTokenTtlMs > 0 ? Date.now() + consoleTokenTtlMs : null
  if (consolePort > 0) viewerUrl = consoleUrl(consolePort)
  writeConsoleFile()
  return consoleToken
}

/** Parse the JSONL audit sink; a missing or partially written file yields what is readable. */
export function readAuditEntries(file: string): Record<string, unknown>[] {
  try {
    const text = readFileSync(file, 'utf8')
    return text
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => {
        try {
          return JSON.parse(line) as Record<string, unknown>
        } catch {
          return null
        }
      })
      .filter(Boolean) as Record<string, unknown>[]
  } catch {
    return []
  }
}

function page(timeZone: string, injectedToken: string): string {
  return `<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>JumpServer MCP 控制台</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#141414;color:#ddd;font:13px/1.6 "JetBrains Mono","Cascadia Code",Consolas,monospace}
header{position:sticky;top:0;background:#1b1b1b;border-bottom:1px solid #2a2a2a;padding:8px 12px;display:flex;gap:10px;align-items:center;z-index:5;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}
header::-webkit-scrollbar{display:none}
.dot{width:8px;height:8px;border-radius:50%;background:#1d9e75;animation:pulse 2s infinite;flex:none}
@keyframes pulse{50%{opacity:.4}}
header h1{font-size:14px;margin:0;font-weight:500;color:#fff;white-space:nowrap;flex:none}
nav{display:flex;gap:4px;flex:none}
nav button{background:transparent;border:1px solid transparent;color:#999;padding:4px 10px;border-radius:6px;font:inherit;cursor:pointer;white-space:nowrap}
nav button:hover{color:#ddd}
nav button.on{background:#2a2a2a;color:#fff;border-color:#3a3a3a}
#stat{color:#777;font-size:12px;margin-left:auto;white-space:nowrap;flex:none;padding-left:10px}
main{padding:12px 16px}
section{display:none}section.on{display:block}
input[type=text]{background:#222;border:1px solid #333;color:#ddd;padding:4px 10px;border-radius:6px;outline:none}
button.act{background:#24313c;border:1px solid #35505f;color:#9fd3ee;padding:4px 12px;border-radius:6px;font:inherit;cursor:pointer;white-space:nowrap}
button.act:hover{background:#2c3f4d}
button.warn{background:#3a2424;border-color:#5f3535;color:#ee9f9f}
.tw{overflow-x:auto}
table{border-collapse:collapse;min-width:640px;width:100%}
th{position:sticky;top:0;background:#1b1b1b;text-align:left;padding:8px 12px;color:#888;font-weight:400;font-size:12px;border-bottom:1px solid #2a2a2a}
td{padding:6px 12px;border-bottom:1px solid #222;vertical-align:top}
tr:hover td{background:#1d1d1d}
.time{color:#888;white-space:nowrap}
.op{color:#7fb3e8;white-space:nowrap}
.tgt{color:#c9a86a;white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis}
.risk{white-space:nowrap}
.risk-READ{color:#7fc98f}.risk-PRIVILEGED_READ{color:#c9c37f}.risk-UNKNOWN{color:#bbb}.risk-MODIFY{color:#e8a86a}.risk-DANGEROUS{color:#e87f7f}
.bad{color:#e87f7f;font-weight:600}
.cmd{color:#a8d8a8;word-break:break-all}
#empty{padding:40px;text-align:center;color:#666}
.termbox{background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;padding:10px;height:calc(100vh - 210px);overflow-y:auto;white-space:pre-wrap;word-break:break-all;font-size:12.5px;line-height:1.45}
.t-out{color:#cfe3cf}.t-in{color:#e8d47f}.t-sys{color:#6fa8c9}.t-err{color:#e87f7f}
.sessbar{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.sesschip{background:#222;border:1px solid #333;border-radius:6px;padding:2px 10px;cursor:pointer;color:#999;white-space:nowrap}
.sesschip.on{border-color:#3f6d8a;color:#9fd3ee}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.card{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:8px;padding:10px 16px;min-width:110px}
.card .n{font-size:22px;color:#fff}
.card .l{color:#888;font-size:12px}
.grp{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:8px;padding:12px 16px;margin-bottom:12px;overflow-x:auto}
.grp h3{margin:0 0 8px;font-size:13px;color:#ccc;font-weight:500;white-space:nowrap}
.bar{display:flex;align-items:center;gap:10px;margin:3px 0;min-width:420px}
.bar .lab{width:200px;color:#aaa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:right;flex:none}
.bar .track{flex:1;background:#222;border-radius:4px;height:14px;overflow:hidden}
.bar .fill{height:100%;background:#3f6d8a;display:block}
.bar .cnt{width:60px;color:#888;flex:none}
/* V0.4.0: topology */
.nodes{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.node{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:8px;padding:8px 12px;min-width:190px;cursor:pointer}
.node:hover{border-color:#3f6d8a}
.node.on{border-color:#5f8fae;background:#20272c}
.node .ip{color:#fff;font-size:13px}
.node .host{color:#c9a86a;font-size:12px}
.node .role{color:#7fb3e8;font-size:12px}
.node .meta{color:#888;font-size:12px}
.node.dead{border-color:#5f3535;opacity:.75}
#topodetail{background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;padding:10px 14px;margin-bottom:12px;white-space:pre-wrap;color:#bbb;min-height:44px}
.badge{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;border:1px solid #35505f;color:#9fd3ee}
.badge.HIGH{border-color:#2f6b45;color:#7fc98f}
.badge.MEDIUM{border-color:#6b5f2f;color:#c9c37f}
.badge.LOW{border-color:#4a4a4a;color:#bbb}
.ev{color:#888;font-size:12px}
/* V0.4.0: jobs */
.jobbar{height:6px;background:#222;border-radius:3px;overflow:hidden;min-width:120px}
.jobbar i{display:block;height:100%;background:#3f6d8a}
.state-RUNNING{color:#7fc98f}.state-STOPPED{color:#c9c37f}.state-LOST{color:#e87f7f}
#dead{position:fixed;inset:0;background:rgba(10,10,10,.92);z-index:50;display:none;align-items:center;justify-content:center;flex-direction:column;gap:14px}
#dead .t{font-size:16px;color:#e8a86a}
#dead .d{color:#999;font-size:13px;max-width:420px;text-align:center}
#expired{position:fixed;inset:0;background:rgba(10,10,10,.92);z-index:51;display:none;align-items:center;justify-content:center;flex-direction:column;gap:14px}
#expired .t{font-size:16px;color:#e8a86a}
#expired .d{color:#999;font-size:13px;max-width:460px;text-align:center;line-height:1.6}
@media (max-width:720px){
  header h1{display:none}
  #stat{display:none}
  nav button{padding:3px 7px;font-size:12px}
  main{padding:8px}
}
</style></head><body>
<header>
  <div class="dot"></div><h1>JumpServer MCP 控制台</h1>
  <nav>
    <button data-tab="terminal">实时终端</button>
    <button data-tab="assets">资产</button>
    <button data-tab="topology">拓扑</button>
    <button data-tab="jobs">任务</button>
    <button data-tab="audit">审计日志</button>
    <button data-tab="stats">统计</button>
    <button data-tab="sessions">会话</button>
    <button data-tab="settings">设置</button>
  </nav>
  <span id="stat">loading…</span>
</header>
<main>

<section id="tab-terminal">
  <div class="sessbar" id="sesschips"></div>
  <div class="sessbar">
    <button class="act warn" id="btn-interrupt">中断当前命令 (Ctrl+C)</button>
    <label style="color:#999;font-size:12px;display:flex;align-items:center;gap:4px"><input type="checkbox" id="autoscroll" checked> 自动滚动</label>
    <button class="act" id="btn-clear">清屏</button>
    <span style="color:#777;font-size:12px">中断会向远端 Shell 发送 Ctrl+C 并重新验证，不会断开会话。</span>
  </div>
  <div class="termbox" id="term"></div>
</section>

<section id="tab-assets">
  <div class="sessbar">
    <input type="text" id="assq" placeholder="搜索：名称 / IP / 平台 / 节点 / 备注" style="width:260px">
    <select id="assgroup" title="按分组（节点）筛选"></select>
    <select id="assplatform" title="按平台筛选"></select>
    <select id="assstatus" title="按状态筛选">
      <option value="">全部状态</option>
      <option value="active">活跃（近期访问）</option>
      <option value="idle">未访问</option>
    </select>
    <button class="act" id="ass-refresh">刷新</button>
    <span style="color:#777;font-size:12px" id="assmeta"></span>
  </div>
  <div class="tw"><table><thead><tr>
    <th style="width:40px">#</th><th style="width:200px">名称</th><th style="width:135px">IP</th>
    <th style="width:90px">平台</th><th style="width:150px">分组 / 节点</th><th style="width:120px">角色</th>
    <th style="width:100px">状态</th><th>备注</th>
  </tr></thead><tbody id="assrows"></tbody></table></div>
  <div id="assempty" style="display:none;color:#888;padding:14px">暂无资产数据 — 让 AI 调用一次 jumpserver_assets 后此处会显示缓存清单。</div>
  <div class="grp" style="margin-top:12px"><h3>基线（漂移检测）</h3><div id="assbaselines" style="color:#999;font-size:12px">无</div></div>
</section>

<section id="tab-topology">
  <div class="sessbar">
    <button class="act" id="topo-refresh">刷新</button>
    <span style="color:#777;font-size:12px">数据来自 jumpserver_topology / jumpserver_inspect 的最近一次采集。</span>
  </div>
  <div id="topometa" style="color:#888;margin-bottom:8px"></div>
  <div class="nodes" id="toponodes"></div>
  <div id="topodetail">点击节点查看详情</div>
  <div class="grp"><h3>关系（含证据）</h3><div id="topoedges"></div></div>
</section>

<section id="tab-jobs">
  <div class="sessbar">
    <button class="act" id="jobs-refresh">刷新</button>
    <span style="color:#777;font-size:12px">流式任务（tail -f / journalctl -f / tcpdump）。任务运行期间该 Shell 被独占。</span>
  </div>
  <div class="tw"><table><thead><tr><th style="width:150px">任务</th><th style="width:170px">目标</th><th style="width:100px">状态</th><th style="width:170px">运行时长</th><th>命令</th><th style="width:90px"></th></tr></thead>
  <tbody id="jrows"></tbody></table></div>
  <div class="grp" style="margin-top:12px"><h3>输出尾部</h3><div class="termbox" id="jobout" style="height:220px"></div></div>
</section>

<section id="tab-audit">
  <div class="sessbar">
    <input type="text" id="filter" placeholder="过滤：命令 / 资产 / 操作类型 / 风险 / callId" style="width:280px">
    <button class="act" id="exp-jsonl">导出 JSONL</button>
    <button class="act" id="exp-csv">导出 CSV</button>
    <span style="color:#777;font-size:12px">时间显示时区：${timeZone}（存储为 UTC）</span>
  </div>
  <div class="tw"><table><thead><tr><th style="width:165px">时间</th><th style="width:125px">操作</th><th style="width:185px">目标</th><th style="width:140px">风险 / 结果</th><th>命令</th></tr></thead>
  <tbody id="rows"></tbody></table></div>
  <div id="empty">暂无审计记录</div>
</section>

<section id="tab-stats">
  <div class="cards" id="cards"></div>
  <div class="grp"><h3>按目标资产（Top 10）</h3><div id="by-target"></div></div>
  <div class="grp"><h3>按风险等级</h3><div id="by-risk"></div></div>
  <div class="grp"><h3>按操作类型</h3><div id="by-op"></div></div>
  <div class="grp"><h3>近 14 天</h3><div id="by-day"></div></div>
</section>

<section id="tab-sessions">
  <div class="sessbar">
    <button class="act warn" id="close-all">断开全部会话</button>
    <button class="act" id="interrupt-all">中断当前命令</button>
    <span style="color:#777;font-size:12px">断开会释放 SSH/PTY；AI 侧下次调用工具会自动重连。</span>
  </div>
  <div class="tw"><table><thead><tr><th style="width:200px">会话</th><th style="width:150px">状态</th><th style="width:190px">当前资产</th><th style="width:120px">权限模式</th><th style="width:170px">最近使用</th><th></th></tr></thead>
  <tbody id="srows"></tbody></table></div>
</section>

<section id="tab-settings">
  <div class="sessbar">
    <button class="act" id="set-refresh">刷新</button>
    <span style="color:#777;font-size:12px">连接信息来自 WorkBuddy 连接器表单（环境变量）或 config.json。优先级：环境变量 &gt; config.json &gt; 默认值。密码不显示明文。</span>
  </div>
  <div class="grp"><h3>当前连接</h3><div id="setconn">加载中…</div></div>
  <div class="grp"><h3>策略配置（只在 config.json 中设置）</h3><div id="setpolicy">加载中…</div></div>
  <div class="grp"><h3>已知主机密钥（known_hosts）</h3><div id="sethosts">加载中…</div></div>
</section>

</main>
<div id="dead"><div class="t">工作台已失效</div><div class="d">本地控制台进程已退出。V0.5.1 起工作台会自动重连 —— 若 30 秒内没有恢复，说明这个 MCP 进程已彻底结束，让 AI 重新调用任意一个 jumpserver 工具（例如 jumpserver_status）即可复活。</div><button class="act" id="dead-close">关闭本页</button></div>
<div id="expired"><div class="t">控制台令牌已过期</div><div class="d">出于安全考虑，本地控制台的访问令牌有时效。请让 AI 重新调用一次 jumpserver_status（或任意工具），然后用新的链接打开控制台。</div><button class="act" id="expired-close">关闭本页</button></div>
<script>
var TZ = ${JSON.stringify(timeZone)};
var tab = (location.hash || '#audit').slice(1);
var auditAll = [], lastCount = -1;
var trackedSeq = {}, currentSess = null, sessStatus = {}, termLines = 0;
var failCount = 0, deadShown = false, expiredShown = false;
var topo = null, topoPick = null, jobPick = null;
function $(id){return document.getElementById(id);}
function esc(s){return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function stripAnsi(s){return String(s == null ? '' : s).replace(/\\x1b\\[[0-9;?]*[A-Za-z]/g,'').replace(/[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f]/g,'');}
function shortId(id){return id.length > 22 ? id.slice(0,8) + '…' + id.slice(-10) : id;}
function labelId(id){return id === 'anonymous' ? '当前对话' : shortId(id);}
/* V0.4.0: storage is UTC, display is the configured zone. */
var dtf = null;
try { dtf = new Intl.DateTimeFormat('en-CA',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}); } catch(e) { dtf = null; }
function fmtTime(ts){
  var raw = String(ts == null ? '' : ts);
  if (!raw) return '';
  var d = new Date(raw);
  if (isNaN(d.getTime())) return raw.replace('T',' ').slice(0,19);
  if (dtf) { try { return dtf.format(d).replace(',',''); } catch(e) {} }
  return raw.replace('T',' ').slice(0,19) + ' UTC';
}
function showDead(){
  if (deadShown) return; deadShown = true;
  $('dead').style.display = 'flex';
}
/* V0.5.1: a successful poll clears the overlay, so the page recovers by itself
   when a restarted MCP process takes the console address back over. */
function hideDead(){
  if (!deadShown) return; deadShown = false;
  $('dead').style.display = 'none';
}
function showExpired(){
  if (expiredShown) return; expiredShown = true;
  $('expired').style.display = 'flex';
}
$('dead-close').addEventListener('click', function(){ window.close(); });
$('expired-close').addEventListener('click', function(){ window.close(); });
/* fetch wrapper: any success resets the dead-counter; N misses => dead overlay */
/* V0.4.1: /api/* requires the console access token. V0.5.1: the server injects
   it into the page, so the token-free stable address still works. */
var TOKEN = (new URLSearchParams(location.search)).get('token') || ${JSON.stringify(injectedToken)};
function withToken(u){
  if (!TOKEN) return u;
  return u + (u.indexOf('?') >= 0 ? '&' : '?') + 'token=' + encodeURIComponent(TOKEN);
}
var tokenReloads = 0;
/* V0.5.1: an aged-out token is transparent — reloading fetches a fresh one
   from the server (which injects the current token into the page). */
function refreshToken(){
  if (tokenReloads >= 2) { showExpired(); return; }
  tokenReloads++; location.reload();
}
function F(u,o){
  return fetch(withToken(u),o).then(function(r){
    /* V0.4.2: a 403 marked expired means the token aged out. */
    if (r.status === 403 && r.headers.get('x-console-token-expired') === '1') { refreshToken(); }
    failCount=0; hideDead(); return r;
  }).catch(function(e){failCount++;if(failCount>=${DEAD_AFTER_FAILURES})showDead();throw e;});
}
function POST(u,body){
  return F(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
}

/* ---- tabs ---- */
function showTab(name){
  tab = name; location.hash = name;
  var secs = document.querySelectorAll('section');
  for (var i=0;i<secs.length;i++) secs[i].className = (secs[i].id === 'tab-'+name) ? 'on' : '';
  var btns = document.querySelectorAll('nav button');
  for (var j=0;j<btns.length;j++) btns[j].className = (btns[j].getAttribute('data-tab')===name)?'on':'';
  if (name==='audit') pollAudit();
  if (name==='stats') pollStats();
  if (name==='sessions') pollSessions();
  if (name==='topology') pollTopology();
  if (name==='jobs') pollJobs();
  if (name==='assets') pollAssets();
  if (name==='settings') pollSettings();
}
var navBtns = document.querySelectorAll('nav button');
for (var b=0;b<navBtns.length;b++){
  (function(btn){btn.addEventListener('click',function(){showTab(btn.getAttribute('data-tab'));});})(navBtns[b]);
}
showTab(['terminal','assets','topology','jobs','audit','stats','sessions','settings'].indexOf(tab)>=0?tab:'audit');

/* ---- terminal ---- */
function renderChips(list){
  var el = $('sesschips');
  if (!list.length){ el.innerHTML = '<span style="color:#666">当前没有活动会话 —— 在对话里用 jumpserver 工具连接后，这里会出现实时终端。</span>'; return; }
  var exists = false;
  for (var i=0;i<list.length;i++) if (list[i].id===currentSess) exists = true;
  if (!exists) currentSess = list[0].id;
  el.innerHTML = list.map(function(s){
    var st = s.status || {};
    var label = labelId(s.id) + ' · ' + (st.state||'?') + (st.target? ' · '+st.target : '');
    return '<span class="sesschip'+(s.id===currentSess?' on':'')+'" data-id="'+esc(s.id)+'" title="'+esc(s.id)+'">'+esc(label)+'</span>';
  }).join('');
  var chips = el.querySelectorAll('.sesschip');
  for (var j=0;j<chips.length;j++){
    (function(ch){ch.addEventListener('click',function(){currentSess=ch.getAttribute('data-id');$('term').innerHTML='';termLines=0;renderChips(list);});})(chips[j]);
  }
}
function appendTerm(sess, events){
  if (sess !== currentSess) return;
  var box = $('term');
  var stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  for (var i=0;i<events.length;i++){
    var e = events[i]; var cls='t-out', txt='';
    if (e.type==='output'){cls='t-out';txt=stripAnsi(e.data);}
    else if (e.type==='input'){cls='t-in';txt='▸ '+stripAnsi(e.data);}
    else if (e.type==='state'){cls='t-sys';txt='── '+(e.prev||'?')+' → '+e.state;}
    else if (e.type==='target'){cls='t-sys';txt='── 进入 '+e.target+(e.hostname?(' ('+e.hostname+')'):'');}
    else if (e.type==='error'){cls='t-err';txt='!! '+e.message;}
    var div=document.createElement('div');div.className=cls;div.appendChild(document.createTextNode(txt));
    box.appendChild(div);termLines++;
  }
  while (termLines > ${TERMINAL_MAX_LINES} && box.firstChild){box.removeChild(box.firstChild);termLines--;}
  if (stick && $('autoscroll').checked) box.scrollTop = box.scrollHeight;
}
function pollTerminal(){
  if (tab!=='terminal'){setTimeout(pollTerminal,1000);return;}
  var min = Infinity;
  for (var k in trackedSeq) if (trackedSeq[k]<min) min=trackedSeq[k];
  F('/api/terminal?since='+(min===Infinity?0:min)).then(function(r){return r.json();}).then(function(j){
    var list=j.sessions||[];
    renderChips(list);
    for (var i=0;i<list.length;i++){
      var s=list[i];
      sessStatus[s.id]=s.status;
      var mine=(s.events||[]).filter(function(e){return e.seq>(trackedSeq[s.id]||0);});
      appendTerm(s.id,mine);
      trackedSeq[s.id]=s.lastSeq||trackedSeq[s.id]||0;
    }
    var st=sessStatus[currentSess];
    $('stat').textContent = st ? ('state='+st.state+' target='+(st.target||'none')+' mode='+st.permissionMode) : (list.length+' 会话');
  }).catch(function(){});
  setTimeout(pollTerminal,1000);
}
pollTerminal();
$('btn-clear').addEventListener('click',function(){$('term').innerHTML='';termLines=0;});
$('btn-interrupt').addEventListener('click',function(){
  POST('/api/interrupt',{sessionId:currentSess}).then(function(r){return r.json();}).then(function(j){
    alert(j.interrupted ? ('已发送 Ctrl+C；' + (j.verified ? 'Shell 已重新验证可用' : 'Shell 未能验证，已降级为 UNKNOWN')) : '当前没有可中断的活动会话');
  }).catch(function(){});
});

/* ---- assets (V0.4.1) ---- */
var assetData = null;
/* Activity: a target is "活跃" when the audit log mentions it in the last 30 min. */
function activeTargets(){
  var set = {}, cut = Date.now() - 30*60*1000;
  for (var i=0;i<auditAll.length;i++){
    var e = auditAll[i];
    var t = String(e.target || e.hostname || '');
    if (!t) continue;
    var ts = Date.parse(String(e.timestamp||''));
    if (!isNaN(ts) && ts >= cut) set[t] = true;
  }
  return set;
}
function fillSelect(id, values, allLabel){
  var el = $(id); if (!el) return;
  var cur = el.value;
  var html = '<option value="">'+esc(allLabel)+'</option>';
  values.sort().forEach(function(v){ html += '<option value="'+esc(v)+'">'+esc(v)+'</option>'; });
  el.innerHTML = html;
  if (values.indexOf(cur)>=0) el.value = cur;
}
function renderAssets(){
  var rows = $('assrows');
  if (!assetData || !assetData.assets || !assetData.assets.length){
    rows.innerHTML=''; $('assempty').style.display='block'; $('assmeta').textContent=''; return;
  }
  $('assempty').style.display='none';
  var q = ($('assq').value||'').toLowerCase();
  var gsel = $('assgroup').value, psel = $('assplatform').value, ssel = $('assstatus').value;
  var active = activeTargets();
  var roles = assetData.roles || {};
  var list = assetData.assets.filter(function(a){
    if (gsel && String(a.node||'') !== gsel) return false;
    if (psel && String(a.platform||'') !== psel) return false;
    var isActive = !!(a.ip && active[a.ip]) || !!(a.name && active[a.name]);
    if (ssel === 'active' && !isActive) return false;
    if (ssel === 'idle' && isActive) return false;
    if (q){
      var hay = [a.name,a.ip,a.platform,a.node,a.comment,a.raw].join(' ').toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  });
  rows.innerHTML = list.map(function(a){
    var isActive = !!(a.ip && active[a.ip]) || !!(a.name && active[a.name]);
    var role = roles[a.ip] || roles[a.name] || [];
    return '<tr>'
      + '<td style="color:#666">'+esc(a.index==null?'':a.index)+'</td>'
      + '<td>'+esc(a.name||'-')+'</td>'
      + '<td style="font-family:ui-monospace,Consolas,monospace">'+esc(a.ip||'-')+'</td>'
      + '<td>'+esc(a.platform||'-')+'</td>'
      + '<td>'+esc(a.node||'-')+'</td>'
      + '<td>'+esc(role.length?role.join(', '):'-')+'</td>'
      + '<td>'+(isActive?'<span style="color:#7ad17a">活跃</span>':'<span style="color:#888">未访问</span>')+'</td>'
      + '<td style="color:#999">'+esc(a.comment||'')+'</td>'
      + '</tr>';
  }).join('');
  $('assmeta').textContent = '共 ' + (assetData.assets.length) + ' 项 · 显示 ' + list.length + ' 项'
    + (assetData.updatedAt ? ' · 采集于 ' + fmtTime(new Date(assetData.updatedAt).toISOString()) : '')
    + (assetData.reportedTotal!=null ? ' · KoKo 报告总数 ' + assetData.reportedTotal : '');
  var bl = assetData.baselines || [];
  $('assbaselines').innerHTML = bl.length ? bl.map(function(n){return '<span class="sesschip">'+esc(n)+'</span>';}).join(' ') : '无（用 jumpserver_baseline_capture 创建）';
}
function pollAssets(){
  if (tab!=='assets') return;
  F('/api/assets').then(function(r){return r.json();}).then(function(j){
    assetData = j;
    var nodes = {}, plats = {};
    (j.assets||[]).forEach(function(a){ if(a.node) nodes[a.node]=1; if(a.platform) plats[a.platform]=1; });
    fillSelect('assgroup', Object.keys(nodes), '全部分组');
    fillSelect('assplatform', Object.keys(plats), '全部平台');
    renderAssets();
  }).catch(function(){});
}
['assq','assgroup','assplatform','assstatus'].forEach(function(id){
  var el = $(id); if (el) el.addEventListener('input', renderAssets);
});
var assRefresh = $('ass-refresh');
if (assRefresh) assRefresh.addEventListener('click', function(){ pollAssets(); });

/* ---- settings (V0.5.0) ---- */
function srcLabel(s){
  if (s==='env') return 'WorkBuddy 环境变量';
  if (s==='config') return 'config.json';
  return '默认值';
}
function srcChip(s){
  var color = s==='env' ? '#5c9' : (s==='config' ? '#7ab' : '#888');
  return '<span style="color:'+color+'">'+srcLabel(s)+'</span>';
}
function kvTable(rows){
  return '<table style="width:auto"><tbody>'+rows.map(function(r){
    return '<tr><td style="color:#999;padding:2px 16px 2px 0;vertical-align:top">'+esc(r[0])+'</td>'+
           '<td style="padding:2px 16px 2px 0">'+r[1]+'</td>'+
           '<td style="padding:2px 0">'+r[2]+'</td></tr>';
  }).join('')+'</tbody></table>';
}
function renderSettings(j){
  var c = j.connection;
  if (!c){
    $('setconn').innerHTML = '<span style="color:#666">控制台没有拿到连接信息（audit-only 模式）。</span>';
  } else {
    var pw = c.password.present ? '已配置' : '未配置';
    var rows = [
      ['JumpServer 地址', esc(c.host.value||'(未设置)'), srcChip(c.host.source)],
      ['SSH 端口', esc(c.port.value), srcChip(c.port.source)],
      ['用户名', esc(c.username.value||'(未设置)'), srcChip(c.username.source)],
      ['密码', esc(pw)+(c.password.via?' <span style="color:#666">('+esc(c.password.via)+')</span>':''), srcChip(c.password.source)]
    ];
    $('setconn').innerHTML = kvTable(rows) +
      '<div style="color:#777;font-size:12px;margin-top:8px">配置文件：'+esc(c.configPath)+
      (c.configPresent?' <span style="color:#7ab">已找到</span>':' <span style="color:#a86">不存在 —— 使用环境变量与默认值</span>')+'</div>';
  }
  var p = j.policy || {};
  var keys = Object.keys(p);
  $('setpolicy').innerHTML = keys.length ? kvTable(keys.map(function(k){
    var v = p[k];
    var text = Array.isArray(v) ? (v.length ? v.join(', ') : '（空）') : String(v);
    return [k, esc(text), ''];
  })) : '<span style="color:#666">无</span>';
  var h = (j.knownHosts && j.knownHosts.entries) || {};
  var hosts = Object.keys(h);
  if (!j.knownHosts || !j.knownHosts.path){
    $('sethosts').innerHTML = '<span style="color:#666">未配置 known_hosts 路径。</span>';
  } else if (!hosts.length){
    $('sethosts').innerHTML = '<span style="color:#666">暂无记录 —— 首次连接堡垒机时会记录其主机密钥（TOFU）。</span>'+
      '<div style="color:#777;font-size:12px;margin-top:6px">'+esc(j.knownHosts.path)+'</div>';
  } else {
    $('sethosts').innerHTML = kvTable(hosts.map(function(k){
      var r = h[k];
      return [k, '<span style="color:#8ab">'+esc(r.fingerprint)+'</span>', '<span style="color:#777">'+esc(r.algorithm||'')+' · '+esc(r.source)+'</span>'];
    })) + '<div style="color:#777;font-size:12px;margin-top:6px">'+esc(j.knownHosts.path)+'</div>';
  }
}
function pollSettings(){
  if (tab!=='settings') return;
  F('/api/settings').then(function(r){return r.json();}).then(function(j){ renderSettings(j); }).catch(function(){});
}
var setRefresh = $('set-refresh');
if (setRefresh) setRefresh.addEventListener('click', function(){ pollSettings(); });

/* ---- topology (V0.4.0) ---- */
function renderTopology(){
  if (!topo){ $('topometa').textContent='暂无拓扑数据：在对话里执行 jumpserver_topology（或 jumpserver_inspect）后这里会出现节点与关系。'; $('toponodes').innerHTML=''; $('topoedges').innerHTML=''; $('topodetail').textContent='点击节点查看详情'; return; }
  var nodes = topo.nodes||[], edges = topo.edges||[];
  $('topometa').textContent = '节点 ' + nodes.length + ' · 关系 ' + edges.length + ' · profiles ' + (topo.profiles||[]).join(',') +
    ' · 采集于 ' + fmtTime(new Date(topo.updatedAt).toISOString()) + ' · 耗时 ' + (topo.durationMs||0) + 'ms';
  $('toponodes').innerHTML = nodes.map(function(n){
    return '<div class="node'+(n.reachable?'':' dead')+(topoPick===n.target?' on':'')+'" data-t="'+esc(n.target)+'">'
      +'<div class="ip">'+esc(n.target)+'</div>'
      +'<div class="host">'+esc(n.hostname||'未知主机名')+'</div>'
      +'<div class="role">'+esc((n.roles||[]).join(', ')||'未识别')+'</div>'
      +'<div class="meta">端口 '+(n.ports&&n.ports.length?n.ports.join(','):'无')+' · '+(n.os||'未知系统')+'</div>'
      +'</div>';
  }).join('');
  var cards = $('toponodes').querySelectorAll('.node');
  for (var i=0;i<cards.length;i++){(function(c){c.addEventListener('click',function(){topoPick=c.getAttribute('data-t');renderTopology();});})(cards[i]);}
  if (topoPick){
    var n = null; for (var q=0;q<nodes.length;q++) if (nodes[q].target===topoPick) n=nodes[q];
    if (n){
      var ins = edges.filter(function(e){return e.to===n.target && e.type!=='same_upstream';});
      var outs = edges.filter(function(e){return e.from===n.target && e.type!=='same_upstream';});
      $('topodetail').textContent =
        n.target + (n.hostname?(' ('+n.hostname+')'):'') + '\\n'
        + '角色      ' + ((n.roles||[]).join(', ')||'未识别') + '\\n'
        + '系统      ' + (n.os||'?') + '  内核 ' + (n.kernel||'?') + '\\n'
        + '负载      ' + (n.load?n.load.join(' / '):'?') + '   内存 ' + (n.memoryUsedPct==null?'?':(n.memoryUsedPct+'%')) + '   核数 ' + (n.cores==null?'?':n.cores) + '\\n'
        + '端口      ' + ((n.ports||[]).join(', ')||'无') + '\\n'
        + 'IP        ' + ((n.ips||[]).join(', ')||'?') + '\\n'
        + '入向      ' + (ins.length? ins.map(function(e){return e.from+' → '+e.type+':'+(e.port||'?')+' ['+e.confidence+']';}).join('\\n          ') : '无') + '\\n'
        + '出向      ' + (outs.length? outs.map(function(e){return e.type+':'+(e.port||'?')+' → '+e.to+' ['+e.confidence+']';}).join('\\n          ') : '无');
    }
  } else { $('topodetail').textContent='点击节点查看详情'; }
  $('topoedges').innerHTML = edges.length ? edges.map(function(e){
    return '<div style="padding:4px 0;border-bottom:1px solid #222">'
      +'<span style="color:#fff">'+esc(e.from)+'</span> ──▶ <span style="color:#fff">'+esc(e.to)+'</span> '
      +'<span class="badge">'+esc(e.type)+'</span> :'+esc(e.port==null?'?':e.port)+' '
      +'<span class="badge '+esc(e.confidence)+'">'+esc(e.confidence)+'</span><br>'
      +'<span class="ev">'+esc((e.evidence||[]).join(' · '))+'</span></div>';
  }).join('') : '<span style="color:#666">没有发现节点间关系（可能需要 network/web profile，或这些主机之间没有直接连接）</span>';
}
function pollTopology(){
  if (tab!=='topology') return;
  F('/api/topology').then(function(r){return r.json();}).then(function(j){
    topo = j && j.nodes ? j : null;
    renderTopology();
  }).catch(function(){});
}
$('topo-refresh').addEventListener('click',pollTopology);
setInterval(pollTopology,3000);

/* ---- jobs (V0.4.0) ---- */
function renderJobs(list){
  $('jrows').innerHTML = list.length ? list.map(function(j){
    var pct = j.maxDurationMs ? Math.min(100, Math.round((Date.now()-j.startedAt)/j.maxDurationMs*100)) : 0;
    return '<tr data-id="'+esc(j.id)+'"><td>'+esc(j.id)+'</td>'
      +'<td class="tgt">'+esc(j.target)+(j.hostname?(' ('+esc(j.hostname)+')'):'')+'</td>'
      +'<td class="state-'+esc(j.state)+'">'+esc(j.state)+'</td>'
      +'<td><div class="jobbar"><i style="width:'+pct+'%"></i></div><span class="time">'+Math.round((Date.now()-j.startedAt)/1000)+'s / '+Math.round(j.maxDurationMs/1000)+'s</span></td>'
      +'<td class="cmd">'+esc(j.command)+'</td>'
      +'<td>'+(j.state==='RUNNING'?'<button class="act warn" data-stop="'+esc(j.id)+'">停止</button>':'')+'</td></tr>';
  }).join('') : '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">没有任务 —— 在对话里用 jumpserver_job_start 启动 tail -f / journalctl -f 一类的流式命令</td></tr>';
  var rows=$('jrows').querySelectorAll('tr[data-id]');
  for (var i=0;i<rows.length;i++){(function(r){r.addEventListener('click',function(){jobPick=r.getAttribute('data-id');showJobOut(list);});})(rows[i]);}
  var stops=$('jrows').querySelectorAll('button[data-stop]');
  for (var s=0;s<stops.length;s++){(function(btn){btn.addEventListener('click',function(ev){
    ev.stopPropagation();
    POST('/api/jobs/stop',{id:btn.getAttribute('data-stop')}).then(function(){pollJobs();}).catch(function(){});
  });})(stops[s]);}
  showJobOut(list);
}
function showJobOut(list){
  var j=null; for (var i=0;i<list.length;i++) if (list[i].id===jobPick) j=list[i];
  $('jobout').textContent = j ? ('# ' + j.id + '  ' + j.target + '  [' + j.state + ']\\n\\n' + (j.output||'(无输出)')) : '点击一行查看输出';
}
function pollJobs(){
  if (tab!=='jobs') return;
  F('/api/jobs').then(function(r){return r.json();}).then(function(list){renderJobs(list||[]);}).catch(function(){});
}
$('jobs-refresh').addEventListener('click',pollJobs);
setInterval(pollJobs,1000);

/* ---- audit ---- */
function renderAudit(){
  var q=$('filter').value.toLowerCase();
  var list=q?auditAll.filter(function(e){return JSON.stringify(e).toLowerCase().indexOf(q)>=0;}):auditAll;
  var rows=list.slice().reverse().map(function(e){
    var tgt=e.target||e.hostname||'-';
    var cmd=e.redactedCommand||e.command||'-';
    var risk=esc(e.risk||'?');
    // V0.4.3: result carries commandStatus. A COMPLETED exchange with a
    // non-zero exit is a FAILED command and must not look healthy.
    var status=String(e.result||'?');
    var exitN=e.exitCode;
    var bad=(status!=='SUCCESS'&&status!=='COMPLETED'&&status!=='ok'&&status!=='RUNNING'&&status!=='')
      || (typeof exitN==='number'&&exitN!==0);
    return '<tr><td class="time">'+esc(fmtTime(e.timestamp))+'</td>'
      +'<td class="op">'+esc(e.operation)+'</td>'
      +'<td class="tgt" title="'+esc(tgt)+'">'+esc(tgt)+'</td>'
      +'<td class="risk risk-'+risk+'">'+risk+' / '+esc(status)+(bad?' <span class="bad">exit '+esc(String(exitN!=null?exitN:'?'))+'</span>':'')+'</td>'
      +'<td class="cmd">'+esc(cmd)+'</td></tr>';
  }).join('');
  $('rows').innerHTML=rows;
  $('empty').style.display=list.length?'none':'block';
  $('stat').textContent='审计 '+auditAll.length+' 条'+(q?' / 匹配 '+list.length:'');
  lastCount=auditAll.length;
}
function pollAudit(){
  if (tab!=='audit') return;
  F('/api/entries').then(function(r){return r.json();}).then(function(j){
    if (j.length!==auditAll.length){auditAll=j;renderAudit();}else{auditAll=j;}
  }).catch(function(){});
}
setInterval(pollAudit,1000);
$('filter').addEventListener('input',renderAudit);
function download(name,mime,text){
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([text],{type:mime}));
  a.download=name;a.click();URL.revokeObjectURL(a.href);
}
$('exp-jsonl').addEventListener('click',function(){
  download('jumpserver-audit.jsonl','application/json',auditAll.map(function(e){return JSON.stringify(e);}).join('\\n'));
});
$('exp-csv').addEventListener('click',function(){
  var cols=['timestamp','operation','actor','target','hostname','risk','result','exitCode','durationMs','toolCallId','batchId','taskId','redactedCommand'];
  var q=function(v){v=v==null?'':String(v);return /[",\\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  var lines=[cols.join(',')];
  auditAll.forEach(function(e){lines.push(cols.map(function(c){return q(e[c]);}).join(','));});
  download('jumpserver-audit.csv','text/csv','\\ufeff'+lines.join('\\n'));
});

/* ---- stats ---- */
function bars(el,rows){
  if (!rows.length){el.innerHTML='<span style="color:#666">暂无数据</span>';return;}
  var max=rows[0][1]||1;
  el.innerHTML=rows.map(function(r){
    return '<div class="bar"><span class="lab" title="'+esc(r[0])+'">'+esc(r[0])+'</span>'
      +'<span class="track"><span class="fill" style="width:'+Math.round(r[1]/max*100)+'%"></span></span>'
      +'<span class="cnt">'+r[1]+'</span></div>';
  }).join('');
}
function topN(map,n){
  var arr=[];for (var k in map) arr.push([k,map[k]]);
  arr.sort(function(a,b){return b[1]-a[1];});
  return arr.slice(0,n||10);
}
function pollStats(){
  if (tab!=='stats') return;
  F('/api/stats').then(function(r){return r.json();}).then(function(s){
    var fail=s.failed||0;
    $('cards').innerHTML=
      '<div class="card"><div class="n">'+s.total+'</div><div class="l">审计总数</div></div>'
      +'<div class="card"><div class="n" style="color:'+(fail?'#e8a86a':'#7fc98f')+'">'+fail+'</div><div class="l">失败 / 受阻</div></div>'
      +'<div class="card"><div class="n">'+s.targets+'</div><div class="l">涉及资产</div></div>'
      +'<div class="card"><div class="n">'+s.days+'</div><div class="l">活跃天数</div></div>';
    bars($('by-target'),topN(s.byTarget,10));
    bars($('by-risk'),topN(s.byRisk,10));
    bars($('by-op'),topN(s.byOperation,10));
    bars($('by-day'),s.byDay.slice(-14));
  }).catch(function(){});
}
setInterval(pollStats,3000);

/* ---- sessions ---- */
function pollSessions(){
  if (tab!=='sessions') return;
  F('/api/sessions').then(function(r){return r.json();}).then(function(list){
    $('srows').innerHTML = list.length ? list.map(function(s){
      var st=s.status||{};
      return '<tr><td title="'+esc(s.id)+'">'+esc(labelId(s.id))+'</td>'
        +'<td>'+esc(st.state||'?')+'</td>'
        +'<td class="tgt">'+esc(st.target||'-')+(st.hostname?' ('+esc(st.hostname)+')':'')+'</td>'
        +'<td>'+esc(st.permissionMode||'-')+'</td>'
        +'<td class="time">'+fmtTime(new Date(s.lastUsedAt).toISOString())+'</td>'
        +'<td><button class="act" data-int="'+esc(s.id)+'">中断</button> <button class="act warn" data-id="'+esc(s.id)+'">断开</button></td></tr>';
    }).join('') : '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">无活动会话</td></tr>';
    var btns=$('srows').querySelectorAll('button[data-id]');
    for (var i=0;i<btns.length;i++){
      (function(btn){btn.addEventListener('click',function(){
        if (!confirm('断开该会话？')) return;
        POST('/api/sessions/close',{sessionId:btn.getAttribute('data-id')})
          .then(function(){pollSessions();}).catch(function(){});
      });})(btns[i]);
    }
    var ints=$('srows').querySelectorAll('button[data-int]');
    for (var k=0;k<ints.length;k++){
      (function(btn){btn.addEventListener('click',function(){
        POST('/api/interrupt',{sessionId:btn.getAttribute('data-int')}).then(function(r){return r.json();}).then(function(j){
          alert(j.interrupted ? ('已发送 Ctrl+C；' + (j.verified ? 'Shell 已重新验证可用' : 'Shell 未能验证，已降级为 UNKNOWN')) : '该会话当前不可中断');
          pollSessions();
        }).catch(function(){});
      });})(ints[k]);
    }
  }).catch(function(){});
}
setInterval(pollSessions,2000);
$('close-all').addEventListener('click',function(){
  if (!confirm('断开全部 JumpServer 会话？')) return;
  POST('/api/sessions/close',{all:true}).then(function(){pollSessions();}).catch(function(){});
});
$('interrupt-all').addEventListener('click',function(){
  POST('/api/interrupt',{}).then(function(r){return r.json();}).then(function(j){
    alert('已向 '+(j.interrupted||0)+' 个会话发送 Ctrl+C');
  }).catch(function(){});
});
</script></body></html>`
}

function sendJson(res: import('node:http').ServerResponse, data: unknown): void {
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(data))
}

function readBody(req: import('node:http').IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let text = ''
    req.on('data', (chunk: Buffer) => {
      text += chunk.toString('utf8')
      if (text.length > 65536) req.destroy()
    })
    req.on('end', () => {
      try {
        resolve(JSON.parse(text) as Record<string, unknown>)
      } catch {
        resolve({})
      }
    })
    req.on('error', () => resolve({}))
  })
}

function lastSeqOf(events: TerminalEvent[]): number {
  return events.length > 0 ? (events[events.length - 1]?.seq ?? 0) : 0
}

/**
 * V0.4.3: connector-internal bookkeeping the user must never see in the live
 * terminal — the `__dsh_rc=$?` capture line, the completion/probe markers, and
 * the printf wrapper that prints them.
 *
 * This is a DISPLAY filter only. The raw events stay in the ring buffer and in
 * the audit JSONL, so the evidence trail an investigator needs is intact.
 */
const INTERNAL_MARKER_LINE = /^\s*(__dsh_rc=|printf\s+'?\\n?__DSH_JS_(DONE|PROBE)|__DSH_JS_(DONE|PROBE)(_END)?_)/

export function stripInternalMarkers(event: TerminalEvent): TerminalEvent {
  if (event.type !== 'output' && event.type !== 'input') return event
  const data = event.data
  if (!data.includes('__dsh_rc') && !data.includes('__DSH_JS_')) return event
  const kept = data
    .split('\n')
    .filter((line) => !INTERNAL_MARKER_LINE.test(line) && !line.includes('__DSH_JS_') && !line.includes('__dsh_rc'))
    .join('\n')
  return { ...event, data: kept }
}

/**
 * V0.4.1: project the last topology into a target -> roles map so the 资产 tab
 * can render a 角色 column. Tolerant of the loosely-typed stored node shape:
 * a node without roles simply does not appear.
 */
function topologyRoles(store: TopologyStore | null): Record<string, string[]> {
  const current = store?.get() ?? null
  if (current === null) return {}
  const out: Record<string, string[]> = {}
  for (const node of current.nodes) {
    if (typeof node !== 'object' || node === null) continue
    const record = node as { id?: unknown; target?: unknown; roles?: unknown }
    const key = typeof record.target === 'string' ? record.target : typeof record.id === 'string' ? record.id : null
    if (key === null) continue
    const roles = Array.isArray(record.roles) ? record.roles.filter((r): r is string => typeof r === 'string') : []
    if (roles.length > 0) out[key] = roles
  }
  return out
}

/**
 * There is NO browser launch here on purpose. A MCP server runs as a detached
 * child process: any shell-open it performs lands in the OS default browser
 * (Chrome/Edge), not in the WorkBuddy preview panel. The only available path is
 * a handover to the model — see consoleHintForModel() — which then opens the
 * URL through the host's own preview surface.
 */

/**
 * Instruction block handed to the model on a tool response. `present_files`
 * with a localhost URL opens the WorkBuddy built-in preview panel — that is
 * the ONLY way to surface this console in-app.
 *
 * V0.5.1: emitted repeatedly until the page has been fetched once (see
 * withConsoleHint), and worded to pre-empt the "present_files reports my final
 * result" reading that made the model park the URL until the task was over.
 */
export function consoleHintForModel(): string | null {
  const url = auditViewerUrl()
  if (url === null || hintEnabled !== true) return null
  hintEmitted += 1
  return (
    '[jumpserver-console] JumpServer 工作台（实时终端 / 资产 / 拓扑 / 任务 / 审计 / 统计 / 会话 / 设置）: ' + url + '\n' +
    '这是「启动阶段」的界面交接，不是任务结果汇报 —— 请在执行第一条远程命令之前就调用 present_files 打开它。' +
    '等到任务快结束才打开就晚了：那时进程可能已经退出，页面只会显示「工作台已失效」。\n' +
    '地址固定（V0.5.1 起不含令牌、也不随进程退出而失效），可以直接打开或收藏。\n' +
    '禁止改用系统浏览器打开（不要 rundll32 / start / explorer / 外部浏览器）。'
  )
}

/** V0.5.1: true while a console exists that no browser has opened yet. */
export function consoleHintPending(): boolean {
  return hintEnabled === true && viewerUrl !== null && consoleOpened !== true && hintEmitted < CONSOLE_NAG_LIMIT
}

/**
 * Start the embedded console. Returns the intended URL, or null when disabled.
 * `registry` powers the live-terminal / session tabs; pass null for an
 * audit-only mirror. When the configured port is taken and portFallback is
 * on, an ephemeral port is used so every conversation keeps its own console.
 */
export function startAuditViewer(
  auditPath: string,
  opts: AuditViewerOptions,
  registry: SessionRegistry | null,
  services: AuditViewerServices = {},
): string | null {
  if (opts.enabled !== true) return null
  hintEnabled = opts.autoOpen
  stableAddress = opts.stableUrl !== false
  consoleOpened = false
  hintEmitted = 0
  consoleBound = false
  consoleDir = join(dirname(auditPath), 'consoles')
  consoleStartedAt = new Date().toISOString()
  const ttlMinutes = opts.tokenTtlMinutes
  // undefined => keep the 12h default; an explicit 0 disables expiry.
  consoleTokenTtlMs = ttlMinutes === undefined || !Number.isFinite(ttlMinutes) || ttlMinutes <= 0 ? (ttlMinutes === 0 ? 0 : 12 * 60 * 60 * 1000) : ttlMinutes * 60_000
  rotateConsoleToken()
  const audit = services.audit ?? null
  const assets = services.assets ?? null
  const baselines = services.baselines ?? null
  const timeZone = services.timeZone ?? 'Asia/Shanghai'
  const server = http.createServer((req, res) => {
    void (async () => {
      const target = req.url ?? '/'
      const href = target.split('?')[0] ?? '/'
      const query = new URLSearchParams(target.split('?')[1] ?? '')
      // V0.4.1: /api/* must present the token (query or header).
      // V0.4.2: an expired token is rejected with a distinct marker so the page
      // can show "console expired" instead of a generic failure.
      // V0.5.1: in stable-address mode `GET /` is exempt — the page is static
      // and carries no audit data, and it receives the token as an injected
      // constant rather than a query parameter. Cross-origin callers are still
      // refused outright, so a web page in the local browser cannot read the
      // audit trail or reach /api/interrupt.
      const presented = query.get('token') ?? (typeof req.headers[TOKEN_HEADER] === 'string' ? (req.headers[TOKEN_HEADER] as string) : null)
      const isPageLoad = (req.method === 'GET' || req.method === 'HEAD') && (href === '/' || href === '/index.html')
      const origin = req.headers['origin']
      const reqHost = typeof req.headers['host'] === 'string' ? (req.headers['host'] as string) : ''
      const crossOrigin =
        typeof origin === 'string' && origin.length > 0 && origin !== 'http://' + reqHost && origin !== 'https://' + reqHost
      const pageExempt = stableAddress && isPageLoad && !crossOrigin
      if (!pageExempt && !tokenMatches(presented)) {
        const expired = consoleTokenExpired()
        res.statusCode = 403
        res.setHeader('content-type', 'text/plain; charset=utf-8')
        if (expired) res.setHeader('x-console-token-expired', '1')
        res.end(expired ? 'console token expired: reload the page to get a fresh one' : 'forbidden: missing or invalid console token')
        return
      }
      const entries = (): Record<string, unknown>[] => (audit !== null ? audit.list() : readAuditEntries(auditPath))
      if (href === '/api/entries') {
        sendJson(res, entries())
        return
      }
      if (href === '/api/stats') {
        const list = entries()
        const byRisk: Record<string, number> = {}
        const byOperation: Record<string, number> = {}
        const byTarget: Record<string, number> = {}
        const byDayMap: Record<string, number> = {}
        let failed = 0
        for (const e of list) {
          const risk = String(e['risk'] ?? '?')
          const op = String(e['operation'] ?? '?')
          const targetName = String(e['target'] ?? e['hostname'] ?? '(未进入资产)')
          const day = String(e['timestamp'] ?? '').slice(0, 10)
          byRisk[risk] = (byRisk[risk] ?? 0) + 1
          byOperation[op] = (byOperation[op] ?? 0) + 1
          byTarget[targetName] = (byTarget[targetName] ?? 0) + 1
          if (day.length > 0) byDayMap[day] = (byDayMap[day] ?? 0) + 1
          const approvalPending = e['approvalRequired'] === true && String(e['approvalResult']) === 'pending'
          // V0.4.3: `result` now carries commandStatus (SUCCESS/EXIT_NONZERO/
          // TIMEOUT/...). Judging failure on result !== 'COMPLETED' alone hid
          // real failures: `jps -lv` exiting 127 was recorded COMPLETED and
          // counted as healthy. Fall back to the exit code so older records
          // (pre-V0.4.3) are still classified correctly.
          const status = String(e['result'] ?? '')
          const exitCode = e['exitCode']
          const statusFailed = status !== '' && status !== 'SUCCESS' && status !== 'COMPLETED' && status !== 'ok' && status !== 'RUNNING'
          const exitFailed = typeof exitCode === 'number' && exitCode !== 0
          if (statusFailed || exitFailed || approvalPending) failed += 1
        }
        const byDay = Object.keys(byDayMap).sort().map((d) => [d.slice(5), byDayMap[d] ?? 0] as [string, number])
        sendJson(res, {
          total: list.length,
          failed,
          targets: Object.keys(byTarget).length,
          days: byDay.length,
          byRisk,
          byOperation,
          byTarget,
          byDay,
        })
        return
      }
      if (href === '/api/assets') {
        const snapshot = assets?.get() ?? null
        if (snapshot === null) {
          sendJson(res, { updatedAt: null, assets: [], baselines: baselines?.list() ?? [], roles: {} })
          return
        }
        sendJson(res, {
          updatedAt: snapshot.updatedAt,
          filter: snapshot.filter,
          group: snapshot.group,
          reportedTotal: snapshot.reportedTotal,
          health: snapshot.health,
          assets: snapshot.assets,
          baselines: baselines?.list() ?? [],
          // V0.4.1: role hints from the last topology, so the 资产 tab can show a
          // 角色 column without the console ever touching the bastion.
          roles: topologyRoles(services.topology ?? null),
        })
        return
      }
      if (href === '/api/sessions') {
        if (registry === null) {
          sendJson(res, [])
          return
        }
        const list: unknown[] = []
        for (const [id, bundle] of registry.snapshot()) {
          list.push({ id, status: bundle.manager.status(), lastUsedAt: bundle.lastUsedAt, lastSeq: lastSeqOf(bundle.observer.snapshot()) })
        }
        sendJson(res, list)
        return
      }
      if (href === '/api/sessions/close' && req.method === 'POST') {
        if (registry === null) {
          sendJson(res, { closed: 0 })
          return
        }
        const body = await readBody(req)
        let closed = 0
        const ids: string[] = body['all'] === true
          ? [...registry.snapshot().keys()]
          : [String(body['sessionId'] ?? '')]
        await Promise.all(ids.map(async (id) => {
          const bundle = registry.get(id)
          if (bundle === undefined) return
          try {
            await bundle.manager.close()
            closed += 1
          } catch {
            /* close failures must not 500 the console */
          }
        }))
        sendJson(res, { closed })
        return
      }
      // V0.4.0: out-of-band Ctrl+C — reaches the remote shell even mid-command.
      if (href === '/api/interrupt' && req.method === 'POST') {
        if (registry === null) {
          sendJson(res, { interrupted: 0, verified: false })
          return
        }
        const body = await readBody(req)
        const only = typeof body['sessionId'] === 'string' && body['sessionId'].length > 0 ? body['sessionId'] : null
        let interrupted = 0
        let verified = false
        let jobsStopped = 0
        for (const [id, bundle] of registry.snapshot()) {
          if (only !== null && id !== only) continue
          // V0.4.5: the console uses the SAME single-entry interrupt as the
          // MCP tool. Previously it called manager.interrupt() and THEN
          // jobs.stopAll(), which sent two Ctrl+C to a streaming job.
          const outcome = await interruptSession(services.jobs, bundle.manager, id, 'console interrupt')
          if (outcome.sent) interrupted += 1
          if (outcome.verified) verified = true
          jobsStopped += outcome.jobsStopped
        }
        sendJson(res, { interrupted, verified, jobsStopped })
        return
      }
      if (href === '/api/terminal') {
        if (registry === null) {
          sendJson(res, { sessions: [] })
          return
        }
        const since = Math.max(0, Math.floor(Number(query.get('since') ?? '0')) || 0)
        const sessions: unknown[] = []
        for (const [id, bundle] of registry.snapshot()) {
          let events = bundle.observer.snapshotSince(since)
          if (events.length > TERMINAL_TAIL_EVENTS) events = events.slice(-TERMINAL_TAIL_EVENTS)
          // V0.4.3: the live terminal is a USER view. The connector's own
          // bookkeeping (`__dsh_rc`, __DSH_JS_DONE_/PROBE_ markers and the
          // printf wrapper) is stripped here — the raw events stay in the ring
          // buffer and the audit JSONL, so the evidence trail is untouched.
          events = events.map(stripInternalMarkers)
          sessions.push({ id, status: bundle.manager.status(), lastSeq: lastSeqOf(bundle.observer.snapshot()), events })
        }
        sendJson(res, { sessions })
        return
      }
      if (href === '/api/settings') {
        // V0.5.0: one read for the 设置 tab. The connection view carries the
        // password SOURCE only; no credential value is ever serialized here.
        const conn = services.connection !== undefined && services.connection !== null
          ? services.connection()
          : null
        const policy = services.policy !== undefined && services.policy !== null ? services.policy() : {}
        const knownHosts = services.knownHosts !== undefined && services.knownHosts !== null
          ? services.knownHosts()
          : { entries: {} }
        sendJson(res, { connection: conn, policy, knownHosts })
        return
      }
      if (href === '/api/topology') {
        sendJson(res, services.topology?.get() ?? { nodes: [], edges: [], warnings: [] })
        return
      }
      if (href === '/api/jobs') {
        sendJson(res, services.jobs !== null && services.jobs !== undefined ? services.jobs.list() : [])
        return
      }
      if (href === '/api/jobs/stop' && req.method === 'POST') {
        if (services.jobs === null || services.jobs === undefined) {
          sendJson(res, { stopped: false })
          return
        }
        const body = await readBody(req)
        const id = String(body['id'] ?? '')
        try {
          const job = await services.jobs.stop(id)
          sendJson(res, { stopped: true, state: job.state })
        } catch {
          sendJson(res, { stopped: false })
        }
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(page(timeZone, consoleToken ?? ''))
      // V0.5.1: the page has been fetched — stop nagging the model about it.
      consoleOpened = true
    })().catch(() => {
      try {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end('console error')
      } catch {
        /* response already gone */
      }
    })
  })
  consoleRequestedPort = opts.port
  // V0.5.1: a random fallback port is what made handover URLs go stale, so it
  // only applies in the legacy (token-in-URL) mode.
  const allowEphemeralFallback = opts.portFallback !== false && !stableAddress
  server.on('error', (error) => {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'EADDRINUSE') {
      if (allowEphemeralFallback) {
        // Legacy mode: another conversation holds the configured port — take an
        // ephemeral one so THIS conversation keeps its own live console.
        try {
          server.listen(0, '127.0.0.1')
        } catch {
          console.error('[jumpserver-mcp] ops console: fallback listen failed')
        }
        return
      }
      // Stable mode: the address is shared on purpose. Hand over the SAME URL
      // the owner serves, and let the heartbeat take the listener over as soon
      // as that process exits.
      viewerUrl = consoleUrl(opts.port)
      if (!consoleAdoptLogged) {
        consoleAdoptLogged = true
        console.error(
          '[jumpserver-mcp] ops console: 127.0.0.1:' +
            String(opts.port) +
            ' is already served by another MCP process; adopting that address (will take over when it exits)',
        )
      }
      return
    }
    console.error('[jumpserver-mcp] ops console: ' + (error instanceof Error ? error.message : String(error)))
  })
  server.on('listening', () => {
    consoleBound = true
    consoleAdoptLogged = false
    const address = server.address()
    const port = typeof address === 'object' && address !== null ? address.port : opts.port
    consolePort = port
    consoleStartedAt = new Date().toISOString()
    viewerUrl = consoleUrl(port)
    if (port !== opts.port) {
      console.error('[jumpserver-mcp] ops console: port ' + String(opts.port) + ' busy, using port ' + String(port))
    } else {
      console.error('[jumpserver-mcp] ops console: ' + viewerUrl)
    }
    writeConsoleFile()
  })
  server.on('close', () => {
    consoleBound = false
  })
  startHeartbeat()
  try {
    server.listen(opts.port, '127.0.0.1')
  } catch (error) {
    console.error('[jumpserver-mcp] ops console: ' + (error instanceof Error ? error.message : String(error)))
  }
  server.unref?.()
  consoleServer = server
  return consoleUrl(opts.port)
}

/**
 * V0.4.4: tear the console down so tests can run one per case without
 * leaking HTTP listeners and heartbeat intervals. Production code leaves
 * the console running for the life of the MCP process; this is purely a
 * test seam.
 */
export function stopAuditViewer(): void {
  if (consoleHeartbeatTimer !== null) {
    clearInterval(consoleHeartbeatTimer)
    consoleHeartbeatTimer = null
  }
  if (consoleFile !== null) {
    try { unlinkSync(consoleFile) } catch { /* already gone */ }
    consoleFile = null
  }
  if (consoleServer !== null) {
    try { consoleServer.close() } catch { /* already closed */ }
    consoleServer = null
  }
  // V0.5.0: the exit handler registered by startHeartbeat() has to come off
  // with the console. startHeartbeat() registers with process.once(), and each
  // registration is a NEW wrapper, so repeated start/stop cycles in one process
  // accumulate listeners until Node emits a MaxListenersExceededWarning. The
  // V0.4.4 comment claimed this removal already happened; it did not.
  process.removeListener('exit', onProcessExit)
  viewerUrl = null
  consoleDir = null
  consolePort = 0
  consoleToken = null
  consoleTokenExpiresAt = null
  // V0.5.1 state, so a following startAuditViewer() begins clean.
  consoleBound = false
  consoleAdoptLogged = false
  consoleRequestedPort = 0
  consoleOpened = false
  hintEmitted = 0
}

/**
 * V0.4.1: the console URL carries the access token.
 * V0.5.1: in stable mode the token moves into the served page instead, so the
 * address is short, bookmarkable and identical in every process.
 */
function consoleUrl(port: number): string {
  const base = 'http://127.0.0.1:' + String(port) + '/'
  if (stableAddress) return base
  return consoleToken !== null ? base + '?token=' + consoleToken : base
}

/**
 * Heartbeat a per-process discovery file:
 *   data/consoles/<pid>.json = { pid, port, startedAt, heartbeatAt, tokenExpiresAt }
 * Stale files (heartbeat older than 20s => the conversation/process is gone)
 * are pruned, so external tools can enumerate live consoles by listing the dir.
 *
 * V0.4.3 SECURITY: the file must NEVER contain the tokenized URL. Any local
 * process (or a sync agent watching the workspace) could otherwise read the
 * token off disk and reach the console, defeating the token entirely. The
 * token lives only in this process's memory and is handed to the user through
 * the MCP response (consoleHintForModel).
 */
function writeConsoleFile(): void {
  if (consoleFile === null || consolePort <= 0) return
  try {
    writeFileSync(consoleFile, JSON.stringify({
      pid: process.pid,
      port: consolePort,
      startedAt: consoleStartedAt,
      heartbeatAt: new Date().toISOString(),
      tokenExpiresAt: consoleTokenExpiresAt !== null ? new Date(consoleTokenExpiresAt).toISOString() : null,
    }) + '\n', 'utf8')
  } catch {
    /* discovery file is best-effort */
  }
}

/**
 * V0.4.4: heartbeat timer + discovery file registration, independent of whether
 * this process owns the listener.
 * V0.5.1: started BEFORE the bind attempt, because when the address is already
 * served by another process the same timer drives the takeover retry.
 */
function startHeartbeat(): void {
  if (consoleDir === null) return
  try {
    mkdirSync(consoleDir, { recursive: true })
    consoleFile = join(consoleDir, String(process.pid) + '.json')
  } catch {
    return
  }
  const timer = setInterval(() => {
    if (consolePort > 0) writeConsoleFile()
    pruneStale()
    attemptConsoleTakeover()
  }, 5_000)
  timer.unref?.()
  consoleHeartbeatTimer = timer
  process.once('exit', onProcessExit)
}

/**
 * V0.5.1: in stable mode the console address outlives any single process. If
 * another MCP held it at boot we adopted its URL; because we then own no
 * listener, keep probing so this process serves that same address the moment
 * it frees up — an already-open page recovers without the user doing anything.
 */
function attemptConsoleTakeover(): void {
  if (consoleBound) return
  const server = consoleServer
  if (server === null) return
  try {
    server.listen(consoleRequestedPort, '127.0.0.1')
  } catch {
    /* still busy, or shutting down — the next tick retries */
  }
}

/**
 * Named exit handler so stopAuditViewer() can remove it: `process.once()` with
 * an anonymous arrow would be unreachable afterwards, and each registration
 * wraps the handler afresh — hence the explicit removeListener on teardown.
 */
function onProcessExit(): void {
  if (consoleFile !== null) {
    try { unlinkSync(consoleFile) } catch { /* already gone */ }
  }
}

function pruneStale(): void {
  if (consoleDir === null) return
  try {
    const names = readdirSync(consoleDir)
    const now = Date.now()
    for (const name of names) {
      if (!name.endsWith('.json')) continue
      const file = join(consoleDir, name)
      try {
        const raw = JSON.parse(readFileSync(file, 'utf8')) as { heartbeatAt?: string }
        const age = now - Date.parse(raw.heartbeatAt ?? '')
        if (!Number.isFinite(age) || age > 20_000) unlinkSync(file)
      } catch {
        try {
          unlinkSync(file)
        } catch {
          /* concurrent delete */
        }
      }
    }
  } catch {
    /* console dir may not exist yet */
  }
}

/** Audit hook kept for API compatibility: console opening is model-driven now. */
export function notifyAuditRecord(): void {
  /* no-op: see consoleHintForModel() */
}

/** Current console URL (null until the listener is bound / when disabled). */
export function auditViewerUrl(): string | null {
  return viewerUrl
}

/**
 * V0.4.2: issue a fresh token for a running console and return the new URL.
 * The previous token stops working immediately, so the caller must hand the new
 * URL to the user. Returns null when no console is running.
 */
export function rotateConsoleAccessToken(): string | null {
  // V0.5.1: not gated on consolePort — in stable mode a process that adopted
  // another's address still owns a token and must be able to rotate it.
  if (consoleToken === null) return null
  rotateConsoleToken()
  return viewerUrl
}

/** V0.4.2: token lifetime + expiry, for status output. */
export function consoleTokenInfo(): { ttlMinutes: number; expiresAt: string | null; expired: boolean } {
  return {
    ttlMinutes: consoleTokenTtlMs > 0 ? Math.round(consoleTokenTtlMs / 60_000) : 0,
    expiresAt: consoleTokenExpiresAt !== null ? new Date(consoleTokenExpiresAt).toISOString() : null,
    expired: consoleTokenExpired(),
  }
}

/**
 * V0.4.2: force the current token past its expiry. Exported for tests so the
 * expiry path can be exercised without waiting out a real TTL.
 */
export function forceExpireConsoleToken(): void {
  if (consoleToken === null) return
  consoleTokenExpiresAt = Date.now() - 1
}
