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
import { basename, dirname, join } from 'node:path'
import type { SessionRegistry } from '../jumpserver/session-registry.js'
import type { TerminalEvent } from '../jumpserver/terminal-observer.js'
import { DEFAULT_AUDIT_RING_SIZE, type AuditStore } from './audit-store.js'
import type { JobStore } from './job-store.js'
import type { TopologyStore } from './topology-store.js'
import type { AssetStore } from './asset-store.js'
import type { BaselineStore } from './baseline-store.js'
import type { ConnectionView } from '../config/env.js'
import { interruptSession } from './interrupt.js'
import { consoleTabSources, resolveConsoleTabs, type ConsoleTabSource } from './console-tabs.js'
import { CONSOLE_TAB_IDS, type ConsoleTabId } from '../config/types.js'
import { computeAuditStats } from './audit-metrics.js'
import { consoleAddressFor, isPinLive, stalePinFallback } from './console-address.js'

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
  /**
   * V0.5.10: `config.json` auditViewer.tabs — which navigation tabs the console
   * shows. Absent means "all of them" (resolveConsoleTabs' empty-config rule),
   * so an audit-only mirror never has to think about it.
   *
   * This is a visibility switch, NOT an access-control one: the hidden tab's
   * /api route, its section markup and the audit sink all stay exactly as they
   * are. See src/runtime/console-tabs.ts.
   */
  consoleTabs?: (() => Partial<Record<ConsoleTabId, boolean>>) | null
  /**
   * V0.5.13: the console's OWN tab preferences (console-prefs.json), written
   * by the switches in the 设置 tab. Kept separate from `consoleTabs` so the two
   * layers stay distinguishable: config.json pins a tab (and the UI shows it
   * locked), this one is what the operator clicked.
   */
  consoleTabLocal?: (() => Partial<Record<ConsoleTabId, boolean>>) | null
  /**
   * V0.5.13: the 设置 tab's tab-visibility block — the resolved visible list,
   * which layer decided each tab, the local store's integrity and its path
   * hint. Rendering it live (rather than only baking it into the HTML) is what
   * lets the switches redraw themselves after a successful write.
   */
  consoleTabReport?: (() => Record<string, unknown>) | null
  /**
   * V0.5.13: persist one tab's visibility. Structured result so the page can
   * name the reason (unknown id / always-on tab / unreadable store / failed
   * write) instead of a generic failure.
   */
  setConsoleTab?: ((id: string, hidden: boolean) => { ok: boolean; error?: string }) | null
  /**
   * V0.5.11: the multi-account view for the 设置 tab — the active profile id,
   * the redacted profile list, the file integrity flag and whether the console
   * may write. REDACTED only: no token, no plaintext ever reaches this payload.
   */
  accounts?: (() => Record<string, unknown>) | null
  /** V0.5.11: point the connector at one account (null = none). */
  switchAccount?: ((id: string | null) => { ok: boolean; error?: string }) | null
  /** V0.5.11: create/update one account. Never echoes the password back. */
  saveAccount?: ((input: Record<string, unknown>) => { ok: boolean; error?: string }) | null
  /**
   * V0.5.12: delete one account. Structured result (same shape as saveAccount)
   * so the page can say WHY a delete failed — unknown id, read-only console or
   * an unreadable profiles file — instead of a single "unknown error".
   */
  removeAccount?: ((id: string) => { ok: boolean; error?: string }) | null
}

/** Terminal events sent to the page per poll (tail; older events are dropped). */
const TERMINAL_TAIL_EVENTS = 400
/** Max lines kept per session in the page (client side). */
const TERMINAL_MAX_LINES = 2000
/** Consecutive failed polls before the page declares the server dead. */
const DEAD_AFTER_FAILURES = 6
/** V0.5.10: upper bound on one /api/entries page (a client cannot ask for more). */
const AUDIT_PAGE_MAX = 20000

/**
 * V0.5.10: the single label table for the console navigation. Used by the
 * server when it renders the nav (only VISIBLE tabs appear in the HTML) and
 * handed to the page so the 设置 tab can name the hidden ones. Keys are the
 * same ids the sections, the hash router and auditViewer.tabs use.
 */
const CONSOLE_TAB_LABELS: Record<ConsoleTabId, string> = {
  terminal: '实时终端',
  assets: '资产',
  topology: '拓扑',
  jobs: '任务',
  audit: '审计日志',
  stats: '统计',
  sessions: '会话',
  settings: '设置',
}

/**
 * Nav markup for the visible tabs, in CONSOLE_TAB_IDS order.
 *
 * A hidden tab produces NO button — the operator simply cannot navigate to it.
 * Its section markup stays in the page (removing it would leave the script's
 * `$('rows')` / `$('cards')` bindings pointing at nothing), and the hash router
 * refuses to select it, so the state is unreachable rather than absent.
 */
function navMarkup(visibleTabs: readonly ConsoleTabId[]): string {
  return visibleTabs.map((id) => '    <button data-tab="' + id + '">' + CONSOLE_TAB_LABELS[id] + '</button>').join('\n')
}

/**
 * V0.5.13: the ONE place the two preference layers are merged for this module.
 * The page render, the /api/settings payload and the POST /api/console/tabs
 * response all go through here, so the nav that was rendered, the switches that
 * report it and the router that guards it can never disagree about which tabs
 * exist. Hiding a tab is a visibility change only — never a permission change.
 */
function resolveVisibleTabs(services: AuditViewerServices): ConsoleTabId[] {
  return resolveConsoleTabs(
    services.consoleTabs?.() ?? undefined,
    services.consoleTabLocal?.() ?? undefined,
  )
}

/** V0.5.13: which layer decided each tab, for the locked rows in 设置. */
function resolveTabSources(services: AuditViewerServices): Record<ConsoleTabId, ConsoleTabSource> {
  return consoleTabSources(
    services.consoleTabs?.() ?? undefined,
    services.consoleTabLocal?.() ?? undefined,
  )
}

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
 * V0.5.4: which role this process plays in the workspace.
 *   `owner`    — owns the configured (stable) port and serves it.
 *   `follower` — the port was taken, so this process adopted the same public
 *                address for handover BUT bound a private loopback port for its
 *                own sessions.
 *   `none`     — console disabled or not started yet.
 */
type ConsoleRole = 'owner' | 'follower' | 'none'
let consoleRole: ConsoleRole = 'none'
/**
 * V0.5.4: the follower's private loopback listener + port. Before this, a
 * process that lost the port race served NOTHING — its sessions were invisible
 * (and, worse, the shared page's 中断 button acted on the port owner's sessions
 * instead of the caller's). Two WorkBuddy conversations therefore looked at one
 * terminal with no way to tell whose it was.
 */
let consoleFollowerServer: import('node:http').Server | null = null
let consoleFollowerPort = 0
/** V0.5.4: heartbeat freshness window; an entry older than this is a dead process. */
const CONSOLE_STALE_MS = 20_000
/**
 * V0.5.4: live session registry, kept module-level so the heartbeat can publish
 * a one-line instance summary (state / target / session count) for the page's
 * instance picker. Cleared on stopAuditViewer.
 */
let liveRegistry: SessionRegistry | null = null
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

/**
 * V0.5.12: true when the request carries an Origin header that is neither
 * `http://<Host>` nor `https://<Host>`.
 *
 * A browser ALWAYS sends Origin on a cross-origin fetch / form post, so this is
 * the CSRF marker: a page on another origin must not be able to drive the
 * console even when it somehow learned a valid token. Requests WITHOUT Origin —
 * curl, the host's preview panel, the model's own programmatic calls — carry no
 * such signal and are left to the token check (see the handler gate).
 */
function isCrossOrigin(req: import('node:http').IncomingMessage): boolean {
  const origin = req.headers['origin']
  if (typeof origin !== 'string' || origin.length === 0) return false
  const host = typeof req.headers['host'] === 'string' ? (req.headers['host'] as string) : ''
  return origin !== 'http://' + host && origin !== 'https://' + host
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

function page(
  timeZone: string,
  injectedToken: string,
  selfPid: number,
  selfPort: number,
  openPid: number | null = null,
  handover: string | null = null,
  visibleTabs: readonly ConsoleTabId[] = CONSOLE_TAB_IDS,
  tabSources: Partial<Record<ConsoleTabId, ConsoleTabSource>> = {},
): string {
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
/* V0.5.4: per-instance (per-conversation) picker + embedded foreign console */
.instpick{background:#222;border:1px solid #333;color:#ddd;padding:3px 6px;border-radius:6px;font:inherit;font-size:12px;flex:none;max-width:320px;margin-left:auto}
.instpick+.instpick{margin-left:0}
#stat{margin-left:0}
.fwbar{background:#2a2118;border:1px solid #5f4a2f;color:#e8c98a;border-radius:8px;padding:8px 12px;margin-bottom:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:12px}
.fwbar b{color:#fff;font-weight:500}
.fwbar button{background:#3a2f1e;border:1px solid #6b552f;color:#e8c98a;padding:3px 10px;border-radius:6px;font:inherit;cursor:pointer}
#fwframe{width:100%;height:calc(100vh - 250px);border:1px solid #2a2a2a;border-radius:8px;background:#0d0d0d}
main{padding:12px 16px}
section{display:none}section.on{display:block}
input[type=text],input[type=password]{background:#222;border:1px solid #333;color:#ddd;padding:4px 10px;border-radius:6px;outline:none}
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
/* V0.5.9: a refusal is not a failure — it is the policy working. Kept visually
   distinct from the .bad class so "stopped" never reads as "crashed". */
.refused{color:#e8c07f;font-size:10px;border:1px solid #6b5a2f;border-radius:3px;padding:0 3px;margin-left:4px;white-space:nowrap}
/* V0.5.8: judge marker — 自动 = AUTO_ALLOWED (ran without a human prompt). */
.judge{color:#999;font-size:10px;border:1px solid #444;border-radius:3px;padding:0 3px;margin-left:4px;white-space:nowrap}
.judge.auto{color:#7fd1a8;border-color:#2f6b4f}
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
${navMarkup(visibleTabs)}
  </nav>
  <select class="instpick" id="instsel" title="工作区内的控制台实例 —— 每个 WorkBuddy 对话对应一个 MCP 进程，各自有独立的会话/终端/审计"></select>
  <span id="instnote" style="display:none;color:#e8a86a;font-size:12px;white-space:nowrap;flex:none"></span>
  <span id="stat">loading…</span>
</header>
<main>

<!-- V0.5.4: another MCP instance (i.e. another WorkBuddy conversation) embedded
     in full. Its own page injects its own token, so no secret is shared.
     V0.5.8: this wrapper also carries the case "the instance that asked for
     this page is not the process serving it" — the title/button say which pid
     is which instead of calling the requesting conversation a stranger. -->
<section id="foreign" style="display:none">
  <div class="fwbar">
    <b id="fwtitle">正在查看另一个实例</b>
    <span id="fwmeta"></span>
    <button id="fwback"><span id="fwbacklabel">切回本对话实例</span>（pid <span id="fwbackpid"></span>）</button>
  </div>
  <iframe id="fwframe" title="另一个实例的控制台" referrerpolicy="no-referrer"></iframe>
</section>

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
    <button class="act" id="audit-archive">归档审计</button>
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
  <div class="grp"><h3>控制台显示的 Tab（取消勾选即隐藏）</h3><div id="settabs">加载中…</div></div>
  <div class="grp"><h3>JumpServer 账号（多账号）</h3><div id="setaccts">加载中…</div></div>
</section>

</main>
<div id="dead"><div class="t">工作台已失效</div><div class="d">本地控制台进程已退出。V0.5.1 起工作台会自动重连 —— 若 30 秒内没有恢复，说明这个 MCP 进程已彻底结束，让 AI 重新调用任意一个 jumpserver 工具（例如 jumpserver_status）即可复活。</div><button class="act" id="dead-close">关闭本页</button></div>
<div id="expired"><div class="t">控制台令牌已过期</div><div class="d">出于安全考虑，本地控制台的访问令牌有时效。请让 AI 重新调用一次 jumpserver_status（或任意工具），然后用新的链接打开控制台。</div><button class="act" id="expired-close">关闭本页</button></div>
<script>
var TZ = ${JSON.stringify(timeZone)};
/* V0.5.10: which tabs this console shows (config: auditViewer.tabs). The nav
   above is already rendered from the same list server-side, so VISIBLE and the
   buttons can never disagree. TAB_LABELS lets the 设置 tab name the hidden
   ones. Both are inert data — visibility is not an access-control boundary. */
var VISIBLE = ${JSON.stringify(visibleTabs)};
var TAB_LABELS = ${JSON.stringify(CONSOLE_TAB_LABELS)};
/* V0.5.13: which layer decided each tab — 'config' (pinned in config.json, so
   the switch is rendered locked and disabled), 'local' (this console's own
   store), 'always' (settings), 'default'. The switches need it to avoid
   offering a control that cannot win; it is inert data, not a permission. */
var TAB_SOURCES = ${JSON.stringify(tabSources)};
/* V0.5.6: 实时终端 is the landing tab. The console exists to be WATCHED while
   the agent works — the live PTY mirror is what the operator opens it for; the
   audit table is a lookup, not the reason to look up. A bookmark (no hash)
   therefore lands on terminal, and an unknown hash falls back to it too. */
var tab = (location.hash || '#terminal').slice(1);
/* V0.5.10: the audit table is fetched incrementally and windowed. auditAll is
   the in-memory window, auditLastIdx the ABSOLUTE index of the newest record
   seen, auditTotal/auditWindowed mirror the server counters, auditNotice is a
   one-line status (e.g. the last archive) kept in the status bar. Only
   AUDIT_RENDER_LIMIT rows are ever built into the DOM — rendering a 5000-row
   innerHTML on every poll is what made a long-lived console crawl. */
var auditAll = [], lastCount = -1, auditLastIdx = -1, auditTotal = 0, auditWindowed = false, auditNotice = '';
var AUDIT_RENDER_LIMIT = 300, AUDIT_PAGE_LIMIT = 1000, AUDIT_BACKFILL_LIMIT = 5000, AUDIT_MEM_LIMIT = 5000;
var trackedSeq = {}, currentSess = null, sessStatus = {}, termLines = 0;
var failCount = 0, deadShown = false, expiredShown = false;
var topo = null, topoPick = null, jobPick = null;
/* V0.5.4: instance (per-conversation) state. SELFPID is injected by THIS
   instance's server; the handover URL carries ?inst=<pid> so opening the
   console from a second conversation lands on that conversation's sessions
   instead of whichever process owns the shared address.
   V0.5.8: the process that ANSWERS the shared port is very often not the
   conversation that asked for the console. OPENPID is the requester (from
   ?inst=), HANDOVER is that instance's own address once it has one, and
   「本实例」 means OPENPID — never "whoever answered". Failing to jump, the
   wrapper says which pid serves the page instead of calling the requester a
   stranger. */
var SELFPID = ${JSON.stringify(selfPid)};
var SELFPORT = ${JSON.stringify(selfPort)};
var OPENPID = ${JSON.stringify(openPid)};
var HANDOVER = ${JSON.stringify(handover)};
var EMBED = (new URLSearchParams(location.search)).get('embed') === '1';
/* V0.7.2 (E-4): the server redirected here because ?inst= named an instance
   that no longer exists. Say so — a silent redirect would look like the
   console had been replaced by somebody else's. */
var GONEPID = (new URLSearchParams(location.search)).get('gone');
var HOME = (OPENPID !== null && OPENPID > 0) ? OPENPID : SELFPID;
var instances = [], selPid = HOME, instReady = false, movedAway = false, shownGone = false, polls = 0;
function instById(pid){
  for (var i=0;i<instances.length;i++) if (instances[i].pid === pid) return instances[i];
  return null;
}
/* V0.5.8: 「本实例」= the conversation this tab was opened for; the process that
   happens to serve the shared port is named for what it is. */
function instRoleTag(pid){
  if (pid === HOME) return '本实例';
  if (pid === SELFPID) return '本页服务进程';
  var it = instById(pid);
  return (it !== null && it.role === 'owner') ? '主实例' : '其他实例';
}
function instLabel(it){
  var bits = ['pid ' + it.pid, instRoleTag(it.pid)];
  if (it.target) bits.push(it.target);
  if (it.sessions) bits.push('会话 ' + it.sessions);
  bits.push(it.state || '?');
  return bits.join(' · ');
}
/* Where this browser tab really belongs: the requesting instance's own
   listener. Recomputed from the live list when the server had no answer yet
   (a brand-new process publishes its port a moment after it hands out the URL). */
function handoverUrl(){
  if (EMBED || movedAway) return null;
  if (OPENPID === null || OPENPID <= 0 || OPENPID === SELFPID) return null;
  var it = instById(OPENPID);
  if (it === null || !it.port || it.port === SELFPORT) return null;
  return 'http://127.0.0.1:' + it.port + '/?inst=' + it.pid;
}
/* Probe before leaving: a dead port must keep the wrapper (an iframe that
   fails is recoverable, a browser error page is not). /ping is token-free and
   token-free is safe — it answers 204 and carries no data. */
function maybeHandover(){
  var url = HANDOVER || handoverUrl();
  if (url === null) return false;
  movedAway = true;
  fetch(url + (url.indexOf('?') >= 0 ? '&' : '?') + 'ping=1', {mode:'no-cors', cache:'no-store'})
    .then(function(){ location.replace(url + location.hash); })
    .catch(function(){ movedAway = false; applyInstance(); });
  return true;
}
function renderInstances(){
  var el = $('instsel'); if (!el) return;
  if (EMBED) { el.style.display = 'none'; return; }
  if (!instances.length) { el.innerHTML = '<option value="' + HOME + '">pid ' + HOME + ' · 本实例</option>'; return; }
  el.innerHTML = instances.map(function(it){
    return '<option value="' + it.pid + '"' + (it.pid === selPid ? ' selected' : '') + '>' + esc(instLabel(it)) + '</option>';
  }).join('');
}
function selectInstance(pid){
  selPid = pid;
  applyInstance();
}
function applyInstance(){
  var it = instById(selPid);
  /* A vanished instance falls back to this one rather than showing a dead frame. */
  if (it === null) { selPid = SELFPID; it = instById(selPid); }
  var foreign = (selPid !== SELFPID);
  var nav = document.querySelector('header nav');
  if (nav) nav.style.display = foreign ? 'none' : '';
  $('foreign').style.display = foreign ? 'block' : 'none';
  $('instnote').style.display = 'none';
  if (foreign && it !== null) {
    var secs = document.querySelectorAll('main > section');
    for (var i=0;i<secs.length;i++) secs[i].className = '';
    var mine = (selPid === HOME);
    $('fwtitle').textContent = mine
      ? '正在显示本对话实例（pid ' + it.pid + '）的控制台'
      : '正在查看另一个实例（pid ' + it.pid + '）的控制台';
    $('fwmeta').textContent = mine
      ? '本页由 pid ' + SELFPID + ' 的服务进程应答；终端 / 审计 / 会话标签属于它，所以这里整页嵌入了 pid ' + it.pid + ' 自己的控制台，按钮与中断只作用于它。'
      : (it.target ? '目标 ' + it.target + ' · ' : '') +
        '该实例属于另一个对话，它有自己的会话与审计；此处的「中断 / 断开」只作用于它。';
    $('fwbacklabel').textContent = mine ? '切换到本页服务进程' : '切回本对话实例';
    $('fwbackpid').textContent = String(mine ? SELFPID : HOME);
    var f = $('fwframe');
    var want = it.url + '?inst=' + it.pid + '&embed=1';
    if (f.getAttribute('src') !== want) f.setAttribute('src', want);
  } else {
    var f2 = $('fwframe');
    if (f2 && f2.getAttribute('src')) f2.removeAttribute('src');
    if (HOME !== SELFPID) {
      /* The requested instance is gone. Say it, instead of presenting another
         conversation's console as if it were this conversation's. */
      $('instnote').textContent = '本对话实例（pid ' + HOME + '）已退出 · 现显示 pid ' + SELFPID + '（本页服务进程）';
      $('instnote').style.display = '';
    } else if (GONEPID) {
      /* V0.7.2 (E-4): the address carried a ?inst= pin to an instance that
         has since exited. The server redirected to the live console; this
         note explains why the operator landed here instead of there. */
      $('instnote').textContent = '本对话实例（pid ' + GONEPID + '）已退出 · 现显示 pid ' + SELFPID + '（本页服务进程）';
      $('instnote').style.display = '';
    }
    showTab(tab);
  }
  renderInstances();
}
function pollInstances(){
  return F('/api/instances').then(function(r){return r.json();}).then(function(j){
    if (!j || !j.instances) return;
    instances = j.instances;
    polls += 1;
    var first = !instReady;
    instReady = true;
    // Give a just-started process two ticks to publish its port before calling
    // the requested instance dead — otherwise a fresh conversation sees a
    // 「已退出」 notice about itself for one poll interval.
    var gone = (HOME !== SELFPID) && (instById(HOME) === null) && polls >= 2;
    if (maybeHandover()) return;
    if (first || gone !== shownGone) { shownGone = gone; applyInstance(); return; }
    renderInstances();
  }).catch(function(){});
}
function $(id){return document.getElementById(id);}
function esc(s){return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function stripAnsi(s){return String(s == null ? '' : s).replace(/\\x1b\\[[0-9;?]*[A-Za-z]/g,'').replace(/[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f]/g,'');}
function shortId(id){return id.length > 22 ? id.slice(0,8) + '…' + id.slice(-10) : id;}
/* V0.5.4: 'anonymous' is the PTY session id, not the chat conversation — the
   old wording made operators read another conversation's terminal as their own.
   (Do not spell that old label here: this comment ships inside the page.) */
function labelId(id){return id === 'anonymous' ? '当前会话' : shortId(id);}
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
/* V0.5.10: a tab outside VISIBLE is unreachable. Mirrors pickLandingTab()
   (src/runtime/console-tabs.ts): honour the request only when it names a
   visible tab, otherwise land on the first one. Guarding HERE — not just in
   the click handlers — is what keeps a hand-edited #hash from selecting a
   hidden section, and it keeps every poller's own tab!==xxx gate shut for
   tabs that are switched off. */
function landingTab(name){
  if (VISIBLE.length === 0) return 'terminal';
  return VISIBLE.indexOf(name) >= 0 ? name : VISIBLE[0];
}
function showTab(name){
  name = landingTab(name);
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
showTab(tab);

/* V0.5.4: instance picker wiring. The handover URL carries ?inst=<pid>, so the
   conversation that asked for the console lands on its OWN instance; a plain
   bookmark (no ?inst) keeps showing whichever process owns the address.
   V0.5.8: 「切回本对话实例」 returns to OPENPID (the asking conversation), not to
   whoever answered the shared port. */
$('instsel').addEventListener('change', function(){ selectInstance(Number(this.value)); });
$('fwback').addEventListener('click', function(){ selectInstance(selPid === HOME ? SELFPID : HOME); });
pollInstances();
every(5000, pollInstances);

/* ---- V0.5.2: visibility gate -------------------------------------------
   Each poller already self-gates on its OWN tab, so an inactive tab costs
   nothing. What leaked was a HIDDEN page: a console left in a background
   tab (or a minimised window) with, say, the audit tab selected kept
   fetching every second and re-reading audit.jsonl with nobody looking —
   for as long as the tab stayed open. One scheduler, one rule: a page
   nobody can see does not poll. */
function every(ms, fn){
  setInterval(function(){ if (document.hidden) return; fn(); }, ms);
}
/* A tab switch already polls (showTab), but coming BACK to a backgrounded
   page does not, so the user would stare at stale data for up to 3s. */
var POLLERS = { terminal:pollTerminal, topology:pollTopology, jobs:pollJobs, audit:pollAudit, stats:pollStats, sessions:pollSessions, assets:pollAssets, settings:pollSettings };
document.addEventListener('visibilitychange', function(){
  if (document.hidden) return;
  /* terminal keeps a self-rescheduling loop of its own; poking it here would
     start a SECOND chain, so it refreshes on its own next tick (<=1s). */
  if (tab === 'terminal') return;
  var refresh = POLLERS[tab];
  if (refresh) refresh();
});

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
  /* V0.5.2: hidden page = nobody reading the mirror, so skip the fetch too. */
  if (document.hidden || tab!=='terminal'){setTimeout(pollTerminal,1000);return;}
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
  if (s==='profile') return '已选账号';
  return '默认值';
}
function srcChip(s){
  var color = s==='env' ? '#5c9' : (s==='config' ? '#7ab' : (s==='profile' ? '#c9a86a' : '#888'));
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
  renderAccounts(j.accounts);
  // V0.5.13: redraw the tab switches from the live payload, so a config edit or
  // another instance's toggle shows up on the next poll instead of being frozen
  // into the HTML the page was born with. If the resolved list actually CHANGED
  // (another console sharing the same prefs file), rebuild the nav too — the
  // expensive apply only runs on a real change, never on every 5s poll.
  var visibleBefore = VISIBLE.join(',');
  renderVisibleTabs(j.consoleTabs);
  if (VISIBLE.join(',') !== visibleBefore) applyVisibleTabs();
}
function pollSettings(){
  if (tab!=='settings') return;
  F('/api/settings').then(function(r){return r.json();}).then(function(j){ renderSettings(j); }).catch(function(){});
}
/* V0.5.13: the tab switches. V0.5.10 shipped these as a read-only report, which
   was the wrong call — the field request was explicitly "a switch in 设置", and
   a report that says "config.json controls this" without saying how leaves the
   operator exactly where they started. So: real checkboxes, persisted to the
   console's own store via POST /api/console/tabs, EXCEPT where config.json
   pins the tab — those rows are rendered locked and disabled, because a control
   that cannot win is worse than no control.
   Applying a change never edits VISIBLE locally from a guess: the server
   returns the authoritative visible list + sources, and this re-renders the nav
   and the sections from that. One source of truth, still. */
function tabSourceOf(id){ return TAB_SOURCES[id] || 'default'; }
function tabLockReason(id, src){
  if (src === 'always') return '（「设置」不可隐藏：它是唯一的诊断与说明入口）';
  if (src === 'config') return '（已被 config.json 的 auditViewer.tabs 固定，修改请改配置文件）';
  return '';
}
function renderVisibleTabs(report){
  var el = $('settabs'); if (!el) return;
  if (report){
    if (report.visible) VISIBLE = report.visible;
    if (report.sources) TAB_SOURCES = report.sources;
  }
  var all = Object.keys(TAB_LABELS);
  var html = '<div style="font-size:12px;line-height:1.8;margin-bottom:8px">显示 '
    + '<b style="color:#ccc">'+VISIBLE.length+'</b> / '+all.length
    + ' —— 取消勾选即从导航栏移除该 Tab。这只影响控制台的显示与前端轮询：'
    + '审计照旧落盘，权限门禁与全部 /api/ 接口不受影响。</div>';
  for (var i=0;i<all.length;i++){
    var id = all[i];
    var src = tabSourceOf(id);
    var shown = VISIBLE.indexOf(id) >= 0;
    var locked = (src === 'config' || src === 'always');
    html += '<label style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:12px'
      + (locked ? ';opacity:.6' : ';cursor:pointer') + '">'
      + '<input type="checkbox" data-tab-toggle="'+esc(id)+'"'
      + (shown ? ' checked' : '') + (locked ? ' disabled' : '') + '>'
      + '<span style="color:#ccc">'+esc(TAB_LABELS[id]||id)+'</span>'
      + '<span style="color:#777">'+esc(tabLockReason(id, src))+'</span>'
      + '</label>';
  }
  var st = report && report.integrity;
  if (st && st.broken){
    html += '<div style="background:#3a2424;border:1px solid #5f3535;color:#ee9f9f;border-radius:6px;padding:8px 12px;margin-top:8px">'
      + '偏好文件无法读取：'+esc(st.message||'未知原因')
      + ' —— 为避免覆盖可能仍可恢复的数据，写入已被拒绝（当前按默认值显示）。请修复或删除该文件：'
      + esc((report && report.storePathHint)||'~/.workbuddy/jumpserver-mcp/console-prefs.json')+'</div>';
  } else {
    html += '<div style="font-size:12px;color:#777;margin-top:8px">勾选结果保存在本机 '
      + esc((report && report.storePathHint)||'~/.workbuddy/jumpserver-mcp/console-prefs.json')
      + '，不写回 config.json。config.json 里显式写过的项优先级更高，会显示为不可改。</div>';
  }
  html += '<div id="tab-msg" style="font-size:12px;margin-top:6px;color:#888"></div>';
  el.innerHTML = html;
  wireVisibleTabs(el);
}
function tabMsg(text, ok){
  var m = $('tab-msg'); if (!m) return;
  m.textContent = text || '';
  m.style.color = ok ? '#7fc98f' : '#e8a86f';
}
function tabErrText(code){
  if (code==='PREFS_FILE_UNREADABLE') return '偏好文件损坏，已拒绝写入';
  if (code==='PREFS_WRITE_FAILED') return '写入失败（目录不可写？）';
  if (code==='TAB_ALWAYS_VISIBLE') return '该 Tab 不可隐藏';
  if (code==='INVALID_ARGUMENT') return '未知的 Tab';
  if (code==='NOT_AVAILABLE') return '该控制台未接入运行时';
  return code || '未知错误';
}
/* Rebuild the nav from the server's authoritative list, re-bind its clicks
   (innerHTML replaced the old buttons and their listeners), then re-land on the
   current tab — which may itself have just been hidden. Section visibility is
   NOT touched here: showTab() owns it via the "on" class, so there is still
   exactly one mechanism deciding which section is on screen. */
function applyVisibleTabs(){
  var nav = document.querySelector('nav');
  if (nav){
    var html = '';
    for (var i=0;i<VISIBLE.length;i++){
      html += '<button data-tab="'+esc(VISIBLE[i])+'">'+esc(TAB_LABELS[VISIBLE[i]]||VISIBLE[i])+'</button>';
    }
    nav.innerHTML = html;
    var btns = nav.querySelectorAll('button');
    for (var b=0;b<btns.length;b++){
      (function(btn){btn.addEventListener('click',function(){showTab(btn.getAttribute('data-tab'));});})(btns[b]);
    }
  }
  showTab(tab);
}
function wireVisibleTabs(el){
  var boxes = el.querySelectorAll('[data-tab-toggle]');
  for (var i=0;i<boxes.length;i++){
    boxes[i].addEventListener('change', function(){
      var id = this.getAttribute('data-tab-toggle');
      var want = !this.checked; /* checkbox checked = visible */
      POST('/api/console/tabs',{id:id, hidden:want}).then(function(r){return r.json();}).then(function(j){
        if (j && j.ok===false){ tabMsg('保存失败：'+tabErrText(j.error), false); pollSettings(); return; }
        renderVisibleTabs(j);
        applyVisibleTabs();
        tabMsg('已保存：'+esc(TAB_LABELS[id]||id)+(want?' 已隐藏':' 已显示'), true);
      }).catch(function(){ tabMsg('保存失败：请求未送达', false); });
    });
  }
}
renderVisibleTabs();

/* V0.5.11: multi-account block. The list comes from /api/settings (redacted
   ProfileView fields only — no token, no plaintext). Writes go to the three
   /api/accounts/* POST routes, all gated by the console token AND the /api/*
   same-origin gate like every other console endpoint. allowCredentialWrite=false
   renders the list read-only; a
   broken profiles file is reported loudly and the form is withheld, because the
   store would refuse the write anyway. */
function acctMsg(text, ok){
  var m = $('acct-msg'); if (!m) return;
  m.textContent = text || '';
  m.style.color = ok ? '#7fc98f' : '#e8a86f';
}
function renderAccounts(acc){
  var el = $('setaccts'); if (!el) return;
  if (!acc){ el.innerHTML = '<span style="color:#666">控制台没有拿到账号信息（audit-only 模式）。</span>'; return; }
  var list = acc.profiles || [];
  var allowWrite = acc.allowWrite !== false;
  var broken = !!(acc.integrity && acc.integrity.broken);
  var html = '<div style="font-size:12px;color:#888;line-height:1.7;margin-bottom:8px">'
    + '密码以 AES-256-GCM 加密保存在本机 '+esc(acc.storePathHint||'~/.workbuddy/jumpserver-mcp/profiles.json')
    + '（密钥为同目录 vault.key），不上传、不回显；切换账号会断开当前所有堡垒机会话，下次调用工具时按新账号（主机 / 用户名 / 密码）重连。'
    + '</div>';
  if (broken){
    html += '<div style="background:#3a2424;border:1px solid #5f3535;color:#ee9f9f;border-radius:6px;padding:8px 12px;margin-bottom:10px">'
      + '账号文件无法读取：'+esc((acc.integrity&&acc.integrity.message)||'未知原因')
      + ' —— 为避免覆盖可能仍可恢复的数据，写入已被拒绝；请修复或移除该文件后重试。</div>';
  }
  if (!allowWrite){
    html += '<div style="color:#e8a86a;font-size:12px;margin-bottom:10px">本机控制台已关闭凭据写入（config.json 的 auditViewer.allowCredentialWrite = false），下方仅只读展示。</div>';
  }
  if (!list.length){
    html += '<div style="color:#666">暂无账号。'+(allowWrite?'可在下方新增。':'')+'</div>';
  } else {
    html += '<div class="tw"><table><thead><tr><th style="width:180px">标签</th><th style="width:280px">用户名@主机:端口</th>'
      + '<th style="width:110px">凭据</th><th style="width:90px">当前</th><th></th></tr></thead><tbody>';
    list.forEach(function(p){
      var cur = p.active ? '<span style="color:#7fc98f">当前</span>' : '';
      var ops = '';
      if (allowWrite && !broken){
        if (!p.active) ops += '<button class="act" data-acct-activate="'+esc(p.id)+'">设为当前</button> ';
        ops += '<button class="act" data-acct-edit="'+esc(p.id)+'">编辑</button> ';
        ops += '<button class="act warn" data-acct-remove="'+esc(p.id)+'">删除</button>';
      }
      html += '<tr><td>'+esc(p.label)+'</td>'
        + '<td style="font-family:ui-monospace,Consolas,monospace">'+esc(p.username)+'@'+esc(p.host)+':'+esc(p.port)+'</td>'
        + '<td>'+esc(p.hasSecret?'已保存':'未保存')+'</td>'
        + '<td>'+cur+'</td>'
        + '<td>'+ops+'</td></tr>';
    });
    html += '</tbody></table></div>';
  }
  if (allowWrite && !broken){
    html += '<div style="margin-top:12px">'
      + '<div style="color:#ccc;font-size:12px;margin-bottom:6px">新增 / 编辑账号</div>'
      + '<input type="hidden" id="acct-id">'
      + '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">'
      + '<input type="text" id="acct-label" placeholder="标签（如：生产维护账号）" style="width:200px">'
      + '<input type="text" id="acct-host" placeholder="堡垒机地址" style="width:170px">'
      + '<input type="text" id="acct-port" placeholder="端口" value="2222" style="width:80px">'
      + '<input type="text" id="acct-user" placeholder="用户名" style="width:140px">'
      + '<input type="password" id="acct-pass" placeholder="密码（留空表示不改动已有凭据）" style="width:250px" autocomplete="new-password">'
      + '<button class="act" id="acct-save">保存</button>'
      + '<button class="act" id="acct-clear">清空表单</button>'
      + '</div>'
      + '<div id="acct-msg" style="font-size:12px;margin-top:6px;color:#888"></div>'
      + '</div>';
  }
  el.innerHTML = html;
  wireAccounts(el, acc);
}
function acctErrText(code){
  if (code==='CREDENTIAL_WRITE_DISABLED') return '凭据写入已关闭';
  if (code==='PROFILES_FILE_UNREADABLE') return '账号文件无法写入';
  if (code==='PROFILE_NOT_FOUND') return '账号不存在';
  if (code==='INVALID_ARGUMENT') return '请填写标签 / 地址 / 用户名，端口需为 1-65535';
  return code || '未知错误';
}
/* V0.5.12: the delete route now reports WHY it failed. Keep the delete button's
   copy specific instead of the shared generic text, and fall back to the common
   mapping for anything unrecognised. */
function acctDelErrText(code){
  if (code==='PROFILE_NOT_FOUND') return '账号不存在';
  if (code==='PROFILES_FILE_UNREADABLE') return '账号文件损坏，已拒绝写入';
  if (code==='CREDENTIAL_WRITE_DISABLED') return '写入已关闭';
  return acctErrText(code);
}
function wireAccounts(el, acc){
  var acts = el.querySelectorAll('[data-acct-activate]');
  for (var i=0;i<acts.length;i++){
    acts[i].addEventListener('click', function(){
      var id = this.getAttribute('data-acct-activate');
      POST('/api/accounts/activate',{id:id}).then(function(r){return r.json();}).then(function(j){
        if (j && j.ok===false){ acctMsg('切换失败：'+acctErrText(j.error), false); return; }
        pollSettings();
      }).catch(function(){});
    });
  }
  var edits = el.querySelectorAll('[data-acct-edit]');
  for (var e=0;e<edits.length;e++){
    edits[e].addEventListener('click', function(){
      var id = this.getAttribute('data-acct-edit');
      var p = null;
      for (var x=0;x<(acc.profiles||[]).length;x++){ if (acc.profiles[x].id===id) p = acc.profiles[x]; }
      if (!p) return;
      if ($('acct-id')) $('acct-id').value = p.id;
      if ($('acct-label')) $('acct-label').value = p.label || '';
      if ($('acct-host')) $('acct-host').value = p.host || '';
      if ($('acct-port')) $('acct-port').value = String(p.port || 2222);
      if ($('acct-user')) $('acct-user').value = p.username || '';
      if ($('acct-pass')) $('acct-pass').value = '';
      acctMsg('编辑「'+(p.label||'')+'」：密码留空表示不改动。', true);
    });
  }
  var dels = el.querySelectorAll('[data-acct-remove]');
  for (var d=0;d<dels.length;d++){
    dels[d].addEventListener('click', function(){
      var id = this.getAttribute('data-acct-remove');
      POST('/api/accounts/remove',{id:id}).then(function(r){return r.json();}).then(function(j){
        if (j && j.ok===false){ acctMsg('删除失败：'+acctDelErrText(j.error), false); return; }
        pollSettings();
      }).catch(function(){});
    });
  }
  var save = $('acct-save');
  if (save) save.addEventListener('click', function(){
    var passEl = $('acct-pass');
    var body = {
      id: ($('acct-id') && $('acct-id').value) ? $('acct-id').value : undefined,
      label: $('acct-label') ? $('acct-label').value : '',
      host: $('acct-host') ? $('acct-host').value : '',
      port: $('acct-port') ? Number($('acct-port').value) : 0,
      username: $('acct-user') ? $('acct-user').value : '',
      password: (passEl && passEl.value.length > 0) ? passEl.value : undefined
    };
    POST('/api/accounts/save',body).then(function(r){return r.json();}).then(function(j){
      if (j && j.ok===false){ acctMsg('保存失败：'+acctErrText(j.error), false); return; }
      acctMsg('已保存。切换账号会断开当前会话。', true);
      pollSettings();
    }).catch(function(){});
  });
  var clear = $('acct-clear');
  if (clear) clear.addEventListener('click', function(){
    if ($('acct-id')) $('acct-id').value = '';
    if ($('acct-label')) $('acct-label').value = '';
    if ($('acct-host')) $('acct-host').value = '';
    if ($('acct-port')) $('acct-port').value = '2222';
    if ($('acct-user')) $('acct-user').value = '';
    if ($('acct-pass')) $('acct-pass').value = '';
    acctMsg('', true);
  });
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
every(3000, pollTopology);

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
every(1000, pollJobs);

/* ---- audit ---- */
function renderAudit(){
  var q=$('filter').value.toLowerCase();
  var list=q?auditAll.filter(function(e){return JSON.stringify(e).toLowerCase().indexOf(q)>=0;}):auditAll;
  /* V0.5.10: build at most the newest AUDIT_RENDER_LIMIT rows into the DOM
     (newest first). The filter still runs over the whole in-memory window. */
  var shown=list.slice(Math.max(0,list.length-AUDIT_RENDER_LIMIT)).reverse();
  var rows=shown.map(function(e){
    var tgt=e.target||e.hostname||'-';
    var cmd=e.redactedCommand||e.command||'-';
    var risk=esc(e.risk||'?');
    // V0.4.3: result carries commandStatus. A COMPLETED exchange with a
    // non-zero exit is a FAILED command and must not look healthy.
    var status=String(e.result||'?');
    var exitN=e.exitCode;
    /* V0.5.9: BLOCKED (rules said no) and DENIED (no approval) are refusals —
       they never produced an exit code, so they must not render as failures. */
    var refused=(status==='BLOCKED'||status==='DENIED');
    var bad=!refused&&((status!=='SUCCESS'&&status!=='COMPLETED'&&status!=='ok'&&status!=='RUNNING'&&status!=='')
      ||(typeof exitN==='number'&&exitN!==0));
    var refusedTag=refused?' <span class="refused" title="'+esc(String(e.refusalReason||''))+'">'+(status==='BLOCKED'?'已拦截':'未批准')+'</span>':'';
    /* V0.5.8: a command the semantic judge cleared without asking is marked, so
       "why was there no prompt" is answerable from the audit table itself. */
    var judge=(typeof e.riskJudge==='string'&&e.riskJudge.length>0)?String(e.riskJudge):'';
    var auto=judge.indexOf('AUTO_ALLOWED')===0;
    var judgeTag=judge?' <span class="judge'+(auto?' auto':'')+'" title="'+esc(judge)+'">'+(auto?'JEV 自动':'JEV 参考')+'</span>':'';
    return '<tr><td class="time">'+esc(fmtTime(e.timestamp))+'</td>'
      +'<td class="op">'+esc(e.operation)+'</td>'
      +'<td class="tgt" title="'+esc(tgt)+'">'+esc(tgt)+'</td>'
      +'<td class="risk risk-'+risk+'">'+risk+' / '+esc(status)+(bad?' <span class="bad">exit '+esc(String(exitN!=null?exitN:'?'))+'</span>':'')+refusedTag+judgeTag+'</td>'
      +'<td class="cmd">'+esc(cmd)+'</td></tr>';
  }).join('');
  $('rows').innerHTML=rows;
  $('empty').style.display=list.length?'none':'block';
  var stat='审计：匹配 '+list.length+' 条 / 显示最近 '+shown.length+' 条 / 共 '+auditTotal+' 条';
  if (auditWindowed) stat+=' · 更早记录已淘汰或归档';
  if (auditNotice) stat+=' · '+auditNotice;
  $('stat').textContent=stat;
  lastCount=auditAll.length;
}
function pollAudit(){
  if (tab!=='audit') return;
  var first=auditLastIdx<0;
  var limit=first?AUDIT_BACKFILL_LIMIT:AUDIT_PAGE_LIMIT;
  var prevTotal=auditTotal, prevIdx=auditLastIdx;
  /* V0.5.10: incremental fetch keyed on the ABSOLUTE index, not the array
     length. The old code re-requested the whole ring every second and, once the
     ring hit its cap, the length stopped changing so new records never showed. */
  F('/api/entries?since='+auditLastIdx+'&limit='+limit).then(function(r){return r.json();}).then(function(j){
    if (!j || typeof j.items==='undefined'){
      /* Older server: a plain array. Rebuild and render (compat path). */
      auditAll=j||[]; auditTotal=auditAll.length; auditWindowed=false;
      auditLastIdx=auditAll.length-1; renderAudit(); return;
    }
    var got=j.items.length;
    if (got>0) for (var i=0;i<got;i++) auditAll.push(j.items[i]);
    if (typeof j.nextIndex==='number'&&j.nextIndex>auditLastIdx) auditLastIdx=j.nextIndex;
    var total=(typeof j.total==='number')?j.total:prevTotal;
    auditTotal=total; auditWindowed=(j.windowed===true);
    if (auditAll.length>AUDIT_MEM_LIMIT) auditAll=auditAll.slice(-AUDIT_MEM_LIMIT);
    if (got>0||total!==prevTotal||auditLastIdx!==prevIdx||first) renderAudit();
  }).catch(function(){});
}
every(1000, pollAudit);
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
  var cols=['timestamp','operation','actor','target','hostname','risk','result','exitCode','durationMs','toolCallId','batchId','taskId','riskJudge','refusalReason','redactedCommand'];
  var q=function(v){v=v==null?'':String(v);return /[",\\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  var lines=[cols.join(',')];
  auditAll.forEach(function(e){lines.push(cols.map(function(c){return q(e[c]);}).join(','));});
  download('jumpserver-audit.csv','text/csv','\\ufeff'+lines.join('\\n'));
});
/* V0.5.10: rotate the live audit file server-side. The archived file stays on
   disk (never deleted); new records go to a fresh audit.jsonl. */
$('audit-archive').addEventListener('click',function(){
  var ok=window.confirm('归档审计：\\n1) 先把已排队的记录全部落盘；\\n2) 把当前 audit.jsonl 重命名为带 UTC 时间戳的归档文件（例如 audit.2026-01-01T00-00-00-000Z.jsonl）；\\n3) 之后的新记录写入一个全新的 audit.jsonl。\\n归档文件不会被删除。是否继续？');
  if(!ok) return;
  POST('/api/audit/archive').then(function(r){return r.json();}).then(function(j){
    auditAll=[]; auditLastIdx=-1; auditTotal=0; auditWindowed=false;
    if (j&&j.archived) auditNotice='已归档 '+j.records+' 条 → '+j.file;
    else auditNotice='归档未执行（没有可归档的审计文件）';
    renderAudit();
    pollAudit();
  }).catch(function(){ auditNotice='归档失败'; renderAudit(); });
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
every(3000, pollStats);

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
every(2000, pollSessions);
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

/**
 * V0.5.10: paging over a plain array, used only on the no-AuditStore fallback
 * path (`readAuditEntries`). Here an array position IS the absolute index,
 * since the whole file was just parsed.
 */
function paginateArray(
  list: Record<string, unknown>[],
  since: number,
  limit: number,
): { items: Record<string, unknown>[]; total: number; nextIndex: number; windowed: boolean; firstIndex: number } {
  const total = list.length
  const start = Math.max(0, since + 1)
  const items = start >= total ? [] : list.slice(start, start + limit)
  return {
    items,
    total,
    nextIndex: items.length > 0 ? start + items.length - 1 : since,
    windowed: false,
    firstIndex: 0,
  }
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
  const url = advertisedConsoleUrl()
  if (url === null || hintEnabled !== true) return null
  hintEmitted += 1
  return (
    '[jumpserver-console] JumpServer 工作台（实时终端 / 资产 / 拓扑 / 任务 / 审计 / 统计 / 会话 / 设置）: ' + url + '\n' +
    '这是「启动阶段」的界面交接，不是任务结果汇报 —— 请在执行第一条远程命令之前就调用 present_files 打开它。' +
    '等到任务快结束才打开就晚了：那时进程可能已经退出，页面只会显示「工作台已失效」。\n' +
    '地址固定（V0.5.1 起不含令牌、也不随进程退出而失效），可以直接打开或收藏。\n' +
    'V0.5.8：地址末尾的 ?inst= 是本对话实例编号 —— 页面会自动定位到你自己那个实例（它有自己的终端 / 审计 / 会话），' +
    '同一个工作区的其他实例属于别的对话，顶部切换器可切换，中断 / 断开只作用于所选实例。\n' +
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
  // V0.5.4: instance bookkeeping — see ConsoleRole. The registry is kept so the
  // heartbeat can publish this instance's live target/state for the picker.
  consoleRole = 'none'
  consoleFollowerPort = 0
  liveRegistry = registry
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
  // V0.5.4: one request handler, shared by the public (stable-address) listener
  // and — when we lose the port race — the follower's private loopback listener.
  // Both serve the identical page; only the advertised address differs.
  const handler = (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): void => {
    void (async () => {
      const target = req.url ?? '/'
      const href = target.split('?')[0] ?? '/'
      const query = new URLSearchParams(target.split('?')[1] ?? '')
      // V0.5.8: token-free liveness probe, used by a console page to decide
      // whether it may hand the browser over to another instance's listener (a
      // dead port must keep the wrapper) and by the tests. 204, no body, no
      // data — it says nothing an audit-enabled reader could learn from.
      if (href === '/ping') {
        res.writeHead(204, { 'cache-control': 'no-store' })
        res.end()
        return
      }
      // V0.4.1: /api/* must present the token (query or header).
      // V0.4.2: an expired token is rejected with a distinct marker so the page
      // can show "console expired" instead of a generic failure.
      // V0.5.1: in stable-address mode `GET /` is exempt — the page is static
      // and carries no audit data, and it receives the token as an injected
      // constant rather than a query parameter. A cross-origin PAGE LOAD is
      // still refused (see isCrossOrigin), so a web page in the local browser
      // cannot read the audit trail or reach /api/interrupt.
      // V0.5.12: /api/* is same-origin only — see the check below. A token on
      // its own is no longer enough: a cross-origin caller is refused outright,
      // while requests that carry no Origin at all (curl, the host preview
      // panel, the model's programmatic calls) remain token-gated as before.
      const presented = query.get('token') ?? (typeof req.headers[TOKEN_HEADER] === 'string' ? (req.headers[TOKEN_HEADER] as string) : null)
      const isPageLoad = (req.method === 'GET' || req.method === 'HEAD') && (href === '/' || href === '/index.html')
      const pageExempt = stableAddress && isPageLoad && !isCrossOrigin(req)
      if (!pageExempt && !tokenMatches(presented)) {
        const expired = consoleTokenExpired()
        res.statusCode = 403
        res.setHeader('content-type', 'text/plain; charset=utf-8')
        if (expired) res.setHeader('x-console-token-expired', '1')
        res.end(expired ? 'console token expired: reload the page to get a fresh one' : 'forbidden: missing or invalid console token')
        return
      }
      // V0.5.12: the CSRF gate. The token check above already dropped anonymous
      // callers; this stops a cross-origin page that DOES present a valid token
      // from driving the write routes (accounts activate / save / remove,
      // audit archive, interrupt, sessions close, jobs stop). No side effect is
      // reached — the request is refused before any route body runs.
      if (href.startsWith('/api/') && isCrossOrigin(req)) {
        res.statusCode = 403
        res.setHeader('content-type', 'text/plain; charset=utf-8')
        res.end('forbidden: cross-origin request')
        return
      }
      // V0.5.4: every live console in this workspace (one per MCP process, i.e.
      // per conversation). The page's instance picker is built from this, so a
      // conversation can always get to ITS OWN sessions instead of silently
      // watching whichever process happened to win the stable port.
      if (href === '/api/instances') {
        sendJson(res, listConsoleInstances())
        return
      }
      const entries = (): Record<string, unknown>[] => (audit !== null ? audit.list() : readAuditEntries(auditPath))
      if (href === '/api/entries') {
        // V0.5.10: opt-in pagination. Passing no query at all keeps the
        // historical "return the whole array" contract other callers rely on.
        if (query.has('since') || query.has('limit')) {
          // -1 (or absent/non-finite) means "from the beginning" — never clamp
          // negatives to 0, or absolute index 0 would be skipped.
          const sinceRaw = query.has('since') ? Number(query.get('since')) : -1
          const since = Number.isFinite(sinceRaw) ? Math.floor(sinceRaw) : -1
          const limitRaw = Number(query.get('limit') ?? '')
          const limit = Number.isFinite(limitRaw) && limitRaw > 0
            ? Math.min(AUDIT_PAGE_MAX, Math.floor(limitRaw))
            : DEFAULT_AUDIT_RING_SIZE
          sendJson(res, audit !== null ? audit.page(since, limit) : paginateArray(entries(), since, limit))
          return
        }
        sendJson(res, entries())
        return
      }
      // V0.5.10: rotate the live audit file. This branch sits AFTER the token
      // check above, so it is gated exactly like every other /api/* route. Only
      // the archived file NAME is returned — never a full disk path.
      if (href === '/api/audit/archive' && req.method === 'POST') {
        if (audit === null) {
          sendJson(res, { archived: false, file: null, records: 0, bytes: 0 })
          return
        }
        const result = await audit.archive()
        sendJson(res, {
          archived: result.archivedPath !== null,
          file: result.archivedPath !== null ? basename(result.archivedPath) : null,
          records: result.records,
          bytes: result.bytes,
        })
        return
      }
      if (href === '/api/stats') {
        // V0.7.1 (D-8): the statistics come from the shared pure model, so
        // the console, the daily aggregation files and the tests can never
        // disagree about what "failed" means.
        const stats = computeAuditStats(entries())
        sendJson(res, {
          total: stats.total,
          failed: stats.failed,
          exitNonzero: stats.exitNonzero,
          failedIncludingExitNonzero: stats.failedIncludingExitNonzero,
          failureRate: stats.failureRate,
          unverified: stats.unverified,
          byClass: stats.byClass,
          byErrorCode: stats.byErrorCode,
          targets: stats.targets,
          days: stats.days,
          byRisk: stats.byRisk,
          byOperation: stats.byOperation,
          byTarget: stats.byTarget,
          byDay: stats.byDay,
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
        // V0.5.11: the redacted multi-account view. accounts() is built to carry
        // ProfileView fields only — never a password or a vault token.
        const accounts = services.accounts !== undefined && services.accounts !== null
          ? services.accounts()
          : null
        // V0.5.13: the tab-visibility block — resolved visible list, which layer
        // decided each tab, and the local store's integrity. Same shape the
        // write route returns, so the page has ONE renderer for both.
        const consoleTabs = services.consoleTabReport !== undefined && services.consoleTabReport !== null
          ? services.consoleTabReport()
          : null
        sendJson(res, { connection: conn, policy, knownHosts, accounts, consoleTabs })
        return
      }
      // V0.5.13: persist one tab's visibility. Like every other write route it
      // sits AFTER the token check and the same-origin gate. It is deliberately
      // NOT behind auditViewer.allowCredentialWrite: hiding a tab changes what
      // the operator sees and nothing else — no credential is written, no
      // permission is granted, and the audit sink keeps writing.
      if (href === '/api/console/tabs' && req.method === 'POST') {
        const body = await readBody(req)
        if (services.setConsoleTab === undefined || services.setConsoleTab === null) {
          sendJson(res, { ok: false, error: 'NOT_AVAILABLE' })
          return
        }
        const id = String(body['id'] ?? '')
        const hidden = body['hidden'] === true
        const written = services.setConsoleTab(id, hidden)
        if (written.ok !== true) {
          sendJson(res, written)
          return
        }
        // The AUTHORITATIVE new state travels back with the ack: the page
        // rebuilds its nav from this list instead of patching VISIBLE itself,
        // which is what keeps the rendered nav and the router in agreement.
        const report = services.consoleTabReport !== undefined && services.consoleTabReport !== null
          ? services.consoleTabReport()
          : {}
        sendJson(res, { ok: true, ...report })
        return
      }
      // V0.5.11: multi-account write routes. They sit AFTER the token check and
      // the V0.5.12 same-origin gate above, exactly like /api/audit/archive, so
      // they are gated by both the console token and the request's origin.
      if (href === '/api/accounts/activate' && req.method === 'POST') {
        const body = await readBody(req)
        const rawId = body['id']
        const id = rawId === null ? null : typeof rawId === 'string' ? rawId : null
        if (services.switchAccount === undefined || services.switchAccount === null) {
          sendJson(res, { ok: false, error: 'NOT_AVAILABLE' })
          return
        }
        sendJson(res, services.switchAccount(id))
        return
      }
      if (href === '/api/accounts/save' && req.method === 'POST') {
        const body = await readBody(req)
        if (services.saveAccount === undefined || services.saveAccount === null) {
          sendJson(res, { ok: false, error: 'NOT_AVAILABLE' })
          return
        }
        // The response is the structured result only — the request body (which
        // may carry a password) is never echoed back.
        sendJson(res, services.saveAccount(body))
        return
      }
      if (href === '/api/accounts/remove' && req.method === 'POST') {
        const body = await readBody(req)
        if (services.removeAccount === undefined || services.removeAccount === null) {
          sendJson(res, { ok: false, error: 'NOT_AVAILABLE' })
          return
        }
        const id = String(body['id'] ?? '')
        // V0.5.12: pass the service's structured result straight through so the
        // page can name the real reason (PROFILE_NOT_FOUND / read-only / broken
        // store). Never a credential — the result carries a code, not data.
        sendJson(res, id.length > 0 ? services.removeAccount(id) : { ok: false, error: 'INVALID_ARGUMENT' })
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
      // V0.5.8: who asked for this page (?inst=) and where that instance really
      // lives. Embedded pages (?embed=1) never re-locate: they ARE the target.
      const embedded = query.get('embed') === '1'
      const rawInst = query.get('inst')
      const parsedInst = rawInst === null ? null : Number(rawInst)
      const openPid =
        embedded || parsedInst === null || !Number.isFinite(parsedInst) || parsedInst <= 0 ? null : Math.trunc(parsedInst)
      // V0.7.2 (E-4): a pin that no longer resolves must not leave the operator
      // on an empty frame. Redirect to the live console and carry the reason
      // along, so the page can say "that instance is gone" instead of silently
      // showing somebody else's terminal.
      const liveInstances = listConsoleInstances().instances
      if (openPid !== null && !isPinLive(openPid, process.pid, liveInstances)) {
        const fallback = stalePinFallback(viewerUrl, openPid)
        if (fallback !== null) {
          res.writeHead(302, { Location: fallback })
          res.end()
          return
        }
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      const handover =
        openPid === null ? null : resolveConsoleHandover(openPid, process.pid, publishedPort(), liveInstances)
      // V0.5.10: the tab switches are read per page load, so editing
      // auditViewer.tabs takes effect on the next refresh — no console restart.
      const visibleTabs = resolveVisibleTabs(services)
      res.end(page(timeZone, consoleToken ?? '', process.pid, publishedPort(), openPid, handover, visibleTabs, resolveTabSources(services)))
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
  }
  const server = http.createServer(handler)
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
      // V0.5.4: adopting the address must NOT leave this process without a
      // console. Bind a private loopback port so this instance's sessions,
      // terminal mirror and audit stay reachable; the page embeds it when the
      // operator selects this instance. Without this, two conversations showed
      // one terminal and the 中断 button hit the wrong process.
      startFollowerListener(handler)
      return
    }
    console.error('[jumpserver-mcp] ops console: ' + (error instanceof Error ? error.message : String(error)))
  })
  server.on('listening', () => {
    consoleBound = true
    consoleRole = 'owner'
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
  // V0.5.4: the private follower listener (and its role/port) comes down too.
  if (consoleFollowerServer !== null) {
    try { consoleFollowerServer.close() } catch { /* already closed */ }
    consoleFollowerServer = null
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
  // V0.5.4 state.
  consoleRole = 'none'
  consoleFollowerPort = 0
  liveRegistry = null
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
 *   data/consoles/<pid>.json =
 *     { pid, port, role, startedAt, heartbeatAt, tokenExpiresAt, summary }
 * Stale files (heartbeat older than 20s => the conversation/process is gone)
 * are pruned, so external tools can enumerate live consoles by listing the dir.
 *
 * V0.4.3 SECURITY: the file must NEVER contain the tokenized URL. Any local
 * process (or a sync agent watching the workspace) could otherwise read the
 * token off disk and reach the console, defeating the token entirely. The
 * token lives only in this process's memory and is handed to the user through
 * the MCP response (consoleHintForModel). V0.5.4 keeps that promise and adds
 * only non-secret fields (role + a one-line session summary) so the page can
 * label each instance.
 */
function writeConsoleFile(): void {
  const port = publishedPort()
  if (consoleFile === null || port <= 0) return
  try {
    writeFileSync(consoleFile, JSON.stringify({
      pid: process.pid,
      port,
      role: consoleRole,
      startedAt: consoleStartedAt,
      heartbeatAt: new Date().toISOString(),
      tokenExpiresAt: consoleTokenExpiresAt !== null ? new Date(consoleTokenExpiresAt).toISOString() : null,
      summary: selfSummary(),
    }) + '\n', 'utf8')
  } catch {
    /* discovery file is best-effort */
  }
}

/** V0.5.4: the port this instance publishes — the owned one, else the follower's. */
function publishedPort(): number {
  if (consoleRole === 'owner') return consolePort
  return consoleFollowerPort
}

/** V0.5.4: compact live summary so the instance picker can label each console. */
function selfSummary(): { state: string; target: string | null; sessions: number } {
  const registry = liveRegistry
  if (registry === null) return { state: 'none', target: null, sessions: 0 }
  let state = 'none'
  let target: string | null = null
  let sessions = 0
  try {
    for (const [, bundle] of registry.snapshot()) {
      sessions += 1
      const status = bundle.manager.status()
      if (target === null && typeof status.target === 'string' && status.target.length > 0) target = status.target
      if (state === 'none' && typeof status.state === 'string' && status.state.length > 0) state = status.state
    }
  } catch {
    /* a closing session must never break the heartbeat */
  }
  return { state, target, sessions }
}

/** One live console as the page sees it. */
interface ConsoleInstanceView {
  pid: number
  port: number
  role: string
  startedAt: string
  ageMs: number
  self: boolean
  state: string
  target: string | null
  sessions: number
  url: string
}

/**
 * V0.5.4: enumerate this workspace's live consoles from the discovery files.
 * Deliberately file-based — no cross-process calls and no shared secret: the
 * page reaches another instance by EMBEDDING that instance's own page, which
 * injects its own token, so the per-process token model is untouched.
 */
function listConsoleInstances(): {
  selfPid: number
  selfPort: number
  selfRole: string
  instances: ConsoleInstanceView[]
} {
  const instances: ConsoleInstanceView[] = []
  if (consoleDir !== null) {
    try {
      for (const name of readdirSync(consoleDir)) {
        if (!name.endsWith('.json')) continue
        try {
          const raw = JSON.parse(readFileSync(join(consoleDir, name), 'utf8')) as Record<string, unknown>
          const pid = Number(raw['pid'])
          const port = Number(raw['port'])
          if (!Number.isFinite(pid) || !Number.isFinite(port) || port <= 0) continue
          const ageMs = Date.now() - Date.parse(String(raw['heartbeatAt'] ?? ''))
          if (!Number.isFinite(ageMs) || ageMs > CONSOLE_STALE_MS) continue
          const summary = (raw['summary'] ?? {}) as Record<string, unknown>
          const rawTarget = summary['target']
          instances.push({
            pid,
            port,
            role: String(raw['role'] ?? 'owner'),
            startedAt: String(raw['startedAt'] ?? ''),
            ageMs,
            self: pid === process.pid,
            state: String(summary['state'] ?? 'unknown'),
            target: rawTarget === null || rawTarget === undefined ? null : String(rawTarget),
            sessions: Number(summary['sessions'] ?? 0) || 0,
            url: consoleUrl(port),
          })
        } catch {
          /* unreadable discovery entry — skip; the next tick retries */
        }
      }
    } catch {
      /* consoles dir may not exist yet */
    }
  }
  instances.sort((a, b) => (a.self === b.self ? a.pid - b.pid : a.self ? -1 : 1))
  return { selfPid: process.pid, selfPort: publishedPort(), selfRole: consoleRole, instances }
}

/**
 * V0.5.8: where a freshly opened console page should really live.
 *
 * The handover URL is the SHARED stable address (`http://127.0.0.1:8765/`) plus
 * `?inst=<pid>`. Whoever owns that port answers the request — and that is very
 * often NOT the conversation that asked for the console: with two conversations
 * open, the older MCP process holds 8765 and serves the page while the newer
 * one (the process that just handed this URL to its model) is a follower on a
 * private loopback port. The page then treated ITSELF as "the console" and
 * labelled the requesting conversation 「另一个对话」 — an operator watched
 * their own terminal under a stranger's banner, and 「切回本实例」 led to
 * somebody else's session. Content was right, identity was inverted.
 *
 * So when `?inst=` names a live instance that owns a DIFFERENT listener, the
 * page hands the browser over to that instance: the page it then loads is that
 * instance — own tabs, own audit, own sessions, no wrapper.
 *
 * Returns null when the page must stay where it is: no parameter, the parameter
 * names this process, the instance is unknown/stale, or it publishes no port of
 * its own (an owner still binding).
 */
export function resolveConsoleHandover(
  openPid: number | null,
  selfPid: number,
  selfPort: number,
  instances: ConsoleInstanceView[],
): string | null {
  if (openPid === null || !Number.isFinite(openPid) || openPid <= 0) return null
  if (openPid === selfPid) return null
  const target = instances.find((item) => item.pid === openPid)
  if (target === undefined) return null
  if (!Number.isFinite(target.port) || target.port <= 0) return null
  if (target.port === selfPort) return null
  const sep = target.url.includes('?') ? '&' : '?'
  return target.url + sep + 'inst=' + String(target.pid)
}

/**
 * V0.5.4: bind this process's own loopback console when the configured (stable)
 * address belongs to another MCP process. Port 0 = any free port; the number is
 * published in the heartbeat file and is only ever reached through the page's
 * instance picker, never advertised as the workspace address.
 */
function startFollowerListener(
  handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void,
): void {
  if (consoleFollowerServer !== null) return
  const follower = http.createServer(handler)
  follower.on('listening', () => {
    const address = follower.address()
    consoleFollowerPort = typeof address === 'object' && address !== null ? address.port : 0
    // A later takeover flips the role to 'owner'; never downgrade it back.
    if (consoleRole !== 'owner') consoleRole = 'follower'
    consoleStartedAt = new Date().toISOString()
    writeConsoleFile()
  })
  follower.on('error', (error) => {
    console.error(
      '[jumpserver-mcp] ops console: follower listener failed: ' + (error instanceof Error ? error.message : String(error)),
    )
  })
  follower.unref?.()
  consoleFollowerServer = follower
  try {
    follower.listen(0, '127.0.0.1')
  } catch (error) {
    console.error('[jumpserver-mcp] ops console: ' + (error instanceof Error ? error.message : String(error)))
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
    // V0.5.4: heartbeat even when we are only a follower — writeConsoleFile()
    // publishes whichever port this instance owns and no-ops when none is bound.
    writeConsoleFile()
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

/**
 * V0.6.1 (B-4): who owns the console right now, and is the advertised URL
 * actually served?
 *
 * The symptom this answers: "the console link 404s / shows another
 * conversation's terminal / the page says the token expired". All three are
 * ownership questions, and the connector could not answer any of them —
 * `jumpserver_status` published a URL and an expiry, nothing about whether
 * the URL still belongs to a live process.
 */
export interface ConsoleOwnership {
  /** This process's role in the workspace. */
  role: 'owner' | 'follower' | 'none'
  /** This process's pid. */
  pid: number
  /** The port this process publishes (owned or private follower port). */
  port: number
  /** The pid that owns the shared address, when one is alive. */
  ownerPid: number | null
  /** The URL handed to the model (stable address + ?inst=<pid>). */
  url: string | null
  /**
   * True when the advertised URL is served by a LIVE process — i.e. the
   * discovery heartbeat of the instance that owns it is fresh.
   */
  urlServed: boolean
  /** How many live console instances the workspace has. */
  instanceCount: number
}

export function consoleOwnership(): ConsoleOwnership {
  const instances = listConsoleInstances()
  const url = advertisedConsoleUrl()
  // The owner is the live instance whose role is 'owner'; when this process
  // owns the address it is that instance.
  const owner = instances.instances.find((item) => item.role === 'owner')
  return {
    role: consoleRole,
    pid: process.pid,
    port: publishedPort(),
    ownerPid: owner !== undefined ? owner.pid : null,
    url,
    urlServed: owner !== undefined && url !== null,
    instanceCount: instances.instances.length,
  }
}

/** Current console URL (null until the listener is bound / when disabled). */
export function auditViewerUrl(): string | null {
  return viewerUrl
}

/**
 * V0.5.4: the address handed to the model. Same stable address as always (a
 * plain bookmark keeps working) plus `?inst=<pid>`, so the page resolves to the
 * instance that ASKED for the console instead of whichever process owns the
 * port. `auditViewerUrl()` stays parameter-free for callers that need the
 * canonical, bookmark-stable address.
 *
 * V0.7.2 (E-4): the pid is now pinned ONLY when there is more than one live
 * console to disambiguate. With a single console the bare address is
 * unambiguous, and a pinned pid could only ever go stale (the owner of 8765
 * changed three times in 25 minutes on this workspace). See
 * `console-address.ts`.
 */
export function advertisedConsoleUrl(): string | null {
  if (viewerUrl === null) return null
  if (!stableAddress) return viewerUrl
  const address = consoleAddressFor(viewerUrl, process.pid, stableAddress)
  return address.url
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
  return advertisedConsoleUrl()
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
