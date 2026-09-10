import { DEFAULT_ASSET_CACHE_TTL_SECONDS, DEFAULT_TIMEOUTS, type JumpServerConfig, type PermissionMode } from '../config/types.js'
import type { TerminalObserver } from './terminal-observer.js'
import { AbortRequestedError, JumpServerError } from './errors.js'
import { filterAssets, filterAssetsByGroup, parseAssetList, resolveGroupKeywords, type AssetEntry, type AssetHealth, type AssetListResult } from './asset-list.js'
import { cleanAnsi } from './output-buffer.js'
import { MAX_ASSET_CAPTURE_BYTES } from '../config/types.js'
import { SessionMutex } from './mutex.js'
import { JumpServerSession, type ExecOutcome, type SessionRuntimeConfig, type SessionStatus } from './session.js'
import { SessionState } from './state-machine.js'
import { sleep } from './timing.js'
import { normalizedRedactedCommand, redactCommandSecrets } from '../security/command-redaction.js'

export interface AuditRecord {
  timestamp: string
  operation: string
  gateway: string
  target: string | null
  hostname: string | null
  /** Persisted compatibility field; always redacted, never the raw execution command. */
  command: string | null
  redactedCommand?: string
  normalizedRedactedCommand?: string
  /** V0.3.1: who ran the command — AGENT (tool path), HUMAN (sidebar input) or SYSTEM_PROFILE (ops sweep). */
  actor: 'AGENT' | 'HUMAN' | 'SYSTEM_PROFILE'
  /** Risk class (READ/PRIVILEGED_READ/UNKNOWN/MODIFY/DANGEROUS). */
  risk: string
  /** V0.3.1: why the classifier chose this risk (audit must explain itself). */
  riskReason?: string
  /** V0.3.1: matched semantic rule id (systemctl.status / unknown.command / ...). */
  riskRuleId?: string
  riskConfidence?: string
  classifierVersion?: number
  /** V0.3.1: whitespace-normalized command. */
  normalizedCommand?: string
  /** V0.3.1: whether a human approval was required for this command. */
  approvalRequired: boolean
  /** V0.3.1: 'none' | 'approved' | 'denied' — the gate outcome. */
  approvalResult: string
  /** V0.4.0: MCP request id that produced this record (AI task correlation). */
  toolCallId?: string
  /** V0.4.0: one id per jumpserver_batch / inspect / topology call. */
  batchId?: string
  /** V0.4.0: long-running job id (jumpserver_job_start). */
  taskId?: string
  /** V0.4.0: index of this command inside its batch (audit ordering). */
  batchIndex?: number
  /** V0.4.0: monotonic per-process write sequence (stable ordering in the JSONL). */
  sequence?: number
  permissionMode: PermissionMode
  result: string
  exitCode: number | null
  durationMs: number | null
}

/** status()/connect()/enter()/leave()/close() return this extended shape. */
export type ManagerStatus = SessionStatus & { configured: boolean; permissionMode: PermissionMode }

export interface SessionManagerOptions {
  getConfig: () => JumpServerConfig
  resolvePassword: () => Promise<string | undefined>
  onAudit?: (record: AuditRecord) => void | Promise<void>
  onLog?: (message: string) => void
  /** DSH-fiber timer injection (ctx.timeout); falls back to global setTimeout. */
  scheduleTimeout?: (fn: () => void, delayMs: number) => () => void
  /** Test seam: replaces the real ssh2 transport (forwarded to the session). */
  wireFactory?: import('./session.js').WireFactory
  /** V0.2: live terminal mirror sink; every PTY input/output/state/target event lands here. */
  observer?: TerminalObserver
}

export interface ExecRequest {
  command: string
  timeoutMs?: number
  risk: string
  /** V0.3.1: audit actor — defaults to AGENT for the tool path. */
  actor?: 'AGENT' | 'HUMAN' | 'SYSTEM_PROFILE'
  /** V0.3.1: full classification (rule/reason/confidence) so the audit is self-explanatory. */
  classification?: { risk: string; reason?: string; ruleId?: string; confidence?: string; classifierVersion?: number; normalizedCommand?: string }
  /** V0.3.1: approval outcomes from the gate. */
  approvalRequired?: boolean
  approvalResult?: string
  /** V0.4.0: MCP request id (audit correlation). */
  toolCallId?: string
  /** V0.4.0: batch/inspect run id (audit correlation). */
  batchId?: string
  signal?: AbortSignal
}

export interface RunRequest {
  target: string
  command: string
  timeoutMs?: number
  risk: string
  signal?: AbortSignal
  /** V0.3.1: audit actor (default AGENT). */
  actor?: 'AGENT' | 'HUMAN' | 'SYSTEM_PROFILE'
  /** V0.3.1: full classification for the audit. */
  classification?: { risk: string; reason?: string; ruleId?: string; confidence?: string; classifierVersion?: number; normalizedCommand?: string }
  approvalRequired?: boolean
  approvalResult?: string
  /** V0.4.0: MCP request id (audit correlation). */
  toolCallId?: string
  /** V0.4.0: batch/inspect run id (audit correlation). */
  batchId?: string
  /** Runs right after navigation (target verified) and immediately before exec. */
  beforeExec?: () => Promise<void>
}

/** One command inside a target-affinity batch turn. */
export interface BatchCommandRequest {
  command: string
  timeoutMs?: number
  risk: string
  /** V0.3.1: audit actor for this batch command (SYSTEM_PROFILE for ops sweeps). */
  actor?: 'AGENT' | 'HUMAN' | 'SYSTEM_PROFILE'
  /** V0.3.1: full classification for the audit. */
  classification?: { risk: string; reason?: string; ruleId?: string; confidence?: string; classifierVersion?: number; normalizedCommand?: string }
  approvalRequired?: boolean
  approvalResult?: string
  /** V0.4.0: MCP request id (audit correlation). */
  toolCallId?: string
  /** V0.4.0: batch/inspect run id (audit correlation). */
  batchId?: string
  /** V0.4.0: index of this command inside its batch (audit ordering). */
  batchIndex?: number
  /** Runs right after the target is verified and immediately before this command's exec. */
  beforeExec?: () => Promise<void>
}

/** All commands for one target: the manager enters the target ONCE and runs every command before leaving. */
export interface TargetBatchRequest {
  target: string
  commands: BatchCommandRequest[]
  signal?: AbortSignal
  /** V0.4.0: MCP request id (audit correlation). */
  toolCallId?: string
  /** V0.4.0: one id for the whole batch run (inspect/topology/batch). */
  batchId?: string
}

export interface BatchCommandResult {
  command: string
  executionState: string
  exitCode: number | null
  output: string
  truncated: boolean
  durationMs: number
  error: { code: string; message: string } | null
}

export interface TargetBatchResult {
  target: string
  hostname: string | null
  /** Navigation-level failure (enter/menu problems): commands stay empty. */
  error: { code: string; message: string } | null
  commands: BatchCommandResult[]
}

const RECONNECT_LIMIT = 2
const RECONNECT_BACKOFF = [1000, 3000] as const

/** V0.4.0: monotonic audit write sequence (per process). */
let auditSequence = 0

export function toRuntimeConfig(cfg: JumpServerConfig, password: string, wireFactory?: import('./session.js').WireFactory): SessionRuntimeConfig {
  return {
    host: cfg.host,
    port: cfg.port,
    username: cfg.username,
    password,
    connectTimeoutMs: cfg.connectTimeout * 1000,
    enterAssetMs: DEFAULT_TIMEOUTS.enterAsset,
    probeMs: DEFAULT_TIMEOUTS.probe,
    commandMs: cfg.commandTimeout * 1000,
    leaveMs: DEFAULT_TIMEOUTS.leave,
    listAssetsMs: DEFAULT_TIMEOUTS.listAssets,
    wireFactory,
  }
}

/**
 * Plugin singleton: owns the one JumpServer session, serializes every
 * operation through a mutex, observes disconnect and schedules bounded
 * reconnects while idle. A command that loses its wire returns an UNKNOWN
 * outcome and is NEVER re-executed.
 */
/** One cached asset-list capture (per conversation manager). */
interface AssetCaptureCache {
  at: number
  assets: AssetEntry[]
  rawRows: number
  parsedRows: number
  health: AssetHealth
  rawText: string
  truncated: boolean
  paged: boolean
  page: number | null
  pageSize: number | null
  totalPages: number | null
  reportedTotal: number | null
  complete: boolean
}

/**
 * V0.2.5 P0: only a TRUSTWORTHY capture may enter the 5-minute per-conversation
 * cache — a healthy parse, or a footer-CONFIRMED empty account (总数量 0).
 * Timed out / incomplete / parse-failed / paged / truncated captures are
 * returned to the caller but NEVER cached, so a retry re-sends 'p' instead of
 * re-filtering a wrong capture.
 */
function isCacheableAssetResult(parsed: AssetListResult, raw: { truncated: boolean; paged: boolean }): boolean {
  if (raw.paged || raw.truncated || parsed.truncated) return false
  if (parsed.health === 'ok') return true
  return parsed.health === 'ASSET_LIST_EMPTY' && parsed.reportedTotal === 0 && parsed.complete
}

/** Project a cached capture back into an AssetListResult (for filtering). */
function cacheToResult(cache: AssetCaptureCache): AssetListResult {
  return {
    assets: cache.assets,
    truncated: cache.truncated,
    paged: cache.paged,
    rawText: cache.rawText,
    rawRows: cache.rawRows,
    parsedRows: cache.parsedRows,
    page: cache.page,
    pageSize: cache.pageSize,
    totalPages: cache.totalPages,
    reportedTotal: cache.reportedTotal,
    complete: cache.complete,
    health: cache.health,
  }
}

export class SessionManager {
  private session: JumpServerSession | null = null
  private mutex = new SessionMutex()
  private reconnectAttempts = 0
  private reconnectTimer: (() => void) | null = null
  private disposed = false
  private lastError: string | null = null
  /** V0.2.4 P1: one 'p' capture is reused locally for later filtered queries. */
  private assetCache: AssetCaptureCache | null = null
  /** V0.2.5: a connection dropped during a pending op; reconnect once the turn settles. */
  private reconnectPending = false
  /**
   * V0.4.0: id of the streaming job currently owning the PTY (tail -f …).
   * While set, no other command may use the shell — mixing commands into a
   * streaming job's output would corrupt both.
   */
  private activeJob: string | null = null

  constructor(private readonly options: SessionManagerOptions) {}

  /**
   * Run one mutex turn, then flush any reconnect that was deferred while the
   * turn held the queue (V0.2.5): a wire drop mid-operation used to lose the
   * reconnect entirely because onSessionLost returned early on hasPendingOp.
   */
  private async queue<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    try {
      return await this.mutex.run(fn, signal)
    } finally {
      this.flushPendingReconnect()
    }
  }

  private flushPendingReconnect(): void {
    if (this.disposed) return
    if (!this.reconnectPending) return
    this.reconnectPending = false
    const session = this.session
    if (session !== null && session.isLive()) return // already recovered
    this.scheduleReconnect()
  }

  status(): ManagerStatus {
    const cfg = this.options.getConfig()
    const base = this.session?.status() ?? {
      state: SessionState.DISCONNECTED as SessionState,
      gateway: cfg.host + ':' + cfg.port,
      target: null,
      hostname: null,
      user: null,
      pwd: null,
      connectedAt: null,
      lastActivityAt: null,
      reconnectCount: 0,
    }
    return {
      ...base,
      configured: Boolean(cfg.host && cfg.username),
      permissionMode: cfg.permissionMode,
    }
  }

  /** True while a streaming job owns the PTY (see activeJob). */
  hasActiveJob(): boolean {
    return this.activeJob !== null
  }

  /** Fail fast when a streaming job owns the shell instead of corrupting its output. */
  private assertNoActiveJob(): void {
    if (this.activeJob !== null) {
      throw new JumpServerError('SESSION_BUSY', 'a streaming job (' + this.activeJob + ') owns this shell; stop it with jumpserver_job_stop first')
    }
  }

  /** Public connect: serialized through the session queue. */
  async connect(signal?: AbortSignal): Promise<ManagerStatus> {
    return this.queue(() => this.connectLocked(signal), signal)
  }

  /**
   * V0.4.0 P0: out-of-band interrupt — Ctrl+C reaches the remote shell even
   * while a command/batch is in flight (the queue is deliberately bypassed;
   * queueing would only deliver the interrupt after the running op finished).
   */
  async interrupt(): Promise<{ sent: boolean; verified: boolean; state: string; target: string | null }> {
    const session = this.session
    if (session === null || !session.isLive()) {
      return { sent: false, verified: false, state: this.status().state, target: this.status().target }
    }
    const result = await session.interrupt()
    this.activeJob = null
    await this.audit({
      operation: 'interrupt',
      target: session.currentTarget,
      hostname: session.currentHostname,
      command: null,
      risk: 'READ',
      result: result.verified ? 'ok' : 'unverified',
      exitCode: null,
      durationMs: null,
    })
    return { sent: result.sent, verified: result.verified, state: result.state, target: session.currentTarget }
  }

  /**
   * Connect WITHOUT re-acquiring the queue. Only call this while the caller
   * already holds the mutex (e.g. inside run()); calling public connect()
   * from such a context would deadlock on the same lock.
   */
  private async connectLocked(signal?: AbortSignal): Promise<ManagerStatus> {
    this.cancelReconnect()
    const current = this.session
    if (current !== null && current.isLive()) return this.status()
    if (this.disposed) throw new JumpServerError('CONNECTION_LOST', 'JumpServer manager is disposed')
    const cfg = this.options.getConfig()
    if (cfg.enabled === false) {
      throw new JumpServerError('DISABLED', 'JumpServer is disabled in settings')
    }
    if (!cfg.host || !cfg.username || cfg.port < 1) {
      throw new JumpServerError('NOT_CONFIGURED', 'JumpServer host/username are not configured')
    }
    const password = await this.options.resolvePassword()
    if (password === undefined || password.length === 0) {
      throw new JumpServerError('NOT_CONFIGURED', 'JumpServer password is not configured (set ' + cfg.passwordEnv + ' or the password setting)')
    }
    try {
      if (current !== null) await current.close()
    } catch {
      /* stale session */
    }
    const observer = this.options.observer
    let prevState: SessionState | null = null
    const session = new JumpServerSession(toRuntimeConfig(cfg, password, this.options.wireFactory), {
      onLost: () => this.onSessionLost(),
      onLog: (m) => this.options.onLog?.(m),
      onStateChange: (state) => {
        observer?.recordState(state, prevState)
        prevState = state
      },
      onInput: (text) => observer?.recordInput(text),
      onOutput: (chunk) => observer?.recordOutput(chunk),
      onTarget: (target, hostname, user, pwd) => observer?.recordTarget(target, hostname, user, pwd),
    })
    this.session = session
    try {
      await session.connect(signal)
      this.reconnectAttempts = 0
      this.lastError = null
      // A fresh connection may see a changed asset table; never reuse the old capture.
      this.assetCache = null
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : String(error)
      if (this.session === session) this.session = null
      throw error
    }
    return this.status()
  }

  async enter(target: string, signal?: AbortSignal): Promise<ManagerStatus> {
    return this.queue(async () => {
      const session = this.requireLiveSession()
      await session.enter(target, signal)
      await this.audit({ operation: 'enter', target, hostname: session.currentHostname, command: null, risk: 'READ', result: 'ok', exitCode: null, durationMs: null })
      return this.status()
    }, signal)
  }

  async exec(request: ExecRequest): Promise<{ status: ManagerStatus; outcome: ExecOutcome }> {
    return this.queue(async () => {
      const session = this.requireLiveSession()
      this.assertNoActiveJob()
      if (session.status().state !== SessionState.ASSET_SHELL) {
        throw new JumpServerError('NOT_IN_ASSET', 'exec requires an entered (verified) asset shell')
      }
      const started = Date.now()
      const outcome = await session.exec(request.command, { timeoutMs: request.timeoutMs, signal: request.signal })
      const durationMs = Date.now() - started
      await this.audit({
        operation: 'exec',
        target: session.currentTarget,
        hostname: session.currentHostname,
        command: request.command,
        risk: request.risk,
        actor: request.actor,
        classification: request.classification,
        approvalRequired: request.approvalRequired,
        approvalResult: request.approvalResult,
        toolCallId: request.toolCallId,
        batchId: request.batchId,
        result: outcome.executionState,
        exitCode: outcome.kind === 'completed' ? outcome.exitCode : null,
        durationMs,
      })
      return { status: this.status(), outcome }
    }, request.signal)
  }

  /** High-level run: connect -> (leave) -> enter -> exec, all in ONE queue slot. */
  async run(request: RunRequest): Promise<{ status: ManagerStatus; outcome: ExecOutcome; target: string | null; hostname: string | null }> {
    return this.queue(async () => {
      if (!this.options.getConfig().host || !this.options.getConfig().username) {
        throw new JumpServerError('NOT_CONFIGURED', 'JumpServer is not configured')
      }
      const session = await this.ensureConnectedLocked(request.signal)
      this.assertNoActiveJob()
      const st = await this.navigateToTarget(session, request.target, request.signal)
      if (request.beforeExec !== undefined) await request.beforeExec()
      const started = Date.now()
      const outcome = await session.exec(request.command, { timeoutMs: request.timeoutMs, signal: request.signal })
      const durationMs = Date.now() - started
      await this.audit({
        operation: 'run',
        target: st.target,
        hostname: st.hostname,
        command: request.command,
        risk: request.risk,
        actor: request.actor,
        classification: request.classification,
        approvalRequired: request.approvalRequired,
        approvalResult: request.approvalResult,
        toolCallId: request.toolCallId,
        batchId: request.batchId,
        result: outcome.executionState,
        exitCode: outcome.kind === 'completed' ? outcome.exitCode : null,
        durationMs,
      })
      return { status: this.status(), outcome, target: st.target, hostname: st.hostname }
    }, request.signal)
  }

  /** Shared navigation: menu -> enter(target) -> verified status. */
  private async navigateToTarget(session: JumpServerSession, target: string, signal?: AbortSignal): Promise<SessionStatus> {
    let st = session.status()
    if (st.state === SessionState.ASSET_SHELL && st.target === target) return st
    if (st.state === SessionState.ASSET_SHELL) {
      await session.leave(signal)
      st = session.status()
      if (st.state !== SessionState.JUMPSERVER_MENU) {
        throw new JumpServerError('UNKNOWN_STATE', 'not reliably at the JumpServer menu after leaving an asset')
      }
    }
    if (st.state === SessionState.UNKNOWN || st.state === SessionState.ERROR) {
      throw new JumpServerError('UNKNOWN_STATE', 'current session state is not reliably navigable; reconnect and retry')
    }
    if (st.state !== SessionState.JUMPSERVER_MENU) {
      throw new JumpServerError('NOT_AT_MENU', 'cannot navigate: session is in state ' + st.state)
    }
    await session.enter(target, signal)
    return session.status()
  }

  /**
   * V0.4.0: start a streaming job (tail -f / journalctl -f / top / ping / tcpdump).
   * Navigation happens inside the queue; the command is then written RAW (no
   * completion marker) and its output is harvested from the observer stream by
   * the job store. The job owns the PTY until it is stopped.
   */
  async startJob(request: { jobId: string; target: string; command: string; signal?: AbortSignal; toolCallId?: string }): Promise<{ target: string | null; hostname: string | null; state: string; startSeq: number }> {
    return this.queue(async () => {
      this.assertNoActiveJob()
      const cfg = this.options.getConfig()
      if (cfg.enabled === false) throw new JumpServerError('DISABLED', 'JumpServer is disabled in settings')
      if (!cfg.host || !cfg.username) throw new JumpServerError('NOT_CONFIGURED', 'JumpServer is not configured')
      const session = await this.ensureConnectedLocked(request.signal)
      const st = await this.navigateToTarget(session, request.target, request.signal)
      const startSeq = this.options.observer?.cursorSeq ?? 0
      if (!session.writeLine(request.command)) {
        throw new JumpServerError('CONNECTION_LOST', 'could not write the job command to the PTY')
      }
      this.activeJob = request.jobId
      await this.audit({
        operation: 'job-start',
        target: st.target,
        hostname: st.hostname,
        command: request.command,
        risk: 'READ',
        taskId: request.jobId,
        toolCallId: request.toolCallId,
        result: 'RUNNING',
        exitCode: null,
        durationMs: null,
      })
      return { target: st.target, hostname: st.hostname, state: session.state, startSeq }
    }, request.signal)
  }

  /** V0.4.0: stop a streaming job — Ctrl+C (out-of-band) and release the PTY. */
  async stopJob(jobId: string): Promise<{ sent: boolean; state: string }> {
    const session = this.session
    if (this.activeJob !== null && this.activeJob !== jobId) {
      throw new JumpServerError('SESSION_BUSY', 'another job (' + this.activeJob + ') owns this shell')
    }
    this.activeJob = null
    const sent = session?.sendInterrupt() ?? false
    await this.audit({
      operation: 'job-stop',
      target: session?.currentTarget ?? null,
      hostname: session?.currentHostname ?? null,
      command: null,
      risk: 'READ',
      taskId: jobId,
      result: sent ? 'ok' : 'not-sent',
      exitCode: null,
      durationMs: null,
    })
    return { sent, state: this.status().state }
  }

  /**
   * Target-affinity batch: navigate to ONE target, run EVERY command in its
   * task, then return. All commands of one target execute inside a single
   * mutex turn, so a multi-target batch can never bounce between assets.
   * Navigation problems are captured per target (error + empty commands)
   * instead of aborting the whole batch; per-command failures are captured
   * per command so one bad command cannot mask its neighbours' results.
   */
  async runTargetBatch(request: TargetBatchRequest): Promise<TargetBatchResult> {
    return this.queue(async () => {
      const cfg = this.options.getConfig()
      if (cfg.enabled === false) {
        return { target: request.target, hostname: null, error: { code: 'DISABLED', message: 'JumpServer is disabled in settings' }, commands: [] }
      }
      if (!cfg.host || !cfg.username) {
        return { target: request.target, hostname: null, error: { code: 'NOT_CONFIGURED', message: 'JumpServer is not configured' }, commands: [] }
      }
      let session: JumpServerSession
      try {
        session = await this.ensureConnectedLocked(request.signal)
        this.assertNoActiveJob()
      } catch (error) {
        return { target: request.target, hostname: null, error: this.errorDetail(error), commands: [] }
      }
      let st: SessionStatus
      try {
        st = await this.navigateToTarget(session, request.target, request.signal)
      } catch (error) {
        return { target: request.target, hostname: session.currentHostname, error: this.errorDetail(error), commands: [] }
      }
      const results: BatchCommandResult[] = []
      for (const item of request.commands) {
        if (request.signal?.aborted === true) {
          throw new AbortRequestedError()
        }
        try {
          if (item.beforeExec !== undefined) await item.beforeExec()
          const started = Date.now()
          const outcome = await session.exec(item.command, {
            timeoutMs: item.timeoutMs,
            signal: request.signal,
          })
          const durationMs = Date.now() - started
          results.push({
            command: item.command,
            executionState: outcome.executionState,
            exitCode: outcome.kind === 'completed' ? outcome.exitCode : null,
            output: outcome.output,
            truncated: outcome.kind === 'completed' || outcome.kind === 'timeout' ? outcome.truncated : false,
            durationMs,
            error: null,
          })
          await this.audit({
            operation: 'run-batch-cmd',
            target: session.currentTarget,
            hostname: session.currentHostname,
            command: item.command,
            risk: item.risk,
            actor: item.actor,
            classification: item.classification,
            approvalRequired: item.approvalRequired,
            approvalResult: item.approvalResult,
            toolCallId: item.toolCallId ?? request.toolCallId,
            batchId: item.batchId ?? request.batchId,
            batchIndex: item.batchIndex,
            result: outcome.executionState,
            exitCode: outcome.kind === 'completed' ? outcome.exitCode : null,
            durationMs,
          })
        } catch (error) {
          results.push({
            command: item.command,
            executionState: 'ERROR',
            exitCode: null,
            output: '',
            truncated: false,
            durationMs: 0,
            error: this.errorDetail(error),
          })
          await this.audit({
            operation: 'run-batch-cmd',
            target: session.currentTarget,
            hostname: session.currentHostname,
            command: item.command,
            risk: item.risk,
            actor: item.actor,
            classification: item.classification,
            approvalRequired: item.approvalRequired,
            approvalResult: item.approvalResult,
            toolCallId: item.toolCallId ?? request.toolCallId,
            batchId: item.batchId ?? request.batchId,
            batchIndex: item.batchIndex,
            result: 'error',
            exitCode: null,
            durationMs: null,
          })
          if (session.state === SessionState.COMMAND_RUNNING) break
        }
      }
      const final = session.status()
      return {
        target: request.target,
        hostname: st.hostname,
        error: null,
        commands: results,
      }
    }, request.signal)
  }

  private errorDetail(error: unknown): { code: string; message: string } {
    if (error instanceof JumpServerError) {
      return { code: error.code, message: error.message }
    }
    return { code: 'FAILED', message: error instanceof Error ? error.message : String(error) }
  }

    async leave(signal?: AbortSignal): Promise<ManagerStatus> {
    return this.queue(async () => {
      const session = this.requireLiveSession()
      await session.leave(signal)
      await this.audit({ operation: 'leave', target: null, hostname: null, command: null, risk: 'READ', result: 'ok', exitCode: null, durationMs: null })
      return this.status()
    }, signal)
  }

  /**
   * V0.2.3 P1 / V0.2.4: list the authorized assets (KoKo menu command 'p')
   * and filter locally. Read-only — the session stays at the JumpServer menu
   * (or, when the list turned out interactive, is collapsed to UNKNOWN so the
   * next op reconnects instead of typing into a pager). Never enters an asset.
   *
   * V0.2.4 caching: the raw (unfiltered) capture is cached per conversation
   * for assetCacheTtlSeconds, so repeated / filtered queries re-filter the
   * same capture instead of re-sending 'p' to KoKo. The cache is dropped when
   * the connection is re-established or the session is closed.
   */
  async listAssets(filter?: string, signal?: AbortSignal, refresh = false, group?: string): Promise<{
    assets: AssetEntry[]
    count: number
    filter: string | null
    group: string | null
    groupMatched: number
    truncated: boolean
    paged: boolean
    rawText: string
    rawRows: number
    parsedRows: number
    page: number | null
    pageSize: number | null
    totalPages: number | null
    reportedTotal: number | null
    complete: boolean
    health: AssetHealth
  }> {
    return this.queue(async () => {
      const session = await this.ensureConnectedLocked(signal)
      if (session.status().state !== SessionState.JUMPSERVER_MENU) {
        // A shell or unknown screen is not navigable for a menu query.
        throw new JumpServerError('NOT_AT_MENU', 'listAssets requires the JumpServer menu (leave the current asset first)')
      }
      const f = filter?.trim()
      const term = f && f.length > 0 ? f : null
      const ttlMs = Math.max(10, this.options.getConfig().assetCacheTtlSeconds ?? DEFAULT_ASSET_CACHE_TTL_SECONDS) * 1000
      let cache = refresh ? null : this.assetCache
      let truncated = false
      let paged = false
      let parsed: AssetListResult
      if (cache !== null && Date.now() - cache.at < ttlMs) {
        parsed = cacheToResult(cache)
        truncated = cache.truncated
        paged = cache.paged
      } else {
        // V0.2.6 P0 (single fact stream): the asset text is rebuilt from the
        // SAME normalized TerminalObserver event stream the sidebar renders.
        // Record the current event seq -> session writes p\r and completes ->
        // read every output event after that seq and clean them. The sidebar
        // and jumpserver_assets can never disagree about "the same 171 rows".
        const observer = this.options.observer
        const startSeq = observer?.cursorSeq ?? null
        const captured = await session.listAssets(undefined, signal)
        let text = captured.text
        let captureTruncated = captured.truncated
        if (observer !== undefined && startSeq !== null && observer.oldestSeq <= startSeq + 1) {
          const events = observer.snapshotSince(startSeq)
          const joined = events
            .filter((e) => e.type === 'output')
            .map((e) => (e as { data: string }).data)
            .join('')
          const clean = cleanAnsi(joined)
          if (clean.length > 0) text = clean
          captureTruncated = captured.truncated || clean.length >= MAX_ASSET_CAPTURE_BYTES
        }
        parsed = parseAssetList(text)
        truncated = captureTruncated || parsed.truncated
        paged = captured.paged
        if (isCacheableAssetResult(parsed, captured)) {
          this.assetCache = {
            at: Date.now(),
            assets: parsed.assets,
            rawRows: parsed.rawRows,
            parsedRows: parsed.parsedRows,
            health: parsed.health,
            rawText: parsed.rawText,
            truncated,
            paged,
            page: parsed.page,
            pageSize: parsed.pageSize,
            totalPages: parsed.totalPages,
            reportedTotal: parsed.reportedTotal,
            complete: parsed.complete,
          }
        } else {
          // V0.2.5 P0: never cache a failed/incomplete/paged/truncated capture.
          this.assetCache = null
        }
        await this.audit({
          operation: 'list-assets',
          target: null,
          hostname: null,
          command: 'p' + (refresh ? ' (refresh)' : '') + (term ? ' (filter=' + term + ')' : ''),
          risk: 'READ',
          result: captured.paged ? 'paged' : parsed.health + (this.assetCache === null ? ' (not-cached)' : ''),
          exitCode: null,
          durationMs: null,
        })
      }
      // V0.2.6: system asset group (alias) — OR-match configured keywords. An
      // unknown group name is a config typo, reported loudly, never "0 assets".
      const groupTerm = group?.trim() ?? null
      const groupKeywords = groupTerm !== null && groupTerm.length > 0 ? resolveGroupKeywords(this.options.getConfig().assetGroups, groupTerm) : null
      if (groupTerm !== null && groupTerm.length > 0 && groupKeywords === null) {
        throw new JumpServerError('INVALID_GROUP', 'unknown asset group "' + groupTerm + '"; configure assetGroups in settings (name -> keywords) or use a raw filter instead')
      }
      const groupedAll = groupKeywords !== null ? filterAssetsByGroup(parsed.assets, groupKeywords) : parsed.assets
      const matched = filterAssets(groupedAll, term ?? undefined)
      return {
        assets: matched,
        count: matched.length,
        filter: term,
        group: groupTerm !== null && groupTerm.length > 0 ? groupTerm : null,
        groupMatched: groupKeywords !== null ? groupedAll.length : 0,
        truncated,
        paged,
        rawText: parsed.rawText,
        rawRows: parsed.rawRows,
        parsedRows: parsed.parsedRows,
        page: parsed.page,
        pageSize: parsed.pageSize,
        totalPages: parsed.totalPages,
        reportedTotal: parsed.reportedTotal,
        complete: parsed.complete,
        health: parsed.health,
      }
    }, signal)
  }

  async close(): Promise<ManagerStatus> {
    return this.queue(async () => {
      this.cancelReconnect()
      // The PTY is gone; a stale asset capture must not survive a new session.
      this.assetCache = null
      const session = this.session
      this.session = null
      if (session !== null) {
        try {
          await session.close()
        } catch {
          /* already closed */
        }
      }
      this.reconnectAttempts = 0
      await this.audit({ operation: 'close', target: null, hostname: null, command: null, risk: 'READ', result: 'ok', exitCode: null, durationMs: null })
      return this.status()
    })
  }

  /** Called by the plugin's ctx.interval: close when idle past the threshold. */
  tickIdle(): void {
    if (this.disposed) return
    const session = this.session
    if (session === null) return
    const idleMs = this.options.getConfig().idleTimeout * 60 * 1000
    const last = session.lastActivityAt ?? 0
    if (last > 0 && Date.now() - last >= idleMs && session.state !== SessionState.COMMAND_RUNNING) {
      this.options.onLog?.('idle timeout: closing JumpServer session')
      void this.close().catch((e) => this.options.onLog?.('idle close failed: ' + String(e)))
    }
  }

  dispose(): void {
    this.disposed = true
    this.cancelReconnect()
    const session = this.session
    this.session = null
    if (session !== null) {
      void session.close().catch(() => undefined)
    }
  }

  get lastErrorMessage(): string | null {
    return this.lastError
  }

  private requireLiveSession(): JumpServerSession {
    const session = this.session
    if (session === null || !session.isLive()) {
      throw new JumpServerError('CONNECTION_LOST', 'no live JumpServer session; call connect or run first')
    }
    return session
  }

  /**
   * Ensure a live session WHILE ALREADY HOLDING the queue. Never re-enters
   * the mutex (that would deadlock with the outer run() turn).
   */
  private async ensureConnectedLocked(signal?: AbortSignal): Promise<JumpServerSession> {
    const session = this.session
    if (session !== null && session.isLive()) return session
    await this.connectLocked(signal)
    const next = this.session
    if (next === null || !next.isLive()) {
      throw new JumpServerError('CONNECTION_LOST', 'JumpServer connection could not be established')
    }
    return next
  }

  private onSessionLost(): void {
    if (this.disposed) return
    const cfg = this.options.getConfig()
    if (!cfg.autoReconnect) return
    const session = this.session
    // V0.2.5 P1: during a pending op the mutex still owns the turn — do not
    // drop the reconnect. Mark it pending; queue() runs flushPendingReconnect
    // right after the op's turn settles (when hasPendingOp() is false again).
    if (session !== null && session.hasPendingOp()) {
      this.reconnectPending = true
      return
    }
    this.scheduleReconnect()
  }

  private scheduleReconnect(): void {
    if (this.disposed) return
    if (this.reconnectAttempts >= RECONNECT_LIMIT) {
      this.options.onLog?.('reconnect limit reached after ' + RECONNECT_LIMIT + ' attempts')
      return
    }
    this.reconnectAttempts += 1
    const index = Math.min(this.reconnectAttempts, RECONNECT_BACKOFF.length) - 1
    const delay = RECONNECT_BACKOFF[index] ?? 3000
    this.cancelReconnect()
    this.options.onLog?.('JumpServer connection lost; reconnect attempt ' + this.reconnectAttempts + ' in ' + delay + 'ms')
    const schedule = this.options.scheduleTimeout ?? ((fn: () => void, ms: number) => {
      const t = setTimeout(() => { fn() }, ms)
      return () => clearTimeout(t)
    })
    this.reconnectTimer = schedule(() => {
      this.reconnectTimer = null
      if (this.disposed) return
      void this.connect().catch((e) => {
        this.options.onLog?.('reconnect failed: ' + String(e))
      })
    }, delay)
  }

  private cancelReconnect(): void {
    this.reconnectTimer?.()
    this.reconnectTimer = null
  }

  private async audit(partial: {
    operation: string
    target?: string | null
    hostname?: string | null
    command?: string | null
    /** V0.3.1: AGENT by default; the manual bridge passes HUMAN; ops sweeps pass SYSTEM_PROFILE. */
    actor?: 'AGENT' | 'HUMAN' | 'SYSTEM_PROFILE'
    classification?: { risk: string; reason?: string; ruleId?: string; confidence?: string; classifierVersion?: number; normalizedCommand?: string }
    approvalRequired?: boolean
    approvalResult?: string
    /** V0.4.0: MCP request id / batch id / job id (AI task correlation). */
    toolCallId?: string
    batchId?: string
    taskId?: string
    /** V0.4.0: index of this command inside its batch (audit ordering). */
    batchIndex?: number
    risk: string
    result: string
    exitCode?: number | null
    durationMs?: number | null
  }): Promise<void> {
    const cfg = this.options.getConfig()
    if (!cfg.enableAudit) return
    if (this.options.onAudit === undefined) return
    const session = this.session
    const classification = partial.classification
    const redactedCommand = partial.command !== null && partial.command !== undefined ? redactCommandSecrets(partial.command) : null
    const record: AuditRecord = {
      timestamp: new Date().toISOString(),
      operation: partial.operation,
      gateway: cfg.host + ':' + cfg.port,
      target: partial.target ?? (session?.currentTarget ?? null),
      hostname: partial.hostname ?? (session?.currentHostname ?? null),
      command: redactedCommand,
      redactedCommand: redactedCommand ?? undefined,
      normalizedRedactedCommand: redactedCommand !== null ? normalizedRedactedCommand(redactedCommand) : undefined,
      actor: partial.actor ?? 'AGENT',
      risk: partial.risk,
      riskReason: classification?.reason,
      riskRuleId: classification?.ruleId,
      riskConfidence: classification?.confidence,
      classifierVersion: classification?.classifierVersion,
      normalizedCommand: redactedCommand !== null
        ? normalizedRedactedCommand(classification?.normalizedCommand ?? redactedCommand)
        : undefined,
      approvalRequired: partial.approvalRequired ?? false,
      approvalResult: partial.approvalResult ?? 'none',
      toolCallId: partial.toolCallId,
      batchId: partial.batchId,
      taskId: partial.taskId,
      sequence: ++auditSequence,
      batchIndex: partial.batchIndex,
      permissionMode: cfg.permissionMode,
      result: partial.result,
      exitCode: partial.exitCode ?? null,
      durationMs: partial.durationMs ?? null,
    }
    try {
      await this.options.onAudit(record)
    } catch (error) {
      this.options.onLog?.('audit write failed: ' + String(error))
    }
  }
}

export { AbortRequestedError, JumpServerError }
