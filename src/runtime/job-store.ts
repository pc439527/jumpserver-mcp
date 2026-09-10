/**
 * JobStore (V0.4.0) — long-running / streaming commands that do NOT fit the
 * "run until the completion marker appears" model:
 *
 *   tail -f /usr/weaver/Resin4/log/stdout.log
 *   journalctl -f -u nginx
 *   tcpdump -i any port 8080
 *   top -b
 *
 * A job owns the PTY until it is stopped (the manager refuses any other
 * command meanwhile with SESSION_BUSY). Output is harvested incrementally from
 * the conversation's TerminalObserver, never from a captured command buffer.
 *
 * V0.4.5 (Job lifecycle & isolation correctness):
 *  - `stop()` is idempotent / concurrent-safe: two callers (maxDuration pump +
 *    the manual jumpserver_job_stop) share ONE in-flight promise, so the
 *    second caller can never decide STOPPED while the first is still probing
 *    and mask a real LOST;
 *  - every job is scoped to its conversation: read/list/stop/stopAll take a
 *    sessionId, and the RUNNING cap is per conversation, not per process;
 *  - a job is LOST as soon as the manager's PTY ownership no longer points at
 *    it (session closed, transport lost, reconnect replaced the session) —
 *    the old DISCONNECTED-only check missed a reconnect that landed within
 *    one pump interval;
 *  - `read()` is a real cursor read (`nextSeq`), not "the tail of the buffer".
 */
import { randomHex } from '../jumpserver/timing.js'
import type { SessionRegistry } from '../jumpserver/session-registry.js'

export type JobState = 'RUNNING' | 'STOPPING' | 'VERIFYING' | 'STOPPED' | 'LOST'

export interface JobRecord {
  id: string
  sessionId: string
  target: string
  hostname: string | null
  command: string
  state: JobState
  startedAt: number
  stoppedAt: number | null
  maxDurationMs: number
  bytes: number
  truncated: boolean
  error: string | null
  /** TerminalObserver event seq of the last event harvested by pump(). */
  lastSeq: number
  /**
   * V0.4.5 cursor space: absolute number of output characters this job has
   * ever produced. `output` only ever holds the tail, so the absolute cursor
   * of `output[0]` is `producedChars - output.length`.
   */
  producedChars: number
  /** V0.4.5: absolute cursor delivered by the last implicit read(). */
  readCursor: number
  output: string
}

/** What a cursor read returns: the window plus the cursor to pass next time. */
export interface JobReadView extends JobRecord {
  /** Pass as `sinceSeq` on the next read; equals the absolute end cursor. */
  nextSeq: number
  /** Chars the caller asked for that had already been evicted from the buffer. */
  droppedChars: number
  /** True when the returned window does not reach the end of the buffer. */
  partial: boolean
  /** 'cursor' (incremental window) | 'full' (whole remaining buffer). */
  mode: 'cursor' | 'full'
}

/** Hard caps: one conversation must not be able to flood memory or the PTY. */
export const MAX_JOBS = 8
export const MAX_JOB_DURATION_MS = 15 * 60 * 1000
export const DEFAULT_JOB_DURATION_MS = 5 * 60 * 1000
const MAX_JOB_OUTPUT_BYTES = 256 * 1024

export interface JobStartOptions {
  sessionId: string
  target: string
  command: string
  maxDurationMs?: number
  signal?: AbortSignal
  toolCallId?: string
  /** V0.4.3: real classification — the audit must NOT hardcode READ. */
  classification?: { risk: string; reason?: string; ruleId?: string; confidence?: string; classifierVersion?: number; normalizedCommand?: string }
  /** V0.4.3: approval outcome recorded in the audit. */
  approvalRequired?: boolean
  approvalResult?: string
  /**
   * V0.4.4: deferred permission gate. The SessionManager runs this INSIDE its
   * queue, AFTER the target is navigated but BEFORE the command is written to
   * the PTY. When this throws COMMAND_APPROVAL_REQUIRED, the manager writes
   * a `denied` audit and refuses to claim the PTY.
   */
  beforeExec?: () => Promise<void>
}

export interface JobReadOptions {
  /** Conversation the caller is on — a job of another scope is invisible. */
  sessionId?: string
  maxChars?: number
  /** Explicit absolute cursor (from a previous `nextSeq`). */
  sinceSeq?: number | null
  full?: boolean
}

export class JobStore {
  private readonly jobs = new Map<string, JobRecord>()
  /**
   * V0.4.5: one in-flight stop per job. A second stop() for the same id
   * awaits the FIRST promise instead of re-deciding the outcome — the V0.4.4
   * race let caller B observe state VERIFYING, skip the probe branch and
   * stamp STOPPED while caller A's probe later failed with LOST.
   */
  private readonly stopInflight = new Map<string, Promise<JobRecord>>()
  private timer: (() => void) | null = null

  constructor(private readonly registry: SessionRegistry) {}

  async start(options: JobStartOptions): Promise<JobRecord> {
    const bundle = this.registry.get(options.sessionId)
    if (bundle === undefined) throw new Error('no live session for this conversation')
    // V0.4.5: the cap is per conversation. Counting every process-wide RUNNING
    // job let conversation B exhaust conversation A's job budget.
    const running = [...this.jobs.values()].filter((j) => j.state === 'RUNNING' && j.sessionId === options.sessionId)
    if (running.length >= MAX_JOBS) {
      throw new Error('too many running jobs (max ' + MAX_JOBS + '); stop one with jumpserver_job_stop first')
    }
    const id = 'jsjob_' + randomHex(6)
    const maxDurationMs = Math.min(
      Math.max(1000, Math.floor(options.maxDurationMs ?? DEFAULT_JOB_DURATION_MS)),
      MAX_JOB_DURATION_MS,
    )
    const started = await bundle.manager.startJob({
      jobId: id,
      target: options.target,
      command: options.command,
      signal: options.signal,
      toolCallId: options.toolCallId,
      classification: options.classification,
      approvalRequired: options.approvalRequired,
      // V0.4.4: the manager decides the real approval outcome (approved vs
      // denied) based on whether beforeExec threw. tools-ops must NOT
      // pre-decide this from a synchronous flag.
      approvalResult: undefined,
      beforeExec: options.beforeExec,
    })
    const record: JobRecord = {
      id,
      sessionId: options.sessionId,
      target: started.target ?? options.target,
      hostname: started.hostname,
      command: options.command,
      state: 'RUNNING',
      startedAt: Date.now(),
      stoppedAt: null,
      maxDurationMs,
      bytes: 0,
      truncated: false,
      error: null,
      lastSeq: started.startSeq,
      producedChars: 0,
      readCursor: 0,
      output: '',
    }
    this.jobs.set(id, record)
    this.ensureTimer()
    return record
  }

  /** Harvest new observer output for every running job; auto-stop on timeout. */
  pump(): void {
    for (const job of this.jobs.values()) {
      if (job.state !== 'RUNNING') continue
      const bundle = this.registry.get(job.sessionId)
      if (bundle === undefined) {
        this.finish(job, 'LOST', 'session bundle is gone')
        continue
      }
      const status = bundle.manager.status()
      if (status.state === 'DISCONNECTED') {
        this.finish(job, 'LOST', 'ssh connection lost')
        continue
      }
      // V0.4.5: PTY ownership is the authority. A reconnect that completes
      // inside one pump interval used to hide the loss entirely — the old
      // check only looked at DISCONNECTED and the fresh session reported
      // ASSET_SHELL again, so a job whose shell is gone stayed RUNNING.
      const owner = typeof bundle.manager.activeJobId === 'function' ? bundle.manager.activeJobId() : job.id
      if (owner !== job.id) {
        this.finish(job, 'LOST', 'the remote shell is no longer owned by this job')
        continue
      }
      const events = bundle.observer.snapshotSince(job.lastSeq)
      for (const event of events) {
        if (event.seq > job.lastSeq) job.lastSeq = event.seq
        if (event.type !== 'output') continue
        job.output += event.data
        job.bytes += event.data.length
        job.producedChars += event.data.length
      }
      if (job.output.length > MAX_JOB_OUTPUT_BYTES) {
        job.output = job.output.slice(job.output.length - MAX_JOB_OUTPUT_BYTES)
        job.truncated = true
      }
      if (Date.now() - job.startedAt >= job.maxDurationMs) {
        // V0.4.4: go through JobStore.stop so the STOPPED/LOST decision is
        // made by the SAME path the manual jumpserver_job_stop tool uses.
        // V0.4.3 fire-and-forgot the manager stopJob and stamped STOPPED
        // here regardless of whether the shell could be re-verified, which
        // masked a wedged PTY as a clean stop. Now: maxDuration is just
        // another caller of stop(); if verify fails the job becomes LOST.
        // V0.4.5: stop() de-duplicates, so a maxDuration stop racing a manual
        // stop shares one probe and one decision.
        void this.stop(job.id, 'maxDuration reached (' + Math.round(job.maxDurationMs / 1000) + 's)').catch(() => undefined)
      }
    }
    this.prune()
  }

  private finish(job: JobRecord, state: JobState, error: string | null): void {
    if (job.state === 'STOPPED' || job.state === 'LOST') return
    job.state = state
    job.stoppedAt = Date.now()
    job.error = error
  }

  /** One job, only when it belongs to the caller's conversation. */
  get(id: string, sessionId?: string): JobRecord | null {
    const job = this.jobs.get(id)
    if (job === undefined) return null
    if (sessionId !== undefined && job.sessionId !== sessionId) return null
    return this.view(job, 400)
  }

  /** The RUNNING job that currently owns this conversation's PTY, if any. */
  activeJobFor(sessionId: string): JobRecord | null {
    for (const job of this.jobs.values()) {
      if (job.state === 'RUNNING' && job.sessionId === sessionId) return job
    }
    return null
  }

  /**
   * Stop a job: Ctrl+C on the PTY (out-of-band), then PROVE the shell came
   * back. V0.4.3: the state walks RUNNING -> STOPPING -> VERIFYING ->
   * STOPPED/LOST so a wedged PTY is reported as LOST instead of being
   * silently presented as a healthy stopped job.
   * V0.4.4: accepts an optional `reason` (e.g. "maxDuration reached") so
   * the auto-stop pump records WHY the job ended without racing finish().
   * V0.4.5: concurrent-safe — the second caller awaits the first caller's
   * promise and never re-decides; `sessionId` refuses a cross-conversation id.
   */
  async stop(id: string, reason: string | null = null, sessionId?: string): Promise<JobRecord> {
    const job = this.jobs.get(id)
    if (job === undefined) throw new Error('unknown job: ' + id)
    if (sessionId !== undefined && job.sessionId !== sessionId) {
      throw new Error('unknown job: ' + id + ' (not part of this conversation)')
    }
    const inflight = this.stopInflight.get(id)
    if (inflight !== undefined) return inflight
    const promise = this.stopInternal(job, reason)
    this.stopInflight.set(id, promise)
    try {
      return await promise
    } finally {
      this.stopInflight.delete(id)
    }
  }

  private async stopInternal(job: JobRecord, reason: string | null): Promise<JobRecord> {
    const bundle = this.registry.get(job.sessionId)
    if (job.state === 'RUNNING') {
      job.state = 'STOPPING'
      if (bundle !== undefined) job.state = 'VERIFYING'
      try {
        const outcome = bundle !== undefined ? await bundle.manager.stopJob(job.id) : { sent: false, verified: false }
        if (!outcome.verified) {
          this.finish(job, 'LOST', reason ?? 'Ctrl+C sent but the remote shell could not be re-verified')
          return job
        }
      } catch (error) {
        // The shell may already be gone; the job is still terminal.
        this.finish(job, 'LOST', reason ?? (error instanceof Error ? error.message : String(error)))
        return job
      }
    }
    this.finish(job, 'STOPPED', reason)
    return job
  }

  /** Interrupt (Ctrl+C) every running job — console 中断 button / MCP abort. */
  async stopAll(sessionId?: string): Promise<number> {
    let count = 0
    for (const job of [...this.jobs.values()]) {
      if (job.state !== 'RUNNING') continue
      if (sessionId !== undefined && job.sessionId !== sessionId) continue
      await this.stop(job.id, null, sessionId).catch(() => undefined)
      count += 1
    }
    return count
  }

  /**
   * V0.4.5: cursor read. `full` returns the whole remaining buffer once;
   * otherwise the window starts at `sinceSeq` (or the cursor of the previous
   * implicit read) and the response carries `nextSeq` for the next call.
   * V0.4.4 returned the tail of the buffer on every call, so a model polling
   * in a loop re-consumed the same old log lines and re-judged them.
   */
  read(id: string, options: JobReadOptions = {}): JobReadView | null {
    this.pump()
    const job = this.jobs.get(id)
    if (job === undefined) return null
    if (options.sessionId !== undefined && job.sessionId !== options.sessionId) return null
    const maxChars = Math.max(1, options.maxChars ?? 8000)
    const outputStart = job.producedChars - job.output.length
    // `full` ignores the cursor entirely: the caller explicitly asked for the
    // whole buffered output, and the cursor is advanced past it afterwards.
    if (options.full === true) {
      const whole = job.output
      job.readCursor = job.producedChars
      return {
        ...this.view(job, Number.MAX_SAFE_INTEGER),
        output: whole,
        nextSeq: job.producedChars,
        droppedChars: outputStart,
        partial: false,
        mode: 'full',
      }
    }
    const implicit = options.sinceSeq === undefined || options.sinceSeq === null
    const requested = implicit ? job.readCursor : Number(options.sinceSeq)
    const begin = Math.max(Number.isFinite(requested) ? requested : 0, outputStart)
    const droppedChars = Math.max(0, outputStart - (Number.isFinite(requested) ? requested : 0))
    const offset = Math.min(Math.max(0, begin - outputStart), job.output.length)
    const chunk = job.output.slice(offset, offset + maxChars)
    const nextSeq = begin + chunk.length
    if (implicit) job.readCursor = nextSeq
    else if (nextSeq > job.readCursor) job.readCursor = nextSeq
    return {
      ...this.view(job, Number.MAX_SAFE_INTEGER),
      output: chunk,
      nextSeq,
      droppedChars,
      partial: nextSeq < job.producedChars,
      mode: 'cursor',
    }
  }

  /** Jobs of one conversation, or every job when no scope is given (console). */
  list(sessionId?: string): JobRecord[] {
    this.pump()
    const all = [...this.jobs.values()].filter((job) => sessionId === undefined || job.sessionId === sessionId)
    return all.map((job) => this.view(job, 400))
  }

  /** Never hand the whole (possibly 256KB) buffer to a list view. */
  private view(job: JobRecord, maxChars: number): JobRecord {
    if (job.output.length <= maxChars) return { ...job }
    return { ...job, output: '…(truncated) ' + job.output.slice(job.output.length - maxChars) }
  }

  private prune(): void {
    // Keep finished jobs for a while so the console can still show them.
    const now = Date.now()
    for (const [id, job] of [...this.jobs]) {
      if (job.state !== 'RUNNING' && job.stoppedAt !== null && now - job.stoppedAt > 10 * 60 * 1000) {
        this.jobs.delete(id)
        this.stopInflight.delete(id)
      }
    }
    if ([...this.jobs.values()].every((j) => j.state !== 'RUNNING')) this.stopTimer()
  }

  private ensureTimer(): void {
    if (this.timer !== null) return
    const handle = setInterval(() => {
      try {
        this.pump()
      } catch {
        /* a harvest failure must never kill the process */
      }
    }, 1000)
    handle.unref?.()
    this.timer = () => clearInterval(handle)
  }

  private stopTimer(): void {
    this.timer?.()
    this.timer = null
  }

  dispose(): void {
    this.stopTimer()
    this.jobs.clear()
    this.stopInflight.clear()
  }
}
