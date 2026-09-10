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
  lastSeq: number
  output: string
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

export class JobStore {
  private readonly jobs = new Map<string, JobRecord>()
  private timer: (() => void) | null = null

  constructor(private readonly registry: SessionRegistry) {}

  async start(options: JobStartOptions): Promise<JobRecord> {
    const bundle = this.registry.get(options.sessionId)
    if (bundle === undefined) throw new Error('no live session for this conversation')
    const running = [...this.jobs.values()].filter((j) => j.state === 'RUNNING')
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
      const events = bundle.observer.snapshotSince(job.lastSeq)
      for (const event of events) {
        if (event.seq > job.lastSeq) job.lastSeq = event.seq
        if (event.type !== 'output') continue
        job.output += event.data
        job.bytes += event.data.length
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

  /**
   * Stop a job: Ctrl+C on the PTY (out-of-band), then PROVE the shell came
   * back. V0.4.3: the state walks RUNNING -> STOPPING -> VERIFYING ->
   * STOPPED/LOST so a wedged PTY is reported as LOST instead of being
   * silently presented as a healthy stopped job.
   * V0.4.4: accepts an optional `reason` (e.g. "maxDuration reached") so
   * the auto-stop pump records WHY the job ended without racing finish().
   */
  async stop(id: string, reason: string | null = null): Promise<JobRecord> {
    const job = this.jobs.get(id)
    if (job === undefined) throw new Error('unknown job: ' + id)
    const bundle = this.registry.get(job.sessionId)
    if (job.state === 'RUNNING') {
      job.state = 'STOPPING'
      if (bundle !== undefined) job.state = 'VERIFYING'
      try {
        const outcome = bundle !== undefined ? await bundle.manager.stopJob(id) : { sent: false, verified: false }
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
      await this.stop(job.id).catch(() => undefined)
      count += 1
    }
    return count
  }

  read(id: string, maxChars = 8000): JobRecord | null {
    this.pump()
    const job = this.jobs.get(id)
    return job === undefined ? null : this.view(job, maxChars)
  }

  list(): JobRecord[] {
    this.pump()
    return [...this.jobs.values()].map((job) => this.view(job, 400))
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
  }
}
