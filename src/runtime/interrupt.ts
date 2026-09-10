/**
 * V0.4.5: ONE entry point for "stop whatever is running on this session's PTY".
 *
 * V0.4.4 had TWO owners racing for the same foreground job:
 *
 *   jumpserver_interrupt / console 中断
 *       manager.interrupt()          // Ctrl+C #1 + verify
 *       jobs.stopAll()               // JobStore.stop -> stopJob -> Ctrl+C #2
 *
 * JobStore.stop() itself was already correct (one ^C via
 * SessionManager.stopJob -> interruptAndVerify), but running it AFTER
 * manager.interrupt() interrupted the same job twice. The rule is simple:
 * a session with a streaming job has exactly ONE owner (the JobStore), so the
 * interrupt must be delegated to it; only a session with no streaming job may
 * send the raw out-of-band Ctrl+C.
 *
 * The MCP tool and the embedded console both call this function, so the two
 * entry points can never drift apart again.
 */
import type { JobRecord, JobStore } from './job-store.js'
import type { SessionManager } from '../jumpserver/session-manager.js'

export interface InterruptOutcome {
  /** How the stop was performed: a streaming job, a bare shell, or nothing. */
  mode: 'job' | 'shell' | 'none'
  sent: boolean
  verified: boolean
  state: string
  target: string | null
  jobId: string | null
  jobState: string | null
  /** Number of streaming jobs that were stopped (0 for the shell path). */
  jobsStopped: number
  message: string
}

export async function interruptSession(
  jobs: JobStore | null | undefined,
  manager: SessionManager,
  sessionId: string,
  reason = 'interrupt',
): Promise<InterruptOutcome> {
  const running: JobRecord[] =
    jobs !== null && jobs !== undefined
      ? jobs.list(sessionId).filter((job) => job.state === 'RUNNING')
      : []

  if (running.length > 0) {
    const stopped: JobRecord[] = []
    for (const job of running) {
      const result = await jobs!.stop(job.id, reason, sessionId).catch(() => null)
      if (result !== null) stopped.push(result)
    }
    const last = stopped.length > 0 ? stopped[stopped.length - 1]! : null
    const verified = last !== null && last.state === 'STOPPED'
    const state = manager.status().state
    const target = last?.target ?? manager.status().target
    const message =
      last === null
        ? '中断信号未能发送到流式任务所在会话'
        : last.state === 'STOPPED'
          ? '已停止流式任务 ' + last.id + '，远程 Shell 已重新验证可用（' + state + '）'
          : '已停止流式任务 ' + last.id + '，但 Shell 未能重新验证；会话已降级为 ' + state + '，需要重连后再操作'
    return {
      mode: 'job',
      sent: last !== null,
      verified,
      state,
      target,
      jobId: last?.id ?? null,
      jobState: last?.state ?? null,
      jobsStopped: stopped.length,
      message,
    }
  }

  const result = await manager.interrupt()
  return {
    mode: result.sent ? 'shell' : 'none',
    sent: result.sent,
    verified: result.verified,
    state: result.state,
    target: result.target,
    jobId: null,
    jobState: null,
    jobsStopped: 0,
    message: result.sent
      ? result.verified
        ? '中断信号已发送，远程 Shell 已重新验证可用（' + result.state + '）'
        : '中断信号已发送，但 Shell 未能重新验证；会话已降级为 UNKNOWN，需要重连后再操作'
      : '当前没有可中断的活动会话或远端 Shell',
  }
}
