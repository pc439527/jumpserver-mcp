/**
 * Tool helpers — ported from dsh-jumpserver src/tools/common.ts with the DSH
 * tool-host imports removed (HarnessError/TOOL_ABORTED replaced by plain
 * semantics: abort rethrows, everything else maps to a structured value).
 */
import { AbortRequestedError, JumpServerError } from '../jumpserver/errors.js'
// V0.4.5: one shared commandStatus -> error decode (exec + compare + runbook).
import { commandStatusToError } from '../jumpserver/command-status.js'
import type { ExecOutcome, SessionStatus } from '../jumpserver/session.js'
import type { TargetBatchResult } from '../jumpserver/session-manager.js'
import type { SessionBundle } from '../jumpserver/session-registry.js'
import { ANONYMOUS_SESSION } from '../jumpserver/session-registry.js'
import { SessionState } from '../jumpserver/state-machine.js'
import type { AssetEntry } from '../jumpserver/asset-list.js'
import { redactCommandSecrets } from '../security/command-redaction.js'
import type { ToolRunContext } from './context.js'

export type ResultValue = Record<string, unknown> & { ok: boolean }

/** Convert arbitrary runtime values into lossless JSON before tool completion. */
export function sanitizeToolOutput(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === undefined) return undefined
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'bigint') return value.toString()
  if (typeof value === 'function' || typeof value === 'symbol') return undefined
  if (value instanceof Date) return value.toISOString()
  if (value instanceof Error) {
    const code = (value as Error & { code?: unknown }).code
    const out: Record<string, unknown> = { name: value.name, message: value.message }
    if (code !== undefined) out['code'] = sanitizeToolOutput(code, seen)
    return out
  }
  if (typeof value === 'object') {
    if (seen.has(value)) return { name: 'SerializationError', message: 'circular tool output removed' }
    seen.add(value)
    if (value instanceof Map) {
      const out: Record<string, unknown> = {}
      for (const [key, item] of value.entries()) {
        const clean = sanitizeToolOutput(item, seen)
        if (clean !== undefined) out[String(key)] = clean
      }
      return out
    }
    if (value instanceof Set) return [...value].map((item) => sanitizeToolOutput(item) ?? null)
    if (Array.isArray(value)) return value.map((item) => sanitizeToolOutput(item) ?? null)
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) {
      const clean = sanitizeToolOutput(item, seen)
      if (clean !== undefined) out[key] = clean
    }
    return out
  }
  return null
}

export function toLosslessJsonValue<T>(value: T): T {
  return sanitizeToolOutput(value) as T
}

/**
 * Resolve the session scope id, in priority order:
 *
 *  1. `exec.sessionId` — the transport session the HOST assigned. Present when
 *     a single server process serves several conversations (HTTP/SSE, or a
 *     host that multiplexes). This is the only way to keep conversations
 *     apart inside one process.
 *  2. `JUMPSERVER_MCP_SESSION` — explicit operator override, for deployments
 *     that pin one scope per spawned process.
 *  3. `ANONYMOUS_SESSION` — the stdio default. MCP stdio is a
 *     process-per-client model: each WorkBuddy conversation spawns its own
 *     server, so a single fixed scope IS the conversation. Reusing one process
 *     across conversations without (1) or (2) collapses them into one session,
 *     which is why the runtime self-check refuses that combination.
 */
export function sessionIdOf(exec: ToolRunContext): string {
  const fromTransport = exec.sessionId
  if (fromTransport !== undefined && fromTransport.length > 0) return fromTransport
  const env = process.env['JUMPSERVER_MCP_SESSION']
  return env !== undefined && env.length > 0 ? env : ANONYMOUS_SESSION
}

/** The per-conversation bundle for one tool call (never shared across ids). */
export function bundleFor(exec: ToolRunContext, registry: { getOrCreate(sessionId: string): SessionBundle }): SessionBundle {
  return registry.getOrCreate(sessionIdOf(exec))
}

const LIVE_STATES = new Set<string>([
  SessionState.JUMPSERVER_MENU,
  SessionState.ASSET_SHELL,
  SessionState.COMMAND_RUNNING,
  SessionState.ENTERING_ASSET,
])

/** Strip null/undefined optional fields so the declared output shape stays satisfied. */
function dropNulls<T extends Record<string, unknown>>(value: T): T {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value)) {
    if (v !== null && v !== undefined) out[k] = v
  }
  return out as T
}

export function statusToValue(status: SessionStatus & { configured: boolean; permissionMode: string }): ResultValue {
  return dropNulls({
    ok: true,
    connected: LIVE_STATES.has(status.state),
    configured: status.configured,
    gateway: status.gateway,
    state: status.state,
    target: status.target,
    hostname: status.hostname,
    user: status.user,
    pwd: status.pwd,
    permissionMode: status.permissionMode,
    reconnectCount: status.reconnectCount,
  })
}

/**
 * V0.4.5: a COMPLETED exchange with a non-SUCCESS commandStatus becomes a
 * structured failure. Derived from the shared commandStatus mapping so exec
 * and compare can never report the same status with two different codes.
 */
function completedFailure(outcome: { commandStatus: string; exitCode: number; executionState: string }): { code?: string; message?: string } {
  const failure = commandStatusToError(outcome.commandStatus, {
    exitCode: outcome.exitCode,
    executionState: outcome.executionState,
  })
  return failure === null ? {} : { code: failure.code, message: failure.message }
}

export function execOutcomeToValue(status: SessionStatus & { configured: boolean; permissionMode: string }, outcome: ExecOutcome): ResultValue {  const base = {
    ok: true as boolean,
    gateway: status.gateway,
    state: status.state,
    target: status.target,
    hostname: status.hostname,
    durationMs: outcome.durationMs,
  }
  switch (outcome.kind) {
    case 'completed':
      return dropNulls({
        ...base,
        // V0.4.3: a COMPLETED exchange is not a SUCCESSFUL command. `jps -lv`
        // exiting 127 must NOT be reported as ok=true.
        ok: outcome.commandStatus === 'SUCCESS',
        completed: true,
        executionState: 'COMPLETED',
        commandStatus: outcome.commandStatus,
        exitCode: outcome.exitCode,
        output: outcome.output,
        truncated: outcome.truncated,
        // V0.4.5: one shared decode of commandStatus -> error code/message.
        ...completedFailure(outcome),
      } as unknown as Record<string, unknown>) as unknown as ResultValue
    case 'timeout':
      return dropNulls({
        ...base,
        ok: false,
        code: 'COMMAND_TIMEOUT',
        commandStatus: outcome.commandStatus,
        message:
          outcome.executionState === 'TIMEOUT'
            ? 'command timed out; the shell was interrupted (Ctrl+C) and re-verified - it remains usable'
            : 'command timed out and the shell could NOT be re-verified; the session collapsed to UNKNOWN - reconnect before continuing',
        completed: false,
        executionState: outcome.executionState,
        output: outcome.output,
        truncated: outcome.truncated,
      } as unknown as Record<string, unknown>) as unknown as ResultValue
    case 'signal-lost':
      return dropNulls({
        ...base,
        ok: false,
        code: 'CONNECTION_LOST',
        commandStatus: outcome.commandStatus,
        message: 'SSH connection lost during command execution',
        completed: false,
        executionState: 'UNKNOWN',
      } as unknown as Record<string, unknown>) as unknown as ResultValue
  }
}

/** Errors are constructed without secrets; one projection point for future redaction rules. */
function redactSecret(text: string): string {
  return text
}

export async function guardValue(exec: ToolRunContext, fn: () => Promise<ResultValue>): Promise<ResultValue> {
  try {
    return toLosslessJsonValue(await fn())
  } catch (error) {
    if (error instanceof AbortRequestedError || exec.signal.aborted === true) {
      throw new Error('tool call aborted')
    }
    if (error instanceof JumpServerError) {
      const value: ResultValue = { ok: false, code: error.code, message: redactSecret(error.message) }
      return value
    }
    return { ok: false, code: 'FAILED', message: redactSecret(error instanceof Error ? error.message : String(error)) }
  }
}

/** guardValue variant for tools that stream text (jumpserver_snapshot). */
export async function guardText(exec: ToolRunContext, fn: () => Promise<string>): Promise<string> {
  try {
    return await fn()
  } catch (error) {
    if (error instanceof AbortRequestedError || exec.signal.aborted === true) {
      throw new Error('tool call aborted')
    }
    if (error instanceof JumpServerError) {
      return renderResult({ ok: false, code: error.code, message: redactSecret(error.message) })
    }
    return renderResult({ ok: false, code: 'FAILED', message: redactSecret(error instanceof Error ? error.message : String(error)) })
  }
}

/** Compact text projection of one result value (single source of truth for tool output). */
export function renderResult(value: ResultValue): string {
  const lines: string[] = []
  if (value.ok === true) lines.push('ok')
  if (value.code !== undefined) lines.push('code: ' + String(value.code))
  if (value.message !== undefined) lines.push(String(value.message))
  if (value.state !== undefined) lines.push('state: ' + String(value.state))
  if (value.gateway !== undefined) lines.push('gateway: ' + String(value.gateway))
  if (value.target !== undefined) lines.push('target: ' + String(value.target))
  if (value.hostname !== undefined) lines.push('hostname: ' + String(value.hostname))
  if (value.user !== undefined) lines.push('user: ' + String(value.user))
  if (value.exitCode !== undefined) lines.push('exitCode: ' + String(value.exitCode))
  if (typeof value.output === 'string' && value.output.length > 0) {
    lines.push('--- output ---')
    lines.push(value.output)
  }
  return lines.join('\n')
}

/** Compact readable projection of a multi-target batch. */
export function renderBatchResult(tasks: TargetBatchResult[]): ResultValue {
  const lines: string[] = []
  let totalDurationMs = 0
  let failed = 0
  for (const task of tasks) {
    const durationMs = task.commands.reduce((acc, c) => acc + (c.durationMs ?? 0), 0)
    totalDurationMs += durationMs
    if (task.error !== null) failed += 1
    for (const cmd of task.commands) {
      // V0.4.3: a non-zero exit / timeout is a FAILURE, not a completed command.
      if (cmd.error !== null || (cmd.exitCode !== null && cmd.exitCode !== 0)) failed += 1
    }
    lines.push('target=' + task.target + ' hostname=' + (task.hostname ?? '?') + ' commands=' + task.commands.length)
    if (task.error !== null) lines.push('  error=' + task.error.code + ': ' + task.error.message)
    for (const cmd of task.commands) {
      const rc = cmd.exitCode !== null ? String(cmd.exitCode) : '?'
      lines.push('  $ ' + redactCommandSecrets(cmd.command))
      if (cmd.error !== null) {
        lines.push('    error=' + cmd.error.code + ': ' + cmd.error.message)
        continue
      }
      lines.push('    exitCode=' + rc + ' status=' + cmd.commandStatus + ' state=' + cmd.executionState + ' durationMs=' + cmd.durationMs)
      const out = cmd.output.trim()
      if (out.length > 0) {
        lines.push('    --- output ---')
        lines.push(indent(out, 4))
      }
    }
  }
  return {
    ok: failed === 0,
    completed: failed === 0,
    message: 'batch completed: ' + tasks.length + ' target(s), ' + failed + ' error(s), ' + totalDurationMs + ' ms',
    output: lines.join('\n'),
    durationMs: totalDurationMs,
  }
}

function indent(text: string, spaces: number): string {
  const pad = ' '.repeat(spaces)
  return text.split('\n').map((l) => pad + l).join('\n')
}

/** Upper bound for the optional rawText passthrough (keeps model context slim). */
const MAX_RAW_TEXT_CHARS = 16384

/** Canonical structured value for jumpserver_assets. */
export function assetsToValue(
  result: {
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
    health: string
  },
  options: { includeRawText?: boolean } = {},
): ResultValue {
  const rawText = options.includeRawText === true && result.rawText.length > 0
    ? (result.rawText.length > MAX_RAW_TEXT_CHARS ? result.rawText.slice(0, MAX_RAW_TEXT_CHARS) : result.rawText)
    : undefined
  return dropNulls({
    ok: true,
    count: result.assets.length,
    filter: result.filter,
    group: result.group,
    groupMatched: result.group !== null ? result.groupMatched : undefined,
    assets: result.assets.map((a) =>
      dropNulls({
        index: a.index,
        name: a.name,
        ip: a.ip,
        platform: a.platform,
        node: a.node,
        comment: a.comment,
      }),
    ),
    truncated: result.truncated,
    paged: result.paged,
    health: result.health,
    rawRows: result.rawRows,
    parsedRows: result.parsedRows,
    page: result.page,
    pageSize: result.pageSize,
    totalPages: result.totalPages,
    reportedTotal: result.reportedTotal,
    complete: result.complete,
    rawText,
  } as unknown as Record<string, unknown>) as unknown as ResultValue
}

/** Text projection for the assets result: one compact line per row + health notes. */
export function renderAssetsResult(value: ResultValue): string {
  const lines: string[] = []
  // Error values (ok:false) must render as errors — never as "ok count=0".
  if (value.ok !== true) {
    lines.push('code: ' + String(value.code ?? 'FAILED'))
    if (value.message !== undefined) lines.push(String(value.message))
    return lines.join('\n')
  }
  const filter = value['filter']
  const assets = value['assets'] instanceof Array ? (value['assets'] as Array<Record<string, unknown>>) : []
  const group = value['group']
  const groupLine = typeof group === 'string' && group.length > 0
    ? ' group=' + group + ' groupMatched=' + String(value['groupMatched'] ?? 0)
    : ''
  lines.push('ok' + (filter !== undefined && filter !== null ? ' filter=' + String(filter) : '') + groupLine + ' count=' + String(assets.length))
  if (value['paged'] === true) lines.push('note: the list appears to be paged; results may be incomplete')
  if (value['truncated'] === true) lines.push('note: captured screen was truncated; results may be incomplete')
  const health = value['health']
  if (health === 'ASSET_CAPTURE_TIMEOUT') {
    lines.push('note: no asset-list output was captured (ASSET_CAPTURE_TIMEOUT) - the result is NOT an empty account; retry once')
  } else if (health === 'ASSET_CAPTURE_INCOMPLETE') {
    lines.push('note: only the p echo / menu prompt was captured, no asset payload (ASSET_CAPTURE_INCOMPLETE) - NOT an empty account; retry once or call with refresh:true')
  } else if (health === 'ASSET_PARSE_FAILED') {
    const rawRows = value['rawRows'] !== undefined ? String(value['rawRows']) : '?'
    lines.push('note: captured ' + rawRows + ' raw rows but parsed 0 (ASSET_PARSE_FAILED) - KoKo table format is not understood; this is a parser bug, not "no assets"')
  } else if (health === 'ASSET_LIST_EMPTY') {
    lines.push('note: KoKo confirmed an empty account (总数量 0 / explicit no-asset notice) - this IS "no assets"')
  }
  // Footer verification — parsedRows == reportedTotal is the only exact match.
  const total = value['reportedTotal']
  if (typeof total === 'number' && total >= 0) {
    const complete = value['complete'] === true
    lines.push('KoKo footer: reportedTotal=' + total + (complete ? ' (capture complete)' : ' (capture partial)'))
    if (complete) {
      const parsedRows = typeof value['parsedRows'] === 'number' ? value['parsedRows'] : -1
      if (parsedRows !== total) {
        lines.push('note: KoKo reports ' + total + ' assets but only ' + parsedRows + ' rows parsed - capture may be incomplete; retry with refresh:true')
      }
    }
  }
  if (assets.length === 0) lines.push('(no matching assets)')
  for (const a of assets) {
    const name = String(a['name'] ?? '?')
    const ip = a['ip'] !== undefined && a['ip'] !== null ? String(a['ip']) : null
    const platform = a['platform'] !== undefined && a['platform'] !== null ? String(a['platform']) : null
    const node = a['node'] !== undefined && a['node'] !== null ? String(a['node']) : null
    const comment = a['comment'] !== undefined && a['comment'] !== null ? String(a['comment']) : null
    const extras = [platform, node, comment].filter((v): v is string => v !== null && v !== undefined)
    lines.push((ip !== null ? ip : name) + (ip !== null ? '  ' + name : '') + (extras.length > 0 ? '  ' + extras.join('  ') : ''))
  }
  return lines.join('\n')
}
