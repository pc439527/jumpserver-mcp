/**
 * V0.7.1 (D-8): the audit STATISTICS model.
 *
 * WHY THIS EXISTS
 * ---------------
 * The console reported one number — "失败 / 受阻" — computed as
 * `result !== 'SUCCESS' && result !== 'COMPLETED' && result !== 'ok'`.
 * Measured on the real audit file (7235 records), that lumped together:
 *
 *   EXIT_NONZERO   395   the command RAN and returned a non-zero code
 *   unverified      12   an interrupt with no job behind it
 *   TIMEOUT         28   the command never finished
 *   error           68   the request itself failed
 *   DENIED          99   a human refused it
 *   UNKNOWN          9   the outcome could not be determined
 *
 * Three of those are not the same thing:
 *
 *   - `EXIT_NONZERO` is a COMMAND that ran. `jps -lv` exiting 127 means the
 *     binary was missing, not that the connector failed. It was 78% of the
 *     "failures", so it drowned out every other class.
 *   - `unverified` is an interrupt where nothing was running. It is NOT a
 *     failure at all — counting it made a healthy fleet look broken.
 *   - The rest (timeout / lost connection / denied / error) ARE failures of
 *     the operation itself.
 *
 * So the model below separates COMMAND outcomes from OPERATION outcomes, and
 * reports the exit-non-zero class on its own line instead of mixing it in.
 *
 * This module is PURE: no I/O, no clock, no globals. The console, the
 * aggregation files and the tests all use the same numbers.
 */

/** The class of one audit record. */
export type AuditRecordClass =
  /** The command ran and succeeded. */
  | 'success'
  /** The command ran and returned a non-zero exit code. */
  | 'exitNonzero'
  /** The command was still running when the deadline hit. */
  | 'timeout'
  /** The command was interrupted (Ctrl+C) before finishing. */
  | 'interrupted'
  /** The SSH connection dropped during the command. */
  | 'connectionLost'
  /** A human refused the command. */
  | 'denied'
  /** The rule gate refused the command. */
  | 'blocked'
  /** An approval is still pending. */
  | 'pendingApproval'
  /** The request itself failed (bad target, unreachable asset, ...). */
  | 'error'
  /** The outcome could not be determined. */
  | 'unknown'
  /**
   * An interrupt that had no job behind it. NOT a failure — it is excluded
   * from the failure count and from the failure rate.
   */
  | 'unverified'

/** Classes that mean "the OPERATION failed" (not merely the command's exit code). */
const OPERATION_FAILURE_CLASSES: ReadonlySet<AuditRecordClass> = new Set([
  'timeout',
  'interrupted',
  'connectionLost',
  'denied',
  'blocked',
  'error',
  'unknown',
])

/** Classes that mean "the command ran but did not succeed". */
export function isCommandLevelFailure(cls: AuditRecordClass): boolean {
  return cls === 'exitNonzero' || cls === 'timeout' || cls === 'interrupted' || cls === 'connectionLost'
}

/**
 * Classify one audit record.
 *
 * The classification uses the record's own `result` value first, then the
 * exit code (for records written before V0.4.3, which had no status), then
 * the V0.7.1 `errorCode` (the machine-readable code D-6 added).
 */
export function classifyAuditRecord(record: Record<string, unknown>): AuditRecordClass {
  const status = String(record['result'] ?? '').trim()
  const exitCode = record['exitCode']
  const errorCode = String(record['errorCode'] ?? '').trim()
  const approvalPending = record['approvalRequired'] === true && String(record['approvalResult'] ?? '') === 'pending'

  if (approvalPending) return 'pendingApproval'

  switch (status) {
    case 'ok':
    case 'SUCCESS':
      return 'success'
    case 'COMPLETED':
      // Pre-V0.4.3 records only carried COMPLETED; the exit code decides.
      if (typeof exitCode === 'number' && exitCode !== 0) return 'exitNonzero'
      return 'success'
    case 'EXIT_NONZERO':
      return 'exitNonzero'
    case 'TIMEOUT':
      return 'timeout'
    case 'INTERRUPTED':
      return 'interrupted'
    case 'CONNECTION_LOST':
      return 'connectionLost'
    case 'DENIED':
      return 'denied'
    case 'BLOCKED':
      return 'blocked'
    case 'unverified':
      // V0.7.1: NOT a failure — an interrupt with no job behind it.
      return 'unverified'
    case 'error':
      return 'error'
    case 'UNKNOWN':
      return 'unknown'
    default:
      break
  }

  // No recognisable status: fall back to the structured code, then to the
  // exit code, then to the operation itself.
  if (errorCode === 'APPROVAL_DENIED') return 'denied'
  if (errorCode === 'COMMAND_BLOCKED') return 'blocked'
  if (errorCode === 'COMMAND_TIMEOUT') return 'timeout'
  if (errorCode === 'COMMAND_INTERRUPTED') return 'interrupted'
  if (errorCode === 'CONNECTION_LOST') return 'connectionLost'
  if (errorCode === 'COMMAND_EXIT_NONZERO') return 'exitNonzero'
  if (errorCode === 'INTERRUPT_UNVERIFIED') return 'unverified'
  if (status.length > 0) return 'unknown'
  if (typeof exitCode === 'number' && exitCode !== 0) return 'exitNonzero'
  return 'success'
}

export interface AuditStats {
  /** Total records considered. */
  total: number
  /**
   * Operations that FAILED (timeout / lost connection / denied / blocked /
   * error / unknown). Exit-non-zero commands are NOT counted here — they are
   * reported under `exitNonzero`.
   */
  failed: number
  /** Commands that ran and returned a non-zero exit code. */
  exitNonzero: number
  /** Total failures including the exit-non-zero class. */
  failedIncludingExitNonzero: number
  /** failed / total, as a fraction (0 when there are no records). */
  failureRate: number
  /** Interrupts with no job behind them — excluded from every failure count. */
  unverified: number
  /** Count per class. */
  byClass: Record<string, number>
  /** Count per machine-readable error code (D-6). */
  byErrorCode: Record<string, number>
  byRisk: Record<string, number>
  byOperation: Record<string, number>
  byTarget: Record<string, number>
  /** [day, count] sorted by day. */
  byDay: Array<[string, number]>
  /** Distinct targets seen. */
  targets: number
  /** Distinct active days. */
  days: number
}

/** Compute the statistics of a set of audit records. */
export function computeAuditStats(records: Record<string, unknown>[]): AuditStats {
  const byClass: Record<string, number> = {}
  const byErrorCode: Record<string, number> = {}
  const byRisk: Record<string, number> = {}
  const byOperation: Record<string, number> = {}
  const byTarget: Record<string, number> = {}
  const byDayMap: Record<string, number> = {}

  let failed = 0
  let exitNonzero = 0
  let unverified = 0

  for (const record of records) {
    const cls = classifyAuditRecord(record)
    byClass[cls] = (byClass[cls] ?? 0) + 1
    if (OPERATION_FAILURE_CLASSES.has(cls)) failed += 1
    if (cls === 'exitNonzero') exitNonzero += 1
    if (cls === 'unverified') unverified += 1

    const errorCode = String(record['errorCode'] ?? '').trim()
    if (errorCode.length > 0) byErrorCode[errorCode] = (byErrorCode[errorCode] ?? 0) + 1

    const risk = String(record['risk'] ?? '?')
    byRisk[risk] = (byRisk[risk] ?? 0) + 1
    const op = String(record['operation'] ?? '?')
    byOperation[op] = (byOperation[op] ?? 0) + 1
    const targetName = String(record['target'] ?? record['hostname'] ?? '(未进入资产)')
    byTarget[targetName] = (byTarget[targetName] ?? 0) + 1
    const day = String(record['timestamp'] ?? '').slice(0, 10)
    if (day.length > 0) byDayMap[day] = (byDayMap[day] ?? 0) + 1
  }

  const total = records.length
  const byDay = Object.keys(byDayMap).sort().map((d) => [d.slice(5), byDayMap[d] ?? 0] as [string, number])
  return {
    total,
    failed,
    exitNonzero,
    failedIncludingExitNonzero: failed + exitNonzero,
    failureRate: total === 0 ? 0 : failed / total,
    unverified,
    byClass,
    byErrorCode,
    byRisk,
    byOperation,
    byTarget,
    byDay,
    targets: Object.keys(byTarget).length,
    days: byDay.length,
  }
}

/**
 * The daily aggregation record (D-7): one small JSON file per day, so a
 * month of history costs kilobytes instead of megabytes.
 */
export interface DailyAuditMetrics {
  date: string
  total: number
  failed: number
  exitNonzero: number
  unverified: number
  failureRate: number
  byClass: Record<string, number>
  byErrorCode: Record<string, number>
  byRisk: Record<string, number>
  byOperation: Record<string, number>
  /** The top targets of that day (name -> count), capped at 20. */
  byTarget: Record<string, number>
}

/** Aggregate one day's records into the daily metrics file. */
export function aggregateDayMetrics(date: string, records: Record<string, unknown>[]): DailyAuditMetrics {
  const stats = computeAuditStats(records)
  const topTargets: Record<string, number> = {}
  const entries = Object.entries(stats.byTarget).sort((a, b) => b[1] - a[1]).slice(0, 20)
  for (const [name, count] of entries) topTargets[name] = count
  return {
    date,
    total: stats.total,
    failed: stats.failed,
    exitNonzero: stats.exitNonzero,
    unverified: stats.unverified,
    failureRate: stats.failureRate,
    byClass: stats.byClass,
    byErrorCode: stats.byErrorCode,
    byRisk: stats.byRisk,
    byOperation: stats.byOperation,
    byTarget: topTargets,
  }
}
