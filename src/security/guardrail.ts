/**
 * V0.7.1 (D-10): the DANGEROUS-COMMAND GUARDRAIL.
 *
 * WHY THIS EXISTS
 * ---------------
 * A command that is classified DANGEROUS or UNKNOWN gets a human approval
 * prompt — but the prompt asks "may I run this?", not "how long may it run?"
 * or "how much may it touch?". Three failure modes follow:
 *
 *   1. `rm -rf /var/data/*` on a 400 GB volume — approved in a hurry, runs for
 *      40 minutes, and the operator cannot tell whether it is progressing or
 *      wedged.
 *   2. `sed -i` over a 2 GB file — one line of impact on screen, 2 GB of work
 *      on disk.
 *   3. `find / -name '*.log' -delete` — the command LOOKS narrow but walks
 *      the whole filesystem.
 *
 * The guardrail adds two things the prompt cannot:
 *
 *   - a MAXIMUM EXECUTION TIME for a DANGEROUS/UNKNOWN command, so an
 *     unbounded command is bounded by the connector, not only by the shell;
 *   - an IMPACT HINT derived from the command text — the number of lines the
 *     command is likely to touch and whether it walks the filesystem — so the
 *     approver sees the scale next to the command.
 *
 * THE RULES
 * ---------
 *   - READ commands are NEVER touched. A read that takes 40 minutes is the
 *     operator's problem, and capping it would break legitimate long reads.
 *   - The cap is a CEILING, never a raise. A caller asking for 30 minutes on
 *     a DANGEROUS command gets the cap, not 30 minutes.
 *   - The cap never silently truncates: the result says the command hit the
 *     guardrail, so the audit shows a real reason.
 *   - The impact hint is an ESTIMATE from the command text. It is labelled as
 *     such — it must never be presented as a measured fact.
 */

/** The maximum execution time for a DANGEROUS or UNKNOWN command (ms). */
export const DEFAULT_DANGEROUS_TIMEOUT_MS = 120_000

/** The maximum execution time for an UNKNOWN command (ms) — tighter. */
export const DEFAULT_UNKNOWN_TIMEOUT_MS = 60_000

/** Risk classes that the guardrail applies to. */
export type GuardrailRisk = 'READ' | 'PRIVILEGED_READ' | 'UNKNOWN' | 'MODIFY' | 'DANGEROUS'

export interface GuardrailOptions {
  /** Max execution time for a DANGEROUS command (default 120s). */
  dangerousTimeoutMs?: number
  /** Max execution time for an UNKNOWN command (default 60s). */
  unknownTimeoutMs?: number
  /** Max execution time for a MODIFY command (default 120s). */
  modifyTimeoutMs?: number
}

export interface ImpactHint {
  /** The estimated number of lines the command may touch (null = unknown). */
  estimatedLines: number | null
  /** How the estimate was derived — always shown, so it is never a mystery. */
  basis: string
  /** True when the command appears to walk the filesystem. */
  walksFilesystem: boolean
  /** True when the command removes or truncates something. */
  destructive: boolean
  /** True when the command writes in place (sed -i, dd, ...). */
  writesInPlace: boolean
  /** A one-line human summary. */
  summary: string
}

export interface GuardrailDecision {
  /** The timeout actually applied (ms). */
  timeoutMs: number
  /** True when the guardrail lowered the requested timeout. */
  capped: boolean
  /** The impact hint (null for READ commands). */
  impact: ImpactHint | null
  /** A note to append to the approval prompt / result. */
  note: string | null
}

/**
 * Estimate the impact of a command from its TEXT.
 *
 * This is deliberately coarse. A wrong-but-labelled estimate is useful; an
 * unlabeled one is a lie.
 */
export function estimateImpact(command: string): ImpactHint {
  const cmd = command.toLowerCase()
  const destructive = /\brm\b|\brmdir\b|\btruncate\b|\bdd\b|\bmkfs\b|\b>\s*\/\w|\bshred\b/.test(cmd)
  const writesInPlace = /\bsed\b[^|;&]*\s-i\b|\btee\b\s+-i\b|\bdd\b[^|;&]*\bof=/.test(cmd)
  const walksFilesystem = /\bfind\b|\bdu\b|\bgrep\b[^|;&]*\s-r\b|\btar\b[^|;&]*\s-c\b|\blocate\b/.test(cmd)

  // Line counts: an explicit number in the command is the strongest signal.
  let estimatedLines: number | null = null
  let basis = 'no explicit line count in the command text'
  const headMatch = /\bhead\b[^|;&]*\s-n\s*(\d+)/.exec(cmd)
  const tailMatch = /\btail\b[^|;&]*\s-n\s*(\d+)/.exec(cmd)
  const rangeMatch = /\b(?:sed|awk)\b[^|;&]*?(\d+)\s*,\s*(\d+)\s*[pd]/.exec(cmd)
  const sedAll = /\bsed\b[^|;&]*\s-i\b/.test(cmd)
  if (headMatch !== null) {
    estimatedLines = Number(headMatch[1])
    basis = 'head -n in the command'
  } else if (tailMatch !== null) {
    estimatedLines = Number(tailMatch[1])
    basis = 'tail -n in the command'
  } else if (rangeMatch !== null) {
    estimatedLines = Number(rangeMatch[2]) - Number(rangeMatch[1]) + 1
    basis = 'the line range in the sed/awk expression'
  } else if (sedAll) {
    estimatedLines = null
    basis = 'sed -i rewrites every matching line — the count is not knowable from the text'
  } else if (walksFilesystem) {
    basis = 'the command walks the filesystem — the count is not knowable from the text'
  } else if (destructive) {
    basis = 'a destructive command — the count is not knowable from the text'
  }

  const parts: string[] = []
  if (estimatedLines !== null) parts.push('约 ' + String(estimatedLines) + ' 行')
  if (destructive) parts.push('删除/截断')
  if (writesInPlace) parts.push('原地改写')
  if (walksFilesystem) parts.push('遍历文件系统')
  if (parts.length === 0) parts.push('影响面未知')

  return {
    estimatedLines,
    basis,
    walksFilesystem,
    destructive,
    writesInPlace,
    summary: parts.join('；'),
  }
}

/**
 * Apply the guardrail to one command.
 *
 * `requestedTimeoutMs` is what the caller asked for (undefined = the
 * session's default). The result is the timeout that will actually be used.
 */
export function applyGuardrail(
  risk: GuardrailRisk,
  command: string,
  requestedTimeoutMs: number | undefined,
  defaultTimeoutMs: number,
  options: GuardrailOptions = {},
): GuardrailDecision {
  // READ is never touched — capping a legitimate long read would be a
  // regression, not a safety feature.
  if (risk === 'READ' || risk === 'PRIVILEGED_READ') {
    return { timeoutMs: requestedTimeoutMs ?? defaultTimeoutMs, capped: false, impact: null, note: null }
  }

  const dangerousCap = options.dangerousTimeoutMs ?? DEFAULT_DANGEROUS_TIMEOUT_MS
  const unknownCap = options.unknownTimeoutMs ?? DEFAULT_UNKNOWN_TIMEOUT_MS
  const modifyCap = options.modifyTimeoutMs ?? DEFAULT_DANGEROUS_TIMEOUT_MS

  const cap = risk === 'DANGEROUS' ? dangerousCap : (risk === 'UNKNOWN' ? unknownCap : modifyCap)
  const effective = Math.min(requestedTimeoutMs ?? defaultTimeoutMs, cap)
  const capped = effective < (requestedTimeoutMs ?? defaultTimeoutMs)

  const impact = estimateImpact(command)
  const noteParts: string[] = []
  noteParts.push('影响面：' + impact.summary + '（' + impact.basis + '）')
  if (capped) {
    noteParts.push('执行时长已由护栏限制为 ' + String(Math.round(effective / 1000)) + ' 秒')
  } else {
    noteParts.push('执行时长上限 ' + String(Math.round(cap / 1000)) + ' 秒')
  }
  if (impact.walksFilesystem) {
    noteParts.push('该命令会遍历文件系统，建议先缩小范围')
  }
  if (impact.destructive) {
    noteParts.push('该命令会删除或截断内容')
  }

  return {
    timeoutMs: effective,
    capped,
    impact,
    note: noteParts.join('；'),
  }
}
