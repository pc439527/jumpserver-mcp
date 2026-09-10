/**
 * Multi-host comparison (V0.4.1) — jumpserver_compare.
 *
 * Runs the SAME command (or inspect profile) on every target and reports what
 * differs. The value is in the diff, not the raw dumps: "which of these 6 OA
 * nodes has a different nginx upstream / a missing service / a full disk".
 *
 * Design rules:
 *  - every command is re-classified; a non-READ command is refused up front
 *    (compare is a read-only tool — unlike a runbook, there is no per-step
 *    skip because there is only ONE command and silently comparing nothing
 *    would be worse than refusing);
 *  - comparison is line-oriented and order-insensitive by default, because
 *    most diagnostic output (ss, ps, df) is not stably ordered;
 *  - a target that failed is reported as failed and EXCLUDED from the diff,
 *    never counted as "identical".
 */
import { classifyCommand } from '../security/permission.js'
import { requireTargetAllowed } from '../security/target-scope.js'
import { JumpServerError } from './errors.js'
import { mapWithConcurrency } from './concurrency.js'
import { resolveProfile } from './profiles.js'
import type { BatchCommandRequest, SessionManager } from './session-manager.js'

export const MAX_COMPARE_TARGETS = 20

export interface CompareOptions {
  targets: string[]
  /** Exactly one of command / profile must be provided. */
  command?: string
  profile?: string
  /** Drop blank lines before diffing (default true). */
  ignoreBlank?: boolean
  /** Ignore whitespace-only differences inside a line (default true). */
  normalizeWhitespace?: boolean
  /** Line prefixes to strip before diffing (e.g. hostname noise). */
  stripPrefixes?: string[]
  signal?: AbortSignal
  toolCallId?: string
  batchId?: string
  concurrency?: number
}

export interface CompareTarget {
  target: string
  hostname: string | null
  ok: boolean
  exitCode: number | null
  error: { code: string; message: string } | null
  durationMs: number
  /** Normalized lines actually compared (post filtering). */
  lines: string[]
  truncated: boolean
}

export interface CompareGroup {
  /** The exact set of lines shared by every OK target. */
  signature: string[]
  /** Per-target deviation from the majority signature. */
  outliers: Array<{ target: string; missing: string[]; extra: string[] }>
}

export interface CompareResult {
  mode: 'command' | 'profile'
  source: string
  /** Extra commands when mode === profile. */
  commands: string[]
  targets: number
  succeeded: number
  failed: number
  /** How many DISTINCT line-sets were observed (1 == all identical). */
  distinct: number
  groups: CompareGroup[]
  results: CompareTarget[]
  durationMs: number
  warnings: string[]
}

/** Normalize one output block into comparable lines. */
export function normalizeLines(
  text: string,
  options: { ignoreBlank?: boolean; normalizeWhitespace?: boolean; stripPrefixes?: string[] } = {},
): string[] {
  const ignoreBlank = options.ignoreBlank ?? true
  const normalizeWhitespace = options.normalizeWhitespace ?? true
  const prefixes = options.stripPrefixes ?? []
  const out: string[] = []
  for (let line of text.split(/\r?\n/)) {
    for (const prefix of prefixes) {
      if (prefix.length > 0 && line.startsWith(prefix)) line = line.slice(prefix.length)
    }
    if (normalizeWhitespace) line = line.replace(/[ \t]+/g, ' ').trim()
    else line = line.trimEnd()
    if (ignoreBlank && line.length === 0) continue
    out.push(line)
  }
  return out
}

/**
 * Group targets by their exact (order-insensitive) MULTISET of lines and pick
 * the majority set as the signature.
 *
 * V0.4.3: this used to key on the unique line set, so a target with 12
 * duplicate warnings and one with a single warning were declared IDENTICAL —
 * the exact difference an ops comparison exists to surface. The key is now a
 * count-aware multiset (line × occurrences, sorted), and a target whose line
 * counts differ is reported as an outlier.
 */
export function groupBySignature(
  targets: CompareTarget[],
): { distinct: number; groups: CompareGroup[] } {
  const ok = targets.filter((t) => t.ok)
  if (ok.length === 0) return { distinct: 0, groups: [] }

  const keyOf = (lines: string[]): string => {
    const counts = new Map<string, number>()
    for (const line of lines) counts.set(line, (counts.get(line) ?? 0) + 1)
    return [...counts.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([line, n]) => n + '\u0001' + line)
      .join('\u0000')
  }
  const buckets = new Map<string, { lines: string[]; members: CompareTarget[] }>()
  for (const target of ok) {
    const key = keyOf(target.lines)
    const bucket = buckets.get(key)
    if (bucket === undefined) buckets.set(key, { lines: target.lines, members: [target] })
    else bucket.members.push(target)
  }

  const sorted = [...buckets.entries()].sort((a, b) => b[1].members.length - a[1].members.length)
  const majority = sorted[0]![1]
  const majorityKey = keyOf(majority.lines)
  const groups: CompareGroup[] = []

  // Majority group first: outliers are measured against it.
  groups.push({
    signature: dedupeStable(majority.lines),
    outliers: ok
      .filter((t) => keyOf(t.lines) !== majorityKey)
      .map((t) => diffAgainst(majority.lines, t)),
  })

  // Every minority group is its own signature block.
  for (const [, bucket] of sorted.slice(1)) {
    groups.push({
      signature: dedupeStable(bucket.lines),
      outliers: bucket.members.map((t) => diffAgainst(majority.lines, t)),
    })
  }
  return { distinct: sorted.length, groups }
}

/**
 * Count-aware diff: a line present twice in the baseline but once in the
 * target is MISSING (once), and vice versa. Comparing unique sets silently
 * dropped that, which is how duplicate-count drift escaped the report.
 */
function diffAgainst(majorityLines: string[], target: CompareTarget): { target: string; missing: string[]; extra: string[] } {
  const missing = multisetDifference(majorityLines, target.lines)
  const extra = multisetDifference(target.lines, majorityLines)
  return { target: target.target, missing: dedupeStable(missing), extra: dedupeStable(extra) }
}

/** Lines present more often in `from` than in `against` (duplicates included). */
function multisetDifference(from: string[], against: string[]): string[] {
  const counts = new Map<string, number>()
  for (const line of against) counts.set(line, (counts.get(line) ?? 0) + 1)
  const out: string[] = []
  for (const line of from) {
    const left = counts.get(line) ?? 0
    if (left > 0) {
      counts.set(line, left - 1)
      continue
    }
    out.push(line)
  }
  return out
}

function dedupeStable(lines: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const line of lines) {
    if (seen.has(line)) continue
    seen.add(line)
    out.push(line)
  }
  return out
}

export async function compareTargets(
  manager: SessionManager,
  getConfig: () => { allowedTargets?: string[]; deniedTargets?: string[] },
  options: CompareOptions,
): Promise<CompareResult> {
  const started = Date.now()
  const warnings: string[] = []
  const hasCommand = options.command !== undefined && options.command.trim().length > 0
  const hasProfile = options.profile !== undefined && options.profile.trim().length > 0
  if (hasCommand === hasProfile) {
    throw new JumpServerError('INVALID_ARGUMENT', 'provide exactly one of command or profile')
  }

  let commands: string[]
  let source: string
  const mode: 'command' | 'profile' = hasProfile ? 'profile' : 'command'
  if (hasProfile) {
    const resolved = resolveProfile(options.profile)
    if (resolved.unknown.length > 0) warnings.push('unknown profile ignored: ' + resolved.unknown.join(', '))
    commands = resolved.steps.map((s) => s.command)
    source = options.profile!.trim()
  } else {
    commands = [options.command!.trim()]
    source = options.command!.trim()
  }

  // Refuse the whole call up front if any probe is not READ (no partial diffs).
  for (const command of commands) {
    const classification = classifyCommand(command)
    if (classification.risk !== 'READ') {
      throw new JumpServerError(
        'COMMAND_APPROVAL_REQUIRED',
        'compare refuses non-READ command "' + command + '" (' + classification.risk + ': ' + classification.reason + '). ' +
          'Use only read-only commands/profiles so every target is compared on the same, safe basis.',
      )
    }
  }

  const targets = options.targets.map((t) => String(t).trim()).filter((t) => t.length > 0)
  if (targets.length === 0) throw new JumpServerError('ASSET_NOT_FOUND', 'compare requires at least one target')
  if (targets.length > MAX_COMPARE_TARGETS) {
    throw new JumpServerError('TOO_MANY_TARGETS', 'too many targets (' + targets.length + '); max ' + MAX_COMPARE_TARGETS + ' per compare call')
  }

  const results = await mapWithConcurrency(
    targets,
    async (target): Promise<CompareTarget> => {
      requireTargetAllowed(getConfig(), target)
      const requests: BatchCommandRequest[] = commands.map((command, index) => {
        const classification = classifyCommand(command)
        return {
          command,
          risk: classification.risk,
          classification: {
            risk: classification.risk,
            reason: classification.reason,
            ruleId: classification.ruleId,
            confidence: classification.confidence,
            classifierVersion: classification.classifierVersion,
            normalizedCommand: classification.normalizedCommand,
          },
          approvalRequired: false,
          approvalResult: 'none',
          batchIndex: index,
          batchId: options.batchId,
          toolCallId: options.toolCallId,
        }
      })
      const batch = await manager.runTargetBatch({
        target,
        commands: requests,
        signal: options.signal,
        toolCallId: options.toolCallId,
        batchId: options.batchId,
      })
      if (batch.error !== null) {
        return { target, hostname: batch.hostname, ok: false, exitCode: null, error: batch.error, durationMs: 0, lines: [], truncated: false }
      }
      const failed = batch.commands.find((c) => c.error !== null)
      if (failed !== undefined && failed.error !== null) {
        return { target, hostname: batch.hostname, ok: false, exitCode: null, error: failed.error, durationMs: 0, lines: [], truncated: false }
      }
      // Concatenate every probe's output into one comparable block.
      const merged = batch.commands.map((c) => c.output).join('\n')
      const durationMs = batch.commands.reduce((sum, c) => sum + c.durationMs, 0)
      const truncated = batch.commands.some((c) => c.truncated)
      const lines = normalizeLines(merged, {
        ignoreBlank: options.ignoreBlank ?? true,
        normalizeWhitespace: options.normalizeWhitespace ?? true,
        stripPrefixes: options.stripPrefixes,
      })
      return { target, hostname: batch.hostname, ok: true, exitCode: 0, error: null, durationMs, lines, truncated }
    },
    { concurrency: options.concurrency ?? 1, signal: options.signal },
  )

  const succeeded = results.filter((r) => r.ok).length
  const { distinct, groups } = groupBySignature(results)
  return {
    mode,
    source,
    commands,
    targets: targets.length,
    succeeded,
    failed: targets.length - succeeded,
    distinct,
    groups,
    results,
    durationMs: Date.now() - started,
    warnings,
  }
}
