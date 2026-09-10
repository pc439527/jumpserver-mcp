/**
 * Runbooks (V0.4.1) — "Profile / Runbook" execution.
 *
 * A runbook is a NAMED, reviewed survey recipe stored in config. It is the
 * answer to "run the same 8 checks on these 6 servers, the same way, every
 * time" without the model inventing shell.
 *
 * Safety model (identical to inspect):
 *  - an explicit `command` step is re-classified; a non-READ step is SKIPPED
 *    and reported, never executed;
 *  - a `profile` step reuses the fixed, reviewed probe set;
 *  - every target is checked against the allow/deny scope lists.
 *
 * A runbook resolves to a flat list of per-target commands, then runs through
 * the SAME target-affinity batch path inspect uses (one enter per target).
 */
import { classifyCommand } from '../security/permission.js'
import { requireTargetAllowed } from '../security/target-scope.js'
import { JumpServerError } from './errors.js'
import { mapWithConcurrency } from './concurrency.js'
import { isInspectProfile, resolveProfile } from './profiles.js'
import type { BatchCommandRequest, SessionManager, TargetBatchResult } from './session-manager.js'
import type { RunbookDef, RunbookExpect, RunbookStep } from '../config/types.js'

/** A runbook may not walk the whole estate in one call. */
export const MAX_RUNBOOK_TARGETS = 20

export interface RunbookStepPlan {
  id: string
  title: string | null
  kind: 'profile' | 'command'
  /** For profile steps: the profile name; for command steps: the command. */
  source: string
  /** Resolved read-only commands this step contributes. */
  commands: string[]
  /** V0.4.3: probe ids parallel to `commands` (profile steps only). */
  probes: string[]
  /** Why the step is skipped (null when runnable). */
  skipped: { reason: string; risk: string; ruleId: string } | null
  timeoutMs: number | null
  /** V0.4.2: assertions this step carries (null when it asserts nothing). */
  expect: RunbookExpect | null
}

export interface RunbookPlan {
  name: string
  title: string | null
  steps: RunbookStepPlan[]
  runnable: number
  skipped: number
  /** V0.4.2: how many runnable steps carry at least one assertion. */
  asserted: number
}

/**
 * V0.4.3: ONE logical runbook step, as it appears in the result.
 *
 * Before V0.4.3 a profile step expanded into one result row per probe, so a
 * 10-probe profile produced 10 identically-named rows and — worse — the
 * step's `expect` was re-evaluated against every unrelated probe output.
 * Now a step is reported exactly once; the per-probe detail survives in
 * `commands[]` / `probes[]` for anyone who needs it.
 */
export interface RunbookStepResult {
  id: string
  title: string | null
  /** V0.4.3: which kind of step produced this row. */
  kind: 'profile' | 'command'
  source: string
  /**
   * V0.4.3: the output the assertion was actually evaluated against.
   *  - command step / expect.probe set -> that single probe's output
   *  - profile step without expect.probe -> all probe outputs joined by '\n'
   */
  output: string
  /** Aggregate exit code: 0 only when every contributing command exited 0. */
  exitCode: number | null
  truncated: boolean
  durationMs: number
  error: { code: string; message: string } | null
  /**
   * V0.4.4: the error from the probes the assertion was actually judged
   * against (i.e. `expect.probe` if set, else the whole profile). Distinct
   * from `error` (which reports the worst probe in the entire profile) so
   * a healthy target with an unrelated probe failure is not falsely FAILed.
   */
  assertionError: { code: string; message: string } | null
  /** V0.4.3: per-command detail (one entry per probe for profile steps). */
  commands: Array<{
    /** V0.4.3: probe id inside the profile (null for command steps). */
    probe: string | null
    command: string
    exitCode: number | null
    output: string
    truncated: boolean
    durationMs: number
    error: { code: string; message: string } | null
  }>
  /** V0.4.3: probe ids this step ran (profile steps; empty for command steps). */
  probes: string[]
  /** V0.4.2: assertion outcome for this step (null when the step asserts nothing). */
  check: RunbookCheck | null
}

export interface RunbookTargetResult {
  target: string
  hostname: string | null
  error: { code: string; message: string } | null
  /** V0.4.2: overall verdict for this target (null when no step asserted). */
  verdict: RunbookVerdict | null
  steps: RunbookStepResult[]
}

/** V0.4.2: 'pass' = every assertion held; 'fail' = at least one broke. */
export type RunbookVerdict = 'pass' | 'fail'

export interface RunbookCheck {
  verdict: RunbookVerdict
  /** One line per failed assertion, already human-readable. */
  failures: string[]
}

/**
 * V0.4.2: evaluate a step's captured output against its `expect` block.
 * Pure and side-effect free so it can be unit-tested without a bastion.
 * Returns null when the step carries no assertions (nothing to judge).
 */
export function evaluateExpect(
  expect: RunbookExpect | undefined,
  outcome: {
    output: string
    exitCode: number | null
    /**
     * V0.4.4: error from the probe(s) the assertion was scoped to
     * (`expect.probe` if set, else the whole profile). Distinct from the
     * step-level `error` so an unrelated probe failure does not FAIL the
     * assertion. Backward-compatible: callers passing the old `error`
     * key still work because the field is just unused.
     */
    assertionError?: { code: string; message: string } | null
    /** @deprecated V0.4.4 prefer `assertionError`. Still honored if set. */
    error?: { code: string; message: string } | null
  },
): RunbookCheck | null {
  if (expect === undefined) return null
  const failures: string[] = []
  const note = expect.message !== undefined && expect.message.length > 0 ? ' (' + expect.message + ')' : ''
  const output = outcome.output ?? ''
  const haystack = output.toLowerCase()
  const assertionError = outcome.assertionError ?? outcome.error ?? null

  // A step that could not run at all (the SCOPED probe) can never satisfy
  // an assertion. Other probes' errors are still visible on `step.error`.
  if (assertionError !== null) {
    return { verdict: 'fail', failures: ['step did not run: ' + assertionError.code + ' ' + assertionError.message + note] }
  }

  if (expect.contains !== undefined && expect.contains.length > 0) {
    if (!haystack.includes(expect.contains.toLowerCase())) failures.push('missing "' + expect.contains + '"' + note)
  }
  if (expect.notContains !== undefined && expect.notContains.length > 0) {
    if (haystack.includes(expect.notContains.toLowerCase())) failures.push('unexpected "' + expect.notContains + '" present' + note)
  }
  if (expect.matches !== undefined && expect.matches.length > 0) {
    let re: RegExp | null = null
    try {
      re = new RegExp(expect.matches, 'i')
    } catch {
      failures.push('invalid regex "' + expect.matches + '"' + note)
    }
    if (re !== null && !re.test(output)) failures.push('no match for /' + expect.matches + '/i' + note)
  }
  if (expect.exitCode !== undefined) {
    if (outcome.exitCode !== expect.exitCode) {
      failures.push('exit code ' + String(outcome.exitCode) + ' != ' + String(expect.exitCode) + note)
    }
  }
  if (expect.notEmpty === true) {
    if (output.trim().length === 0) failures.push('output is empty' + note)
  }
  if (expect.minLines !== undefined && expect.minLines > 0) {
    const lines = output.split('\n').filter((l) => l.trim().length > 0).length
    if (lines < expect.minLines) failures.push('only ' + String(lines) + ' lines, expected >= ' + String(expect.minLines) + note)
  }

  return failures.length === 0 ? { verdict: 'pass', failures: [] } : { verdict: 'fail', failures }
}

/** Fold per-step checks into one target verdict (null when nothing asserted). */
function foldVerdict(checks: Array<RunbookCheck | null>): RunbookVerdict | null {
  let seen = false
  let failed = false
  for (const check of checks) {
    if (check === null) continue
    seen = true
    if (check.verdict === 'fail') failed = true
  }
  if (!seen) return null
  return failed ? 'fail' : 'pass'
}

export interface RunbookResult {
  runbook: string
  title: string | null
  plan: RunbookPlan
  targets: number
  reachable: number
  results: RunbookTargetResult[]
  durationMs: number
  warnings: string[]
  /** V0.4.2: assertion roll-up (null when no step asserted anything). */
  verdict: RunbookVerdict | null
  passed: number
  failed: number
}

export interface RunbookOptions {
  targets: string[]
  signal?: AbortSignal
  toolCallId?: string
  batchId?: string
  concurrency?: number
}

/**
 * Resolve a runbook definition into a concrete step plan. Pure: no bastion
 * access, no execution — so it is directly unit-testable and can be previewed.
 */
export function planRunbook(name: string, def: RunbookDef): RunbookPlan {
  const steps: RunbookStepPlan[] = []
  let runnable = 0
  let skipped = 0
  let asserted = 0
  for (const step of def.steps) {
    const planned = planStep(step)
    steps.push(planned)
    if (planned.skipped === null && planned.commands.length > 0) {
      runnable += 1
      if (planned.expect !== null) asserted += 1
    } else {
      skipped += 1
    }
  }
  return { name, title: def.title ?? null, steps, runnable, skipped, asserted }
}

function planStep(step: RunbookStep): RunbookStepPlan {
  const timeoutMs = step.timeout !== undefined && step.timeout > 0 ? step.timeout * 1000 : null
  const expect = step.expect ?? null
  const base = { id: step.id, title: step.title ?? null, timeoutMs, expect }

  const hasProfile = step.profile !== undefined && step.profile.length > 0
  const hasCommand = step.command !== undefined && step.command.trim().length > 0
  if (hasProfile && hasCommand) {
    return {
      ...base,
      kind: 'command',
      source: step.command!,
      commands: [],
      probes: [],
      skipped: { reason: 'step defines BOTH profile and command', risk: 'UNKNOWN', ruleId: 'runbook.invalid' },
    }
  }
  if (!hasProfile && !hasCommand) {
    return {
      ...base,
      kind: 'command',
      source: '',
      commands: [],
      probes: [],
      skipped: { reason: 'step defines neither profile nor command', risk: 'UNKNOWN', ruleId: 'runbook.invalid' },
    }
  }

  if (hasProfile) {
    // A typo'd profile must NOT silently fall back to "basic" (resolveProfile
    // does that for the tool path where a default is harmless). In a runbook
    // the recipe is explicit, so an unknown name is a config error -> skip.
    const name = step.profile!.trim().toLowerCase()
    if (!isInspectProfile(name)) {
      return {
        ...base,
        kind: 'profile',
        source: step.profile!,
        commands: [],
        probes: [],
        skipped: { reason: 'unknown inspect profile "' + step.profile + '"', risk: 'UNKNOWN', ruleId: 'runbook.unknown-profile' },
      }
    }
    const resolved = resolveProfile(name)
    const commands: string[] = []
    const probes: string[] = []
    const seen = new Set<string>()
    for (const probe of resolved.steps) {
      const classification = classifyCommand(probe.command)
      if (classification.risk !== 'READ') continue
      if (seen.has(probe.command)) continue
      seen.add(probe.command)
      commands.push(probe.command)
      probes.push(probe.id)
    }
    if (commands.length === 0) {
      return {
        ...base,
        kind: 'profile',
        source: step.profile!,
        commands: [],
        probes: [],
        skipped: { reason: 'no probe of profile "' + step.profile + '" is classified READ', risk: 'UNKNOWN', ruleId: 'profile.risk-mismatch' },
      }
    }
    // V0.4.3: an expect.probe that names no probe of this profile is a config
    // error. Fail loudly at plan time instead of silently asserting nothing.
    if (expect !== null && expect.probe !== undefined && expect.probe.length > 0 && !probes.includes(expect.probe)) {
      return {
        ...base,
        kind: 'profile',
        source: step.profile!,
        commands: [],
        probes: [],
        skipped: {
          reason: 'expect.probe "' + expect.probe + '" is not a probe of profile "' + step.profile + '" (known: ' + probes.join(', ') + ')',
          risk: 'UNKNOWN',
          ruleId: 'runbook.unknown-probe',
        },
      }
    }
    return { ...base, kind: 'profile', source: step.profile!, commands, probes, skipped: null }
  }

  const command = step.command!.trim()
  const classification = classifyCommand(command)
  if (classification.risk !== 'READ') {
    return {
      ...base,
      kind: 'command',
      source: command,
      commands: [],
      probes: [],
      skipped: { reason: classification.reason, risk: classification.risk, ruleId: classification.ruleId },
    }
  }
  return { ...base, kind: 'command', source: command, commands: [command], probes: [], skipped: null }
}

/** Resolve the runbook by name from the configured map; unknown name errors loudly. */
export function resolveRunbook(runbooks: Record<string, RunbookDef> | undefined, name: string): RunbookDef {
  const key = name.trim()
  const table = runbooks ?? {}
  const direct = table[key]
  if (direct !== undefined) return direct
  const lower = key.toLowerCase()
  for (const [k, v] of Object.entries(table)) {
    if (k.toLowerCase() === lower) return v
  }
  const known = Object.keys(table)
  throw new JumpServerError(
    'UNKNOWN_RUNBOOK',
    'unknown runbook "' + name + '"' + (known.length > 0 ? '; configured: ' + known.join(', ') : '; no runbooks configured (set runbooks in config.json)'),
  )
}

/**
 * Execute a runbook against every target. Commands are flattened in step
 * order per target and executed through the target-affinity batch path, so a
 * target is entered once and its results map back to the originating step.
 */
export async function runRunbook(
  manager: SessionManager,
  getConfig: () => { allowedTargets?: string[]; deniedTargets?: string[] },
  name: string,
  def: RunbookDef,
  options: RunbookOptions,
): Promise<RunbookResult> {
  const started = Date.now()
  const plan = planRunbook(name, def)
  const warnings: string[] = []
  for (const step of plan.steps) {
    if (step.skipped !== null) warnings.push('step "' + step.id + '" skipped: ' + step.skipped.reason + ' [' + step.skipped.risk + ']')
  }
  if (plan.runnable === 0) {
    throw new JumpServerError('RUNBOOK_NO_READ_STEPS', 'runbook "' + name + '" has no runnable read-only step; refusing to run')
  }

  const targets = options.targets.map((t) => String(t).trim()).filter((t) => t.length > 0)
  if (targets.length === 0) throw new JumpServerError('ASSET_NOT_FOUND', 'profile_run requires at least one target')
  if (targets.length > MAX_RUNBOOK_TARGETS) {
    throw new JumpServerError('TOO_MANY_TARGETS', 'too many targets (' + targets.length + '); max ' + MAX_RUNBOOK_TARGETS + ' per profile_run call')
  }

  const results = await mapWithConcurrency(
    targets,
    async (target): Promise<RunbookTargetResult> => {
      requireTargetAllowed(getConfig(), target)
      const commands: BatchCommandRequest[] = []
      // V0.4.3: parallel arrays mapping a flat batch index back to its step.
      const indexToStep: number[] = []
      const indexToProbe: Array<string | null> = []
      plan.steps.forEach((step, stepIndex) => {
        if (step.skipped !== null) return
        step.commands.forEach((command, probeIndex) => {
          const classification = classifyCommand(command)
          commands.push({
            command,
            timeoutMs: step.timeoutMs ?? undefined,
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
            batchIndex: commands.length,
            batchId: options.batchId,
            toolCallId: options.toolCallId,
          })
          indexToStep.push(stepIndex)
          indexToProbe.push(step.kind === 'profile' ? (step.probes[probeIndex] ?? null) : null)
        })
      })
      const batch: TargetBatchResult = await manager.runTargetBatch({
        target,
        commands,
        signal: options.signal,
        toolCallId: options.toolCallId,
        batchId: options.batchId,
      })
      if (batch.error !== null) {
        // The target never ran: any assertion it carried is an automatic fail.
        const unreachableCheck = plan.steps.some((s) => s.skipped === null && s.expect !== null)
          ? { verdict: 'fail' as const, failures: ['target unreachable: ' + batch.error.code + ' ' + batch.error.message] }
          : null
        return { target, hostname: batch.hostname, error: batch.error, verdict: unreachableCheck !== null ? 'fail' : null, steps: [] }
      }

      // V0.4.3: fold the flat per-command batch back into ONE row per step.
      const steps: RunbookStepResult[] = []
      for (let stepIndex = 0; stepIndex < plan.steps.length; stepIndex += 1) {
        const step = plan.steps[stepIndex]!
        if (step.skipped !== null) continue
        const members: RunbookStepResult['commands'] = []
        for (let index = 0; index < indexToStep.length; index += 1) {
          if (indexToStep[index] !== stepIndex) continue
          const cmd = batch.commands[index]
          if (cmd === undefined) continue
          members.push({
            probe: indexToProbe[index] ?? null,
            command: cmd.command,
            exitCode: cmd.exitCode,
            output: cmd.output,
            truncated: cmd.truncated,
            durationMs: cmd.durationMs,
            error: cmd.error,
          })
        }
        if (members.length === 0) continue

        // Pick the text the assertion is judged against:
        //  - expect.probe -> that probe only (unknown probe already skipped at plan time)
        //  - profile step -> all probe outputs aggregated (one logical step = one verdict)
        //  - command step -> its single output
        let judged = members
        if (step.kind === 'profile' && step.expect?.probe !== undefined && step.expect.probe.length > 0) {
          const wanted = step.expect.probe
          judged = members.filter((m) => m.probe === wanted)
        }
        const output = judged.map((m) => m.output).join('\n')
        // Aggregate exit code: 0 only when every contributing command exited 0,
        // null when any of them has no exit code (timeout / signal lost).
        let exitCode: number | null = 0
        for (const m of judged) {
          if (m.exitCode === null) {
            exitCode = null
            break
          }
          if (m.exitCode !== 0) exitCode = m.exitCode
        }
        const error = members.find((m) => m.error !== null)?.error ?? null
        // V0.4.4: the assertion verdict must only react to the probe(s) the
        // assertion was scoped to. An unrelated probe failure (e.g. a `df`
        // error when the assertion is `expect.probe: 'listen'`) is reported
        // on the step's `error` but must NOT take down `check.verdict`.
        const assertionError = judged.find((m) => m.error !== null)?.error ?? null
        const check = evaluateExpect(step.expect ?? undefined, { output, exitCode, assertionError })

        steps.push({
          id: step.id,
          title: step.title,
          kind: step.kind,
          source: step.source,
          output,
          exitCode,
          truncated: judged.some((m) => m.truncated),
          durationMs: members.reduce((sum, m) => sum + m.durationMs, 0),
          error,
          assertionError,
          commands: members,
          probes: step.probes,
          check,
        })
      }
      return { target, hostname: batch.hostname, error: null, verdict: foldVerdict(steps.map((s) => s.check)), steps }
    },
    { concurrency: options.concurrency ?? 1, signal: options.signal },
  )

  const judged = results.filter((r) => r.verdict !== null)
  const failed = judged.filter((r) => r.verdict === 'fail').length
  const verdict: RunbookVerdict | null = judged.length === 0 ? null : failed > 0 ? 'fail' : 'pass'
  for (const r of judged) {
    if (r.verdict !== 'fail') continue
    const details = r.steps.flatMap((s) => (s.check?.verdict === 'fail' ? s.check.failures.map((f) => s.id + ': ' + f) : []))
    warnings.push('assertion FAIL on ' + r.target + (details.length > 0 ? ' -> ' + details.join('; ') : ' (target unreachable)'))
  }

  return {
    runbook: name,
    title: plan.title,
    plan,
    targets: targets.length,
    reachable: results.filter((r) => r.error === null).length,
    results,
    durationMs: Date.now() - started,
    warnings,
    verdict,
    passed: judged.length - failed,
    failed,
  }
}
