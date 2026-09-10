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
import type { RunbookDef, RunbookStep } from '../config/types.js'

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
  /** Why the step is skipped (null when runnable). */
  skipped: { reason: string; risk: string; ruleId: string } | null
  timeoutMs: number | null
}

export interface RunbookPlan {
  name: string
  title: string | null
  steps: RunbookStepPlan[]
  runnable: number
  skipped: number
}

export interface RunbookTargetResult {
  target: string
  hostname: string | null
  error: { code: string; message: string } | null
  steps: Array<{
    id: string
    title: string | null
    source: string
    exitCode: number | null
    output: string
    truncated: boolean
    durationMs: number
    error: { code: string; message: string } | null
  }>
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
  for (const step of def.steps) {
    const planned = planStep(step)
    steps.push(planned)
    if (planned.skipped === null && planned.commands.length > 0) runnable += 1
    else skipped += 1
  }
  return { name, title: def.title ?? null, steps, runnable, skipped }
}

function planStep(step: RunbookStep): RunbookStepPlan {
  const timeoutMs = step.timeout !== undefined && step.timeout > 0 ? step.timeout * 1000 : null
  const base = { id: step.id, title: step.title ?? null, timeoutMs }

  const hasProfile = step.profile !== undefined && step.profile.length > 0
  const hasCommand = step.command !== undefined && step.command.trim().length > 0
  if (hasProfile && hasCommand) {
    return {
      ...base,
      kind: 'command',
      source: step.command!,
      commands: [],
      skipped: { reason: 'step defines BOTH profile and command', risk: 'UNKNOWN', ruleId: 'runbook.invalid' },
    }
  }
  if (!hasProfile && !hasCommand) {
    return {
      ...base,
      kind: 'command',
      source: '',
      commands: [],
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
        skipped: { reason: 'unknown inspect profile "' + step.profile + '"', risk: 'UNKNOWN', ruleId: 'runbook.unknown-profile' },
      }
    }
    const resolved = resolveProfile(name)
    const commands: string[] = []
    const seen = new Set<string>()
    for (const probe of resolved.steps) {
      const classification = classifyCommand(probe.command)
      if (classification.risk !== 'READ') continue
      if (seen.has(probe.command)) continue
      seen.add(probe.command)
      commands.push(probe.command)
    }
    if (commands.length === 0) {
      return {
        ...base,
        kind: 'profile',
        source: step.profile!,
        commands: [],
        skipped: { reason: 'no probe of profile "' + step.profile + '" is classified READ', risk: 'UNKNOWN', ruleId: 'profile.risk-mismatch' },
      }
    }
    return { ...base, kind: 'profile', source: step.profile!, commands, skipped: null }
  }

  const command = step.command!.trim()
  const classification = classifyCommand(command)
  if (classification.risk !== 'READ') {
    return {
      ...base,
      kind: 'command',
      source: command,
      commands: [],
      skipped: { reason: classification.reason, risk: classification.risk, ruleId: classification.ruleId },
    }
  }
  return { ...base, kind: 'command', source: command, commands: [command], skipped: null }
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
      const indexToStep: number[] = []
      plan.steps.forEach((step, stepIndex) => {
        if (step.skipped !== null) return
        for (const command of step.commands) {
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
        }
      })
      const batch: TargetBatchResult = await manager.runTargetBatch({
        target,
        commands,
        signal: options.signal,
        toolCallId: options.toolCallId,
        batchId: options.batchId,
      })
      if (batch.error !== null) {
        return { target, hostname: batch.hostname, error: batch.error, steps: [] }
      }
      const steps: RunbookTargetResult['steps'] = []
      batch.commands.forEach((cmd, index) => {
        const stepIndex = indexToStep[index]
        const step = stepIndex !== undefined ? plan.steps[stepIndex] : undefined
        steps.push({
          id: step?.id ?? 'step' + index,
          title: step?.title ?? null,
          source: step?.source ?? cmd.command,
          exitCode: cmd.exitCode,
          output: cmd.output,
          truncated: cmd.truncated,
          durationMs: cmd.durationMs,
          error: cmd.error,
        })
      })
      return { target, hostname: batch.hostname, error: null, steps }
    },
    { concurrency: options.concurrency ?? 1, signal: options.signal },
  )

  return {
    runbook: name,
    title: plan.title,
    plan,
    targets: targets.length,
    reachable: results.filter((r) => r.error === null).length,
    results,
    durationMs: Date.now() - started,
    warnings,
  }
}
