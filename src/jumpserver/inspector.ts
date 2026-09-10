/**
 * Inspector (V0.4.0): run the fixed probe profiles against one or more
 * targets and return STRUCTURED host inventories instead of raw shell text.
 *
 * Safety: every probe is re-classified here. A probe that no longer comes out
 * as READ (after a classifier change) is SKIPPED and reported — it is never
 * executed, and it is never silently downgraded to "probably fine".
 */
import { classifyCommand } from '../security/permission.js'
import { requireTargetAllowed } from '../security/target-scope.js'
import { JumpServerError } from './errors.js'
import { applyProbe, detectRoles, emptyInventory, type HostInventory } from './host-parse.js'
import { resolveProfile } from './profiles.js'
import type { BatchCommandRequest, SessionManager } from './session-manager.js'

/** One inspect call must not be able to walk the whole estate. */
export const MAX_INSPECT_TARGETS = 20

export interface InspectOptions {
  targets: string[]
  profile?: string | string[]
  signal?: AbortSignal
  toolCallId?: string
  batchId?: string
}

export interface SkippedProbe {
  command: string
  risk: string
  ruleId: string
  reason: string
}

export interface InspectResult {
  inventories: HostInventory[]
  profiles: string[]
  unknownProfiles: string[]
  skippedProbes: SkippedProbe[]
  targets: number
  reachable: number
  durationMs: number
  warnings: string[]
}

export async function inspectTargets(
  manager: SessionManager,
  getConfig: () => { allowedTargets?: string[]; deniedTargets?: string[] },
  options: InspectOptions,
): Promise<InspectResult> {
  const started = Date.now()
  const warnings: string[] = []
  const { steps, used, unknown } = resolveProfile(options.profile)
  for (const name of unknown) warnings.push('unknown profile "' + name + '" ignored')

  const classified = steps.map((step) => ({ step, classification: classifyCommand(step.command) }))
  const usable = classified.filter((c) => c.classification.risk === 'READ')
  const skipped: SkippedProbe[] = classified
    .filter((c) => c.classification.risk !== 'READ')
    .map((c) => ({
      command: c.step.command,
      risk: c.classification.risk,
      ruleId: c.step.id,
      reason: c.classification.reason,
    }))
  if (usable.length === 0) {
    throw new JumpServerError('PROFILE_RISK_MISMATCH', 'no probe of the requested profile is classified READ; refusing to run the survey')
  }

  const targets = options.targets.map((t) => String(t).trim()).filter((t) => t.length > 0)
  if (targets.length === 0) throw new JumpServerError('ASSET_NOT_FOUND', 'inspect requires at least one target')
  if (targets.length > MAX_INSPECT_TARGETS) {
    throw new JumpServerError('TOO_MANY_TARGETS', 'too many targets (' + targets.length + '); max ' + MAX_INSPECT_TARGETS + ' per inspect call')
  }

  const inventories: HostInventory[] = []
  for (const target of targets) {
    requireTargetAllowed(getConfig(), target)
    const commands: BatchCommandRequest[] = usable.map((c, index) => ({
      command: c.step.command,
      risk: c.classification.risk,
      classification: {
        risk: c.classification.risk,
        reason: c.classification.reason,
        ruleId: c.classification.ruleId,
        confidence: c.classification.confidence,
        classifierVersion: c.classification.classifierVersion,
        normalizedCommand: c.classification.normalizedCommand,
      },
      approvalRequired: false,
      approvalResult: 'none',
      batchIndex: index,
      batchId: options.batchId,
      toolCallId: options.toolCallId,
    }))
    const result = await manager.runTargetBatch({
      target,
      commands,
      signal: options.signal,
      toolCallId: options.toolCallId,
      batchId: options.batchId,
    })
    if (result.error !== null) {
      inventories.push(emptyInventory(target, used, result.error.code + ': ' + result.error.message))
      continue
    }
    const inventory = emptyInventory(target, used)
    result.commands.forEach((cmd, index) => {
      const step = usable[index]?.step
      if (step === undefined) return
      if (cmd.error !== null) return
      if (cmd.exitCode !== null && cmd.exitCode !== 0 && cmd.output.trim().length === 0) return
      applyProbe(inventory, step.id, cmd.output, cmd.exitCode)
    })
    inventory.roles = detectRoles(inventory)
    inventories.push(inventory)
  }

  return {
    inventories,
    profiles: used,
    unknownProfiles: unknown,
    skippedProbes: skipped,
    targets: targets.length,
    reachable: inventories.filter((i) => i.reachable).length,
    durationMs: Date.now() - started,
    warnings,
  }
}
