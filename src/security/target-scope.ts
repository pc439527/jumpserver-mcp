/**
 * Target scope guard (V0.4.0): restrict which assets this MCP connector may
 * touch. Deny always wins; an allow-list is a substring match so entries can
 * be an IP, an IP prefix ("192.168.79.") or a name fragment ("oa-").
 *
 * Applied BEFORE any navigation (run / batch / inspect / topology / job) and
 * before an exec inside an already-entered asset — so a drifted session can
 * never be used to operate outside the configured scope.
 */
import { JumpServerError } from '../jumpserver/errors.js'

export interface TargetScopeConfig {
  allowedTargets?: string[]
  deniedTargets?: string[]
}

function matches(list: readonly string[] | undefined, target: string): string | null {
  if (list === undefined || list.length === 0) return null
  const needle = target.trim().toLowerCase()
  if (needle.length === 0) return null
  for (const entry of list) {
    const term = entry.trim().toLowerCase()
    if (term.length > 0 && needle.includes(term)) return entry
  }
  return null
}

/** Throws TARGET_DENIED when the target is outside the configured scope. */
export function requireTargetAllowed(cfg: TargetScopeConfig, target: string | null | undefined): void {
  const value = (target ?? '').trim()
  if (value.length === 0) return
  const denied = matches(cfg.deniedTargets, value)
  if (denied !== null) {
    throw new JumpServerError('TARGET_DENIED', 'target "' + value + '" is on deniedTargets (rule: ' + denied + ')')
  }
  if (cfg.allowedTargets === undefined || cfg.allowedTargets.length === 0) return
  if (matches(cfg.allowedTargets, value) === null) {
    throw new JumpServerError(
      'TARGET_DENIED',
      'target "' + value + '" is not in allowedTargets; add it to the config or pick another asset',
    )
  }
}
