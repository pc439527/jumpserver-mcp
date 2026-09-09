/**
 * V0.2.7: manual sidebar terminal input policy + state-aware menu parsing.
 *
 * The browser human terminal does not write raw PTY bytes: it routes typed
 * input through these deciders, and the Host bridge executes the resulting
 * SessionManager action. At the JumpServer menu only menu verbs are legal
 * (p / IP-or-name / q); inside an asset shell 'exit' maps to leave() and
 * every other command is gated by manualPermissionMode.
 *
 * V0.3.1: risk classes are READ / PRIVILEGED_READ / UNKNOWN / MODIFY /
 * DANGEROUS. CONFIRM_MODIFY lets confirmed reads pass; UNKNOWN is NOT a read
 * and asks the user with honest copy (never "该命令会修改服务器").
 */
import { classifyCommand, gateDecision, type Classification } from './permission.js'
import type { ManualPolicy, PermissionMode } from '../config/types.js'

export type ManualGate =
  | { kind: 'allow' }
  | { kind: 'confirm'; risk: string }
  | { kind: 'block'; reason: string }

/**
 * Decision for one manual shell command under the configured manual policy.
 * confirmed=true means the user already acknowledged a modify prompt for this
 * exact call (ephemeral, per request — never cached/armed).
 */
export function manualGate(
  risk: string,
  policy: ManualPolicy,
  agentMode: PermissionMode,
  confirmed: boolean,
  options: { privilegedReadInReadOnly?: boolean } = {},
): ManualGate {
  switch (policy) {
    case 'FULL_ACCESS':
      return { kind: 'allow' }
    case 'FOLLOW_AGENT': {
      const decision = gateDecision(risk as 'READ' | 'PRIVILEGED_READ' | 'UNKNOWN' | 'MODIFY' | 'DANGEROUS', agentMode, options)
      if (decision.kind === 'allow') return { kind: 'allow' }
      if (decision.code === 'COMMAND_APPROVAL_REQUIRED') {
        if (!confirmed) return { kind: 'confirm', risk }
        return { kind: 'allow' }
      }
      return { kind: 'block', reason: 'blocked by manual FOLLOW_AGENT (' + agentMode + '): ' + decision.reason }
    }
    case 'CONFIRM_MODIFY':
    default:
      // confirmed reads pass; everything else (PRIVILEGED_READ is a confirmed
      // read — it just needs elevated rights) asks for one confirmation.
      if (risk === 'READ' || risk === 'PRIVILEGED_READ') return { kind: 'allow' }
      if (!confirmed) return { kind: 'confirm', risk }
      return { kind: 'allow' }
  }
}

export type MenuManualKind = 'p' | 'q' | 'enter' | null

/** Interpret a typed line while the session is at the JumpServer menu. */
export function menuManualKind(command: string): MenuManualKind {
  const trimmed = command.trim()
  if (trimmed.length === 0) return null
  if (trimmed.toLowerCase() === 'p') return 'p'
  if (trimmed.toLowerCase() === 'q' || trimmed.toLowerCase() === 'quit' || trimmed === '退出') return 'q'
  if (/^[a-zA-Z0-9_.:/-]+$/.test(trimmed) && !/^-/.test(trimmed)) return 'enter'
  return null
}

/** Classify a manual shell command (exported so the bridge can audit the risk). */
export function classifyManual(command: string): Classification {
  return classifyCommand(command)
}
