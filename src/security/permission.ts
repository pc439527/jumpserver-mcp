import type { CommandRisk, PermissionMode } from '../config/types.js'
import { classifyCommand as classifyBaseCommand, type Classification } from './command-classifier.js'
import { classifyMysqlCli } from './sql-command-classifier.js'
import { JumpServerError } from '../jumpserver/errors.js'

export type GateDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; code: 'COMMAND_BLOCKED' | 'COMMAND_APPROVAL_REQUIRED'; reason: string }

/**
 * Authoritative classifier used by permission gates. Database CLIs with a
 * verified non-interactive SQL form are classified before falling back to the
 * generic shell classifier. Unknown/ambiguous SQL remains fail-closed.
 */
export function classifyCommand(command: string): Classification {
  return classifyMysqlCli(command) ?? classifyBaseCommand(command)
}

export function isReadOnlyAllowed(command: string): { allowed: boolean; reason?: string } {
  const classification = classifyCommand(command)
  if (classification.risk === 'READ') return { allowed: true }
  return { allowed: false, reason: classification.reason || 'not a confirmed read-only command' }
}

/**
 * V0.3.1 permission matrix (single fact source for Agent tools AND the manual
 * FOLLOW_AGENT policy):
 *
 *   risk             | READ_ONLY          | AUTO                | FULL_ACCESS
 *   -----------------|--------------------|---------------------|---------------
 *   READ             | allow              | allow               | allow
 *   PRIVILEGED_READ  | allow if configured| allow               | allow
 *   UNKNOWN          | deny (block)       | approval            | approval
 *   MODIFY           | deny (block)       | approval            | allow
 *   DANGEROUS        | deny (block)       | approval            | approval
 *
 * UNKNOWN is NEVER presented as MODIFY: it is blocked/approval-gated with the
 * honest copy "read-only cannot be confirmed".
 */
export function gateDecision(
  risk: CommandRisk,
  mode: PermissionMode,
  options: { privilegedReadInReadOnly?: boolean } = {},
): GateDecision {
  switch (mode) {
    case 'READ_ONLY':
      if (risk === 'READ') return { kind: 'allow' }
      if (risk === 'PRIVILEGED_READ' && options.privilegedReadInReadOnly === true) return { kind: 'allow' }
      return { kind: 'deny', code: 'COMMAND_BLOCKED', reason: 'blocked by READ_ONLY permission mode' }
    case 'AUTO':
      if (risk === 'READ' || risk === 'PRIVILEGED_READ') return { kind: 'allow' }
      return { kind: 'deny', code: 'COMMAND_APPROVAL_REQUIRED', reason: 'approval required in AUTO mode' }
    case 'FULL_ACCESS':
      if (risk === 'UNKNOWN' || risk === 'DANGEROUS') {
        return { kind: 'deny', code: 'COMMAND_APPROVAL_REQUIRED', reason: 'approval required even in FULL_ACCESS' }
      }
      return { kind: 'allow' }
  }
}

export type { Classification }

export interface TargetVerification {
  state: string
  currentTarget: string | null
  currentHostname: string | null
}

/**
 * Mandatory safety rule (requirement 21): before any MODIFY/DANGEROUS/UNKNOWN
 * command reaches the wire, the current target must be verified. Unverified
 * target = refuse, no approval prompt.
 */
export function requireTargetVerified(verification: TargetVerification): void {
  if (verification.state !== 'ASSET_SHELL' || verification.currentTarget === null || verification.currentHostname === null) {
    throw new JumpServerError(
      'TARGET_VERIFICATION_FAILED',
      'Target verification failed. Remote modification was not executed.',
    )
  }
}
