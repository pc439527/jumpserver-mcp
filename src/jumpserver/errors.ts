/**
 * Structured error codes for the JumpServer connector (V0.1).
 * DSH-independent: the tool layer maps these onto HarnessError codes.
 */
export const JUMP_ERROR_CODES = [
  'NOT_CONFIGURED',
  'DISABLED',
  'AUTH_FAILED',
  'CONNECTION_TIMEOUT',
  'CONNECTION_LOST',
  'NOT_AT_MENU',
  'MENU_NOT_DETECTED',
  'ASSET_ENTER_TIMEOUT',
  'ASSET_NOT_FOUND',
  'ASSET_VERIFY_FAILED',
  'NOT_IN_ASSET',
  'COMMAND_TIMEOUT',
  'COMMAND_BLOCKED',
  'COMMAND_APPROVAL_REQUIRED',
  'COMMAND_STATE_UNKNOWN',
  'LEAVE_TIMEOUT',
  'MENU_RETURN_FAILED',
  'SESSION_BUSY',
  'UNKNOWN_STATE',
  'TARGET_VERIFICATION_FAILED',
  'INVALID_GROUP',
  // V0.4.0: target outside allowedTargets / inside deniedTargets.
  'TARGET_DENIED',
  // V0.4.0: no running command to interrupt, or nothing to interrupt.
  'NOTHING_TO_INTERRUPT',
  // V0.4.0: inspect/topology target list too large.
  'TOO_MANY_TARGETS',
  // V0.3.1: an ops profile command the classifier does not confirm as READ.
  'PROFILE_RISK_MISMATCH',
] as const

export type JumpServerErrorCode = (typeof JUMP_ERROR_CODES)[number]

export class JumpServerError extends Error {
  readonly code: JumpServerErrorCode
  readonly detail?: string
  constructor(code: JumpServerErrorCode, message?: string, detail?: string) {
    super(message ?? code)
    this.name = 'JumpServerError'
    this.code = code
    this.detail = detail
  }
}

export function isJumpServerError(e: unknown): e is JumpServerError {
  return e instanceof JumpServerError
}

/** Caller/transport cancellation surfaced inside session loops; the tool layer maps it to TOOL_ABORTED. */
export class AbortRequestedError extends Error {
  constructor() {
    super('ABORTED')
    this.name = 'AbortRequestedError'
  }
}

export function errorCodeOf(e: unknown): string {
  if (isJumpServerError(e)) return e.code
  if (e instanceof Error && (e as { code?: unknown }).code !== undefined) {
    return String((e as { code?: unknown }).code)
  }
  return 'FAILED'
}
