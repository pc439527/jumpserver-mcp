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
  // V0.4.1: runbook / compare / baseline.
  'UNKNOWN_RUNBOOK',
  'RUNBOOK_NO_READ_STEPS',
  'UNKNOWN_BASELINE',
  'BASELINE_MISMATCH',
  'INVALID_ARGUMENT',
  // V0.5.0: the bastion's SSH host key contradicts the pinned fingerprint or
  // the recorded known_hosts entry — the connection is refused before auth.
  'HOST_KEY_MISMATCH',
  // V0.5.3: KoKo painted a multi-username selection screen (`ID>` + numbered
  // list) and the caller did not pass `accountIndex`. The connector never
  // auto-picks an account — the operator must tell it which one to use.
  // `detail` carries the parsed list (`accounts=0:admin | 1:ops | 2:root`).
  'ACCOUNT_SELECTION_REQUIRED',
  // V0.5.5: KoKo reported a NETWORK-level failure while dialling the asset
  // (`开始连接到 root(root)@10.0.0.10 error: 网络不通（连接超时）`). The bastion
  // itself is fine and the credentials are fine — the asset is not reachable
  // from the bastion. Distinct from ASSET_ENTER_TIMEOUT on purpose: it is a
  // STOP condition (report to the user), not a "try again with other
  // arguments" condition, and the same target is refused for a cooldown window
  // so a retry loop cannot burn minutes of PTY dial time.
  'ASSET_UNREACHABLE',
  // V0.5.6: the caller came back to answer a KoKo `ID>` selection prompt, but
  // the prompt is no longer on the session (KoKo timed the selection out, or
  // the transport died underneath it). The answer must go through a fresh
  // enter() — retrying the same accountIndex on this session cannot work.
  'ACCOUNT_SELECTION_EXPIRED',
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

/**
 * V0.5.5: the STOP wording for ASSET_UNREACHABLE. It lives here (not in the
 * runtime layer) because every renderer needs it — the single-result
 * projection in tools-common AND the hand-written multi-target renderers in
 * inspector / runbook / compare. Without one shared string the batch tools
 * silently lose the sentence that stops the retry loop.
 *
 * Measured on a real conversation: after one `网络不通（连接超时）` banner the
 * model ran eight more enter/connect cycles (2m53s) because nothing in the
 * result said "this will not get better by retrying". Every retry also costs
 * the bastion's own dial timeout (~15 s) before it can even fail again.
 */
export const UNREACHABLE_STOP_LINE =
  'next: STOP — the bastion cannot reach this asset. Do NOT retry jumpserver_enter / jumpserver_run / ' +
  'jumpserver_connect for it and do not keep diagnosing: report to the user that the server is ' +
  'temporarily unreachable and continue with a different target or wait for the user.'

/**
 * V0.5.9: the one-line reason written to the audit when a command was stopped
 * because approval was not granted. Shared so the gate (exec path) and the
 * manager (run / batch / job paths) record the SAME wording — an audit where
 * the reason depends on which path refused is worse than no reason at all.
 */
export const APPROVAL_DENIED_REASON = '未获人工批准（confirm 未提供或未同意）'

/** Lines for a nested `{code,message,detail?}` failure (SessionManager.errorDetail shape). */
export function renderFailureLines(
  error: { code: string; message: string; detail?: string } | null,
  indent = '',
): string[] {
  if (error === null) return []
  const lines = [indent + error.code + ': ' + error.message]
  if (typeof error.detail === 'string' && error.detail.length > 0) lines.push(indent + '  detail: ' + error.detail)
  if (error.code === 'ASSET_UNREACHABLE') lines.push(indent + '  ' + UNREACHABLE_STOP_LINE)
  return lines
}

export function errorCodeOf(e: unknown): string {
  if (isJumpServerError(e)) return e.code
  if (e instanceof Error && (e as { code?: unknown }).code !== undefined) {
    return String((e as { code?: unknown }).code)
  }
  return 'FAILED'
}
