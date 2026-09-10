/**
 * V0.4.5: what session scope THIS request actually is.
 *
 * V0.4.4 tried to derive it from `sessionIdOf(exec).length > 0`, but
 * `sessionIdOf()` falls back to JUMPSERVER_MCP_SESSION / ANONYMOUS_SESSION —
 * both non-empty strings — so a plain WorkBuddy stdio conversation was
 * reported as `transport` even though no transport id was ever supplied.
 *
 * The only honest signal is whether the TRANSPORT carried a sessionId, so
 * that is what this function reads. It is the single implementation behind
 * `jumpserver_status.sessionScope`, so the report can no longer drift from
 * the resolution order used for the registry key.
 */
import type { ToolRunContext } from './context.js'
import type { SessionScopeMode } from './runtime.js'

/** True only when the HOST assigned a transport session id to this request. */
export function hasTransportSession(exec: Pick<ToolRunContext, 'sessionId'>): boolean {
  return typeof exec.sessionId === 'string' && exec.sessionId.length > 0
}

/**
 * The scope the caller is ACTUALLY on: 'transport' when the host supplied a
 * per-request sessionId, otherwise the runtime-wide mode ('env' → one scope
 * pinned by JUMPSERVER_MCP_SESSION, 'process' → stdio process isolation).
 */
export function projectSessionScope(
  exec: Pick<ToolRunContext, 'sessionId'>,
  runtimeScope: SessionScopeMode,
): SessionScopeMode {
  return hasTransportSession(exec) ? 'transport' : runtimeScope
}
