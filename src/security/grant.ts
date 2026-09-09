/**
 * JumpServer Session Grant (V0.2.4 P0): the FIRST permission boundary.
 *
 * The plugin distinguishes two independent security controls:
 *
 *   1. Session Grant  — is THIS conversation explicitly authorized by the
 *      user (through the /jumpserver slash command) to use jumpserver_* at
 *      all? Tools refuse with JUMPSERVER_NOT_ARMED while locked.
 *   2. Agent Permission Mode — READ_ONLY / AUTO / FULL_ACCESS gating of the
 *      individual command risk (existing security/permission-gate.ts).
 *
 * LOCKED (default) -> /jumpserver <task> -> ARMED_FOR_TURN -> turn settles
 * -> LOCKED. Bare /jumpserver arms a persistent grant revoked by
 * /jumpserver off, by session teardown, or by plugin dispose. The grant is
 * keyed by the same conversation id the tools use (agent.session.header.id),
 * so a grant in one conversation never unlocks another.
 */
export type GrantMode = 'persistent' | 'turn'

export interface GrantState {
  readonly mode: GrantMode
  readonly armedAt: number
  /** Safety cap (ms since epoch); undefined = no expiry (revoked explicitly). */
  readonly expiresAt?: number
}

/** Tool-level code returned while the conversation grant is locked. */
export const JUMPSERVER_NOT_ARMED = 'JUMPSERVER_NOT_ARMED'

export const NOT_ARMED_MESSAGE =
  'JumpServer is locked for this conversation. Run the /jumpserver slash command ' +
  '(e.g. "/jumpserver check CPU/memory/disk of 203.0.113.99") to authorize one ' +
  'JumpServer task for this turn.'

/** Fallback hard cap for turn-scoped grants (the turn-settle relock is primary). */
export const DEFAULT_TURN_GRANT_TTL_MS = 30 * 60 * 1000

export class SessionGrant {
  private readonly grants = new Map<string, GrantState>()

  constructor(private readonly clock: () => number = Date.now) {}

  /**
   * Arm the grant for one conversation. `ttlMs` overrides the mode default;
   * 'turn' grants always carry a hard safety cap.
   */
  arm(sessionId: string, mode: GrantMode, ttlMs?: number): GrantState {
    const now = this.clock()
    const expiresAt = ttlMs !== undefined
      ? now + ttlMs
      : mode === 'turn'
        ? now + DEFAULT_TURN_GRANT_TTL_MS
        : undefined
    const state: GrantState = { mode, armedAt: now, expiresAt }
    this.grants.set(sessionId, state)
    return state
  }

  isGranted(sessionId: string): boolean {
    const state = this.grants.get(sessionId)
    if (state === undefined) return false
    const now = this.clock()
    if (state.expiresAt !== undefined && now >= state.expiresAt) {
      this.grants.delete(sessionId)
      return false
    }
    return true
  }

  modeOf(sessionId: string): GrantMode | null {
    if (!this.isGranted(sessionId)) return null
    return this.grants.get(sessionId)!.mode
  }

  revoke(sessionId: string): void {
    this.grants.delete(sessionId)
  }

  revokeAll(): void {
    this.grants.clear()
  }

  sessionIds(): string[] {
    return [...this.grants.keys()].filter((id) => this.isGranted(id))
  }
}
