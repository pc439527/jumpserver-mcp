/**
 * SessionRegistry: the one-JumpServer-per-conversation table.
 *
 * Every bundle is keyed by the authoritative DSH conversation id
 * (`exec.agent.session.header.id` on the Host face, `scope.sessionId` on the
 * browser face):
 *
 *   - conversation A -> JumpServerSession A (asset 113.99)
 *   - conversation B -> JumpServerSession B (asset 79.100)
 *   - conversation C -> no session yet
 *
 * Bundles are lazily created, never shared across ids, and detached once
 * their manager is fully idle-disconnected for longer than the grace window.
 */
import type { SessionManager } from './session-manager.js'
import type { TerminalObserver } from './terminal-observer.js'
import { SessionState } from './state-machine.js'

export interface SessionBundle {
  /** Conversation-dedicated manager (PTY/mutex/reconnect/currentTarget). */
  readonly manager: SessionManager
  /** Conversation-dedicated terminal mirror stream. */
  readonly observer: TerminalObserver
  /** Last meaningful use, for abandoned-bundle cleanup. */
  lastUsedAt: number
}

export interface SessionRegistryOptions {
  create: (sessionId: string) => SessionBundle
  now?: () => number
  detachGraceMs?: number
  /** V0.3.1 P2: called when a conversation bundle is detached — the owner
   *  cleans every session-attached structure (recent audits, cases, grants,
   *  confirmation tokens) so long-running hosts do not leak Maps. */
  onDetach?: (sessionId: string) => void
}

/** Fallback only for direct/mock tool calls that carry no Agent session. */
export const ANONYMOUS_SESSION = 'anonymous'

export class SessionRegistry {
  private readonly bundles = new Map<string, SessionBundle>()
  private readonly detachGraceMs: number

  constructor(private readonly options: SessionRegistryOptions) {
    this.detachGraceMs = options.detachGraceMs ?? 5 * 60 * 1000
  }

  get(sessionId: string): SessionBundle | undefined {
    return this.bundles.get(sessionId)
  }

  has(sessionId: string): boolean {
    return this.bundles.has(sessionId)
  }

  getOrCreate(sessionId: string): SessionBundle {
    if (sessionId.length === 0) sessionId = ANONYMOUS_SESSION
    let bundle = this.bundles.get(sessionId)
    if (bundle === undefined) {
      bundle = this.options.create(sessionId)
      this.bundles.set(sessionId, bundle)
    }
    bundle.lastUsedAt = (this.options.now ?? Date.now).call(undefined)
    return bundle
  }

  snapshot(): ReadonlyMap<string, SessionBundle> {
    return this.bundles
  }

  get size(): number {
    return this.bundles.size
  }

  applyScrollback(rows: number): void {
    for (const bundle of this.bundles.values()) {
      bundle.observer.setScrollbackRows(rows)
    }
  }

  tickIdle(): void {
    const now = (this.options.now ?? Date.now).call(undefined)
    for (const [sessionId, bundle] of [...this.bundles]) {
      bundle.manager.tickIdle()
      const state = bundle.manager.status().state
      const unusedFor = now - bundle.lastUsedAt
      if (state === SessionState.DISCONNECTED && unusedFor >= this.detachGraceMs) {
        this.bundles.delete(sessionId)
        bundle.manager.dispose()
        this.options.onDetach?.(sessionId)
      }
    }
  }

  dispose(): void {
    for (const [sessionId, bundle] of [...this.bundles]) {
      this.bundles.delete(sessionId)
      bundle.manager.dispose()
      this.options.onDetach?.(sessionId)
    }
  }
}
