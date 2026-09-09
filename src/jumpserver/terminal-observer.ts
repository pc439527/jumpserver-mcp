/**
 * TerminalObserver: capture everything the JumpServer PTY session shows as a
 * monotonic seq-ordered event stream backed by a bounded ring buffer.
 *
 * SECURITY: browser-visible input/output is redacted BEFORE it enters this
 * buffer. The real PTY still receives the original command; the observer is a
 * display/audit surface and must never retain command-line credentials.
 *
 * Some Host operations (notably KoKo `p` asset discovery) must still consume
 * the exact PTY bytes for parsing while keeping that implementation detail out
 * of the human terminal. Those events are retained with visibility=internal;
 * the browser bridge omits them while Host-side parsers can still read them.
 */
import { MAX_TERMINAL_BYTES } from '../config/types.js'
import { redactCommandSecrets } from '../security/command-redaction.js'
import { SessionState } from './state-machine.js'

export type TerminalEventType = 'input' | 'output' | 'state' | 'target' | 'error'
export type TerminalVisibility = 'terminal' | 'internal'

export interface TerminalEventBase {
  seq: number
  timestamp: number
}

export interface TerminalInputEvent extends TerminalEventBase {
  type: 'input'
  /** Redacted form of what the connector wrote to the PTY. */
  data: string
  visibility?: TerminalVisibility
}

export interface TerminalOutputEvent extends TerminalEventBase {
  type: 'output'
  /** Redacted PTY chunk (ANSI retained; UTF-8 decoded). */
  data: string
  visibility?: TerminalVisibility
}

export interface TerminalStateEvent extends TerminalEventBase {
  type: 'state'
  state: SessionState
  prev: SessionState | null
}

export interface TerminalTargetEvent extends TerminalEventBase {
  type: 'target'
  target: string
  hostname: string | null
  user: string | null
  pwd: string | null
}

export interface TerminalErrorEvent extends TerminalEventBase {
  type: 'error'
  message: string
}

export type TerminalEvent =
  | TerminalInputEvent
  | TerminalOutputEvent
  | TerminalStateEvent
  | TerminalTargetEvent
  | TerminalErrorEvent

export type TerminalNewEvent =
  | { type: 'input'; data: string; visibility?: TerminalVisibility }
  | { type: 'output'; data: string; visibility?: TerminalVisibility }
  | { type: 'state'; state: SessionState; prev: SessionState | null }
  | { type: 'target'; target: string; hostname: string | null; user: string | null; pwd: string | null }
  | { type: 'error'; message: string }

/** Bounded ring buffer of terminal events with monotonic seq. */
export class TerminalRingBuffer {
  private events: TerminalEvent[] = []
  private cursor = 0
  private outputBytes = 0
  private maxEvents: number

  constructor(
    maxEvents = 20000,
    private readonly maxOutputBytes = MAX_TERMINAL_BYTES,
  ) {
    this.maxEvents = maxEvents
  }

  /** Re-budget on live settings change; trims oldest events when smaller. */
  setScrollbackRows(rows: number): void {
    const next = Math.max(1000, Math.min(200000, Math.round(rows) * 4))
    if (next === this.maxEvents) return
    this.maxEvents = next
    while (this.events.length > this.maxEvents) {
      const head = this.events[0]!
      if (head.type === 'output') this.outputBytes -= Buffer.byteLength(head.data, 'utf8')
      this.events.shift()
    }
  }

  /** Append one event; drops oldest events to respect the caps. */
  push(event: TerminalNewEvent): TerminalEvent {
    const seq = ++this.cursor
    const full = { ...event, seq, timestamp: Date.now() } as TerminalEvent
    this.events.push(full)
    if (event.type === 'output') {
      this.outputBytes += Buffer.byteLength(event.data, 'utf8')
    }
    while (this.outputBytes > this.maxOutputBytes && this.events.length > 0) {
      const head = this.events[0]!
      if (head.type === 'output') this.outputBytes -= Buffer.byteLength(head.data, 'utf8')
      this.events.shift()
    }
    while (this.events.length > this.maxEvents) {
      const head = this.events[0]!
      if (head.type === 'output') this.outputBytes -= Buffer.byteLength(head.data, 'utf8')
      this.events.shift()
    }
    return full
  }

  snapshotSince(sinceSeq: number): TerminalEvent[] {
    if (sinceSeq < 0) sinceSeq = 0
    if (this.events.length === 0 || sinceSeq >= this.cursor) return []
    return this.events.filter((e) => e.seq > sinceSeq)
  }

  snapshot(): TerminalEvent[] {
    return [...this.events]
  }

  get cursorSeq(): number {
    return this.cursor
  }

  get size(): number {
    return this.events.length
  }

  get oldestSeq(): number {
    return this.events.length > 0 ? this.events[0]!.seq : 0
  }

  clear(): void {
    this.events = []
    this.outputBytes = 0
  }
}

/** Emitting facade the session manager hands the bridge. */
export class TerminalObserver {
  private buffer = new TerminalRingBuffer()
  private internalCaptureDepth = 0

  constructor(private scrollbackRows = 5000) {}

  /**
   * Mark subsequently recorded PTY input/output as Host-internal while a
   * structured operation consumes the same stream. Nested callers are safe.
   * The returned disposer is idempotent and must be used in finally blocks.
   */
  beginInternalCapture(): () => void {
    this.internalCaptureDepth += 1
    let ended = false
    return () => {
      if (ended) return
      ended = true
      this.internalCaptureDepth = Math.max(0, this.internalCaptureDepth - 1)
    }
  }

  private get visibility(): TerminalVisibility {
    return this.internalCaptureDepth > 0 ? 'internal' : 'terminal'
  }

  recordInput(data: string): void {
    const safe = redactCommandSecrets(data)
    this.buffer.push({ type: 'input', data: safe, visibility: this.visibility })
  }

  recordOutput(data: string): void {
    if (data.length === 0) return
    // PTYs normally echo the command. Redacting raw output as well prevents a
    // secret from reappearing through that echo or through diagnostic logs.
    const safe = redactCommandSecrets(data)
    this.buffer.push({ type: 'output', data: safe, visibility: this.visibility })
  }

  recordState(state: SessionState, prev: SessionState | null): void {
    this.buffer.push({ type: 'state', state, prev })
  }

  recordTarget(target: string, hostname: string | null, user: string | null, pwd: string | null): void {
    this.buffer.push({ type: 'target', target, hostname, user, pwd })
  }

  recordError(message: string): void {
    this.buffer.push({ type: 'error', message: redactCommandSecrets(message) })
  }

  snapshotSince(sinceSeq: number): TerminalEvent[] {
    return this.buffer.snapshotSince(sinceSeq)
  }

  snapshot(): TerminalEvent[] {
    return this.buffer.snapshot()
  }

  get cursorSeq(): number {
    return this.buffer.cursorSeq
  }

  get oldestSeq(): number {
    return this.buffer.oldestSeq
  }

  clear(): void {
    this.buffer.clear()
  }

  get scrollback(): number {
    return this.scrollbackRows
  }

  setScrollbackRows(rows: number): void {
    const effective = Math.max(200, rows)
    this.scrollbackRows = effective
    this.buffer.setScrollbackRows(effective)
  }
}

export interface TerminalSnapshotMeta {
  lastSeq: number
  state: string
  connected: boolean
  gateway: string
  target: string | null
  hostname: string | null
  user: string | null
  permissionMode: string
  enabled: boolean
  configured: boolean
}
