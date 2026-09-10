import { SshPtyWire, type Wire } from './client.js'
import { AbortRequestedError, JumpServerError } from './errors.js'
import { MarkerWatcher } from './output-buffer.js'
import { cleanAnsi } from './output-buffer.js'
import { nextState, SessionState } from './state-machine.js'
import { ScreenDetector, type ScreenState } from './detector.js'
import { buildDoneScript, buildProbeScript, cleanCommandOutput, parseDoneLine, PROBE_PREFIX } from './command-runner.js'
import { parseProbeOutput } from './probe.js'
import { MAX_ASSET_CAPTURE_BYTES, MAX_OUTPUT_BYTES } from '../config/types.js'
import { footerComplete, hasPayloadEvidence, looksPaged, parseFooter } from './asset-list.js'
import { randomHex, sleep } from './timing.js'

export interface WireFactory {
  (params: {
    host: string
    port: number
    username: string
    password: string
    connectTimeoutMs: number
    /** V0.5.0: pinned SSH host-key fingerprint (optional). */
    hostFingerprint?: string
    /** V0.5.0: known_hosts store for TOFU. */
    knownHostsPath?: string
  }): Promise<Wire>
}

export interface SessionRuntimeConfig {
  host: string
  port: number
  username: string
  password: string
  /** Test seam: replaces the real ssh2 transport. */
  wireFactory?: WireFactory
  connectTimeoutMs: number
  /** V0.5.0: pinned SSH host-key fingerprint; when set, only a match is accepted. */
  hostFingerprint?: string
  /** V0.5.0: known_hosts store for TOFU when no fingerprint is pinned. */
  knownHostsPath?: string
  enterAssetMs: number
  probeMs: number
  commandMs: number
  leaveMs: number
  /** Bounded wait for the KoKo menu to settle after the 'p' asset-list command. */
  listAssetsMs: number
}

export interface SessionCallbacks {
  onStateChange?: (state: SessionState) => void
  /**
   * Emitted for every text the connector presents to the USER as a typed
   * command (the raw target line, the raw exec command, exit). Internal
   * protocol scripts (probe/done helpers, __dsh_rc) never surface here —
   * the browser mirror records them as wire noise, not as user input.
   */
  onInput?: (text: string) => void
  /**
   * Emitted for EVERY raw PTY output chunk as it arrives (echo included).
   * This is the realtime mirror source: the observer records chunks here,
   * so the browser displays actual server stdout, not connector inputs.
   */
  onOutput?: (chunk: string) => void
  /** Emitted once the target probe verified the asset (hostname/user/pwd known). */
  onTarget?: (target: string, hostname: string | null, user: string | null, pwd: string | null) => void
  onLost?: () => void
  onLog?: (message: string) => void
}

export interface SessionStatus {
  state: SessionState
  gateway: string
  target: string | null
  hostname: string | null
  user: string | null
  pwd: string | null
  connectedAt: number | null
  lastActivityAt: number | null
  reconnectCount: number
}

/**
 * V0.4.3: what actually happened to the COMMAND, as opposed to whether the
 * transport delivered a completion marker.
 *
 * `executionState: 'COMPLETED'` only means "the completion marker came back
 * normally". A command that exits 127 (`jps: command not found`) is a
 * COMPLETED execution with a FAILED command. Reporting it as ok=true hid real
 * failures from the model, the console audit and any PASS/FAIL judgement.
 */
export type CommandStatus =
  | 'SUCCESS'         // exit code 0
  | 'EXIT_NONZERO'    // ran to completion, exited with a non-zero code
  | 'TIMEOUT'         // the completion marker never arrived
  | 'INTERRUPTED'     // Ctrl+C / abort
  | 'CONNECTION_LOST' // the PTY closed underneath us
  | 'UNKNOWN'         // ran, but the outcome could not be determined

export type ExecOutcome =
  | { kind: 'completed'; exitCode: number; commandStatus: 'SUCCESS' | 'EXIT_NONZERO'; output: string; truncated: boolean; durationMs: number; executionState: 'COMPLETED' }
  | { kind: 'timeout'; commandStatus: 'TIMEOUT' | 'UNKNOWN'; output: string; truncated: boolean; durationMs: number; executionState: 'TIMEOUT' | 'UNKNOWN' }
  | { kind: 'signal-lost'; commandStatus: 'CONNECTION_LOST'; output: string; durationMs: number; executionState: 'UNKNOWN' }

export interface ExecOptions {
  timeoutMs?: number
  signal?: AbortSignal
}

const TARGET_PATTERN = /^[a-zA-Z0-9_.:/-]+$/

/** Screen-quiet threshold: the 'p' asset list is considered painted after this much silence. */
const LIST_QUIET_MS = 800

/** Timeout-recovery budget (prompt wait + probe) after a command timeout (ms). */
const EXEC_RECOVERY_MS = 3000

/** KoKo connection-failure markers that abort an asset entry fast (instead of waiting out the timeout). */
const ENTER_FAILURE_PATTERN = /连接失败|无法连接|连接超时|未找到|不存在|无权限|无资产|permission denied|ssh:\s*connect|host\s+key|timed\s*out|error|失败/i

/**
 * One persistent JumpServer session: a single SSH/PTY transport whose logical
 * state is tracked by {@link SessionState}. Transport host (gateway) and the
 * current asset target are kept strictly separate. Never guesses: ambiguity
 * collapses to UNKNOWN and every operation throws instead of acting.
 */
export class JumpServerSession {
  private wire: Wire | null = null
  private wireClosed = false
  private stateValue: SessionState = SessionState.DISCONNECTED
  private detector = new ScreenDetector()
  private opWatcher: MarkerWatcher | null = null
  /** While non-null, every raw chunk feeds this bounded, ANSI-stripped capture (listAssets). */
  private menuCapture: string | null = null
  private menuCaptureTruncated = false
  /**
   * Capture-local payload timestamps (V0.2.5 P0): the quiet timer for the
   * asset list runs from the LAST VALID ASSET PAYLOAD byte, never from the
   * whole session's lastActivityAt and never from the bare 'p' echo — the
   * echo used to start the 800ms timer before KoKo began printing the table,
   * cutting the 171-asset capture down to "p
".
   */
  private menuCapturePayloadAt: number | null = null
  private menuCaptureLastPayloadAt: number | null = null

  currentTarget: string | null = null
  currentHostname: string | null = null
  currentUser: string | null = null
  currentPwd: string | null = null
  connectedAt: number | null = null
  lastActivityAt: number | null = null
  reconnectCount = 0

  constructor(
    private readonly cfg: SessionRuntimeConfig,
    private readonly callbacks: SessionCallbacks = {},
  ) {}

  get state(): SessionState {
    return this.stateValue
  }

  /** True while in a state where PTY commands may be meaningful. */
  isLive(): boolean {
    return (
      this.stateValue === SessionState.JUMPSERVER_MENU ||
      this.stateValue === SessionState.ASSET_SHELL ||
      this.stateValue === SessionState.COMMAND_RUNNING ||
      this.stateValue === SessionState.ENTERING_ASSET
    )
  }

  hasPendingOp(): boolean {
    return this.opWatcher !== null
  }

  status(): SessionStatus {
    return {
      state: this.stateValue,
      gateway: this.cfg.host + ':' + this.cfg.port,
      target: this.currentTarget,
      hostname: this.currentHostname,
      user: this.currentUser,
      pwd: this.currentPwd,
      connectedAt: this.connectedAt,
      lastActivityAt: this.lastActivityAt,
      reconnectCount: this.reconnectCount,
    }
  }

  async connect(signal?: AbortSignal): Promise<void> {
    if (this.stateValue === SessionState.JUMPSERVER_MENU || this.stateValue === SessionState.ASSET_SHELL) return
    this.setState(SessionState.CONNECTING)
    try {
      const wire = this.cfg.wireFactory !== undefined
        ? await this.cfg.wireFactory({
            host: this.cfg.host,
            port: this.cfg.port,
            username: this.cfg.username,
            password: this.cfg.password,
            connectTimeoutMs: this.cfg.connectTimeoutMs,
            hostFingerprint: this.cfg.hostFingerprint,
            knownHostsPath: this.cfg.knownHostsPath,
          })
        : await SshPtyWire.connect({
            host: this.cfg.host,
            port: this.cfg.port,
            username: this.cfg.username,
            password: this.cfg.password,
            connectTimeoutMs: this.cfg.connectTimeoutMs,
            hostFingerprint: this.cfg.hostFingerprint,
            knownHostsPath: this.cfg.knownHostsPath,
          })
      this.attach(wire)
      const menuSeen = await this.waitForScreen(SessionState.JUMPSERVER_MENU, this.cfg.connectTimeoutMs, signal)
      if (!menuSeen) {
        this.setState(SessionState.UNKNOWN)
        throw new JumpServerError('MENU_NOT_DETECTED', 'connected, but the JumpServer menu was not detected within the connect timeout')
      }
      this.connectedAt = Date.now()
      this.setState(SessionState.JUMPSERVER_MENU)
      this.touch()
    } catch (error) {
      this.teardownTransport()
      this.setState(SessionState.ERROR)
      throw error
    }
  }

  async enter(target: string, signal?: AbortSignal): Promise<void> {
    this.assertState(SessionState.JUMPSERVER_MENU, 'NOT_AT_MENU', 'enter(target) requires the JumpServer menu')
    if (!TARGET_PATTERN.test(target)) {
      throw new JumpServerError('ASSET_NOT_FOUND', 'invalid target: ' + target)
    }
    this.currentTarget = target
    this.currentHostname = null
    this.currentUser = null
    this.currentPwd = null
    this.setState(SessionState.ENTERING_ASSET)
    try {
      this.wire!.write(target + '\n')
    this.callbacks.onInput?.(target) // the user-visible target line
      // KoKo dials the asset with a progress banner; watch for the prompt,
      // a connection-failure message, the wire closing, or the deadline.
      const deadline = Date.now() + this.cfg.enterAssetMs
      let shellSeen = false
      let failureText: string | undefined
      for (;;) {
        const screen = this.detector.detect()
        if (screen === 'ASSET_SHELL') {
          shellSeen = true
          break
        }
        const tail = this.detector.tailPreview(400)
        const failure = ENTER_FAILURE_PATTERN.exec(tail)
        if (failure !== null) {
          failureText = failure[0]
          break
        }
        if (this.wireClosed || this.wire === null) break
        if (signal?.aborted === true) throw new AbortRequestedError()
        if (Date.now() >= deadline) break
        await sleep(120)
      }
      if (failureText !== undefined) {
        this.setState(SessionState.UNKNOWN)
        throw new JumpServerError('ASSET_ENTER_TIMEOUT', 'asset connection reported failure while entering ' + target, failureText)
      }
      if (!shellSeen) {
        this.setState(SessionState.UNKNOWN)
        throw new JumpServerError('ASSET_ENTER_TIMEOUT', 'asset shell for ' + target + ' was not detected within the enter timeout')
      }
      const marker = randomHex(6)
      const probeScript = buildProbeScript(marker)
      // The probe script is connector-internal: it must NOT be recorded as a
      // user-visible input line. Its H=/U=/P= results arrive as output events
      // and are surfaced through onTarget (the terminal shows a target meta row).
      const run = await this.runOp(probeScript, PROBE_PREFIX + marker, this.cfg.probeMs, signal)
      if (run.aborted) throw new AbortRequestedError()
      if (run.closed) {
        this.setState(SessionState.DISCONNECTED)
        throw new JumpServerError('CONNECTION_LOST', 'connection lost while probing ' + target)
      }
      const info = run.matched ? parseProbeOutput(run.text, marker) : null
      if (info === null) {
        this.setState(SessionState.UNKNOWN)
        throw new JumpServerError('ASSET_VERIFY_FAILED', 'target verification (probe) failed on ' + target)
      }
      this.currentHostname = info.hostname
      this.currentUser = info.user
      this.currentPwd = info.pwd
      this.callbacks.onTarget?.(target, info.hostname, info.user, info.pwd)
      this.setState(SessionState.ASSET_SHELL)
      this.touch()
    } catch (error) {
      if (this.stateValue === SessionState.ENTERING_ASSET && !this.wireClosed) this.setState(SessionState.UNKNOWN)
      throw error
    }
  }

  async exec(command: string, options: ExecOptions = {}): Promise<ExecOutcome> {
    this.assertState(SessionState.ASSET_SHELL, 'NOT_IN_ASSET', 'exec requires an entered (verified) asset shell')
    const timeoutMs = Math.min(options.timeoutMs ?? this.cfg.commandMs, MAX_COMMAND_SECONDS * 1000)
    const marker = randomHex(8)
    const script = buildDoneScript(command, marker)
    const started = Date.now()
    this.setState(SessionState.COMMAND_RUNNING)
    // The terminal mirror records the RAW command the model asked for — never
    // the done-script wrapper (__dsh_rc / printf / completion marker noise).
    // The wire still writes the full script; only the recorded input differs.
    this.callbacks.onInput?.(command)
    this.touch()
    try {
      const run = await this.runOp(script, marker, timeoutMs, options.signal)
      const durationMs = Date.now() - started
      if (run.aborted) {
        // V0.4.0 P0: an ABORT is not a timeout, but the risk is the same —
        // the remote foreground job keeps running after the model stopped
        // listening (tail -f, a stuck script, a long find). Interrupt it with
        // Ctrl+C and re-prove the shell before the connector declares the
        // asset usable again. Note the recovery runs WITHOUT the abort signal:
        // we are already aborting, so it must not cancel itself.
        const verified = await this.interruptAndRecover(EXEC_RECOVERY_MS)
        if (verified) {
          this.setState(SessionState.ASSET_SHELL)
          this.touch()
        } else {
          this.setState(SessionState.UNKNOWN)
          this.callbacks.onLog?.('command aborted; the remote job was interrupted but the shell could not be re-verified - session collapsed to UNKNOWN')
        }
        throw new AbortRequestedError()
      }
      if (run.closed) {
        this.setState(SessionState.DISCONNECTED)
        return { kind: 'signal-lost', commandStatus: 'CONNECTION_LOST', output: '', durationMs, executionState: 'UNKNOWN' }
      }
      if (!run.matched) {
        // V0.2.5 P0: a timeout only means the completion marker never
        // arrived — the remote foreground job may STILL be running (tail -f,
        // top, a stuck script). Never declare the shell usable blindly.
        // Interrupt the job (Ctrl+C), wait for the prompt, then re-prove the
        // shell with the lightweight probe; otherwise collapse to UNKNOWN so
        // the next navigation reconnects instead of typing into a dead PTY.
        const verified = await this.interruptAndRecover(EXEC_RECOVERY_MS, options.signal)
        if (!verified) {
          this.setState(SessionState.UNKNOWN)
          this.callbacks.onLog?.('command timed out and the shell could not be re-verified; session collapsed to UNKNOWN')
          return { kind: 'timeout', commandStatus: 'UNKNOWN', output: run.text, truncated: run.truncated, durationMs, executionState: 'UNKNOWN' }
        }
        this.setState(SessionState.ASSET_SHELL)
        this.touch()
        return { kind: 'timeout', commandStatus: 'TIMEOUT', output: run.text, truncated: run.truncated, durationMs, executionState: 'TIMEOUT' }
      }
      const done = parseDoneLine(run.text, marker)
      this.setState(SessionState.ASSET_SHELL)
      if (done === null) {
        this.setState(SessionState.UNKNOWN)
        throw new JumpServerError('COMMAND_STATE_UNKNOWN', 'completion marker found but exit code could not be parsed')
      }
      return {
        kind: 'completed',
        exitCode: done.exitCode,
        // V0.4.3: the command itself succeeded or failed — separate from the
        // transport having completed the exchange.
        commandStatus: done.exitCode === 0 ? 'SUCCESS' : 'EXIT_NONZERO',
        output: cleanCommandOutput(run.text, marker),
        truncated: run.truncated,
        durationMs,
        executionState: 'COMPLETED',
      }
    } catch (error) {
      if (this.stateValue === SessionState.COMMAND_RUNNING && !this.wireClosed) this.setState(SessionState.ASSET_SHELL)
      throw error
    }
  }

  /**
   * V0.4.0 P0: out-of-band interrupt. Writes Ctrl+C straight to the PTY
   * WITHOUT taking the operation queue, so it reaches the remote shell even
   * while a command (or a whole batch) is still in flight. Used by
   * jumpserver_interrupt and by the console's 中断 button.
   */
  sendInterrupt(): boolean {
    if (this.wire === null || this.wireClosed) return false
    try {
      this.wire.write('\u0003')
      this.callbacks.onInput?.('^C')
      return true
    } catch {
      return false
    }
  }

  /**
   * Interrupt whatever the remote shell is doing, then re-prove the shell.
   * The connector only returns to ASSET_SHELL when a probe actually answers.
   * V0.4.4: a thin wrapper around interruptAndVerify() so there is exactly
   * ONE place that combines Ctrl+C with re-probe.
   */
  async interrupt(budgetMs: number = EXEC_RECOVERY_MS): Promise<{ sent: boolean; verified: boolean; state: SessionState }> {
    return this.interruptAndVerify(budgetMs)
  }

  /**
   * V0.4.4: the ONLY public path that combines Ctrl+C with a probe. Stops
   * a streaming job / out-of-band interrupt / exec recovery all funnel
   * through here so the connector never sends ^C twice and never declares
   * the shell usable without a fresh probe.
   */
  async interruptAndVerify(budgetMs: number = EXEC_RECOVERY_MS): Promise<{ sent: boolean; verified: boolean; state: SessionState }> {
    const sent = this.sendInterrupt()
    if (!sent) return { sent: false, verified: false, state: this.stateValue }
    this.callbacks.onLog?.('interrupt: Ctrl+C sent; re-verifying the remote shell')
    const verified = await this.probeShellOnly(budgetMs)
    if (verified) {
      this.setState(SessionState.ASSET_SHELL)
      this.touch()
    } else {
      this.setState(SessionState.UNKNOWN)
    }
    return { sent, verified, state: this.stateValue }
  }

  /**
   * V0.4.4: prove the shell is at a prompt WITHOUT sending another Ctrl+C.
   * Use this when the caller already knows the foreground job has been
   * interrupted (e.g. JobStore.stop -> the previous interruptAndVerify
   * step cleared the queue; re-probing must NOT send ^C again).
   */
  async verifyShell(budgetMs = 3000): Promise<boolean> {
    return this.probeShellOnly(budgetMs)
  }

  /**
   * Raw write for the streaming job model (tail -f / journalctl -f / top):
   * the line is sent as-is, with NO completion marker and NO state wait —
   * output is collected from the observer stream instead.
   */
  writeLine(text: string): boolean {
    if (this.wire === null || this.wireClosed) return false
    try {
      this.wire.write(text.endsWith('\n') ? text : text + '\n')
      this.callbacks.onInput?.(text.replace(/\n$/, ''))
      this.touch()
      return true
    } catch {
      return false
    }
  }

  async leave(signal?: AbortSignal): Promise<void> {
    this.assertState(SessionState.ASSET_SHELL, 'NOT_IN_ASSET', 'leave requires an entered asset shell')
    // Exactly one exit attempt: never auto-send multiple exits.
    this.wire!.write('exit\n')
    this.callbacks.onInput?.('exit')
    const back = await this.waitForScreen(SessionState.JUMPSERVER_MENU, this.cfg.leaveMs, signal)
    if (!back) {
      this.setState(SessionState.UNKNOWN)
      throw new JumpServerError('MENU_RETURN_FAILED', 'exit was sent but the JumpServer menu was not confirmed')
    }
    this.currentTarget = null
    this.currentHostname = null
    this.currentUser = null
    this.currentPwd = null
    this.setState(SessionState.JUMPSERVER_MENU)
    this.touch()
  }

  /**
   * List every asset the account is authorized for (KoKo menu command 'p').
   * Display-only: 'p' prints the list and returns to the same menu, so the
   * PTY state NEVER changes ownership here. Captures the screen for a bounded
   * window, stopping once output goes quiet (the list finished painting) or
   * the deadline passes. If the captured tail smells like an interactive
   * pager the session is collapsed to UNKNOWN so the next navigation
   * reconnects instead of typing into the pager.
   */
  async listAssets(timeoutMs?: number, signal?: AbortSignal): Promise<{
    text: string
    truncated: boolean
    paged: boolean
    payload: boolean
    footerComplete: boolean
    reportedTotal: number | null
  }> {
    this.assertState(SessionState.JUMPSERVER_MENU, 'NOT_AT_MENU', 'listAssets requires the JumpServer menu')
    const wire = this.wire
    if (wire === null || this.wireClosed) throw new JumpServerError('CONNECTION_LOST', 'no live JumpServer session; call connect or run first')
    const deadline = Date.now() + Math.min(timeoutMs ?? this.cfg.listAssetsMs, 30000)
    this.menuCapture = ''
    this.menuCaptureTruncated = false
    this.menuCapturePayloadAt = null
    this.menuCaptureLastPayloadAt = null
    // V0.2.5 P0: a real interactive PTY's Enter key is CR ('\r'), not LF
    // ('\n'). KoKo only starts printing the asset table once it receives the
    // CR; 'p\n' is what produced the truncated "p\n" captures.
    wire.write('p\r')
    // The mirror shows the keystroke; the KoKo echo ("Opt> p") is dropped by
    // the client echo filter like any other echoed input.
    this.callbacks.onInput?.('p')
    let captured = ''
    let truncated = false
    let payload = false
    try {
      for (;;) {
        if (signal?.aborted === true) throw new AbortRequestedError()
        if (this.wireClosed || this.wire === null) {
          throw new JumpServerError('CONNECTION_LOST', 'connection lost while listing assets')
        }
        const screen = this.detector.detect()
        if (screen === 'ASSET_SHELL') {
          this.setState(SessionState.UNKNOWN)
          throw new JumpServerError('UNKNOWN_STATE', 'asset list unexpectedly landed in a shell; reconnect and retry')
        }
        // Phase A (WAIT_PAYLOAD) -> B (COLLECTING): without a real asset
        // payload (numbered/pipe row, header, footer, explicit no-asset
        // notice) the bare 'p' echo and lone menu prompt NEVER start the
        // quiet timer — we keep waiting for the actual reply (V0.2.5 P0).
        payload = this.menuCapturePayloadAt !== null
        if (payload) {
          const text = this.menuCapture ?? ''
          // Primary completion: KoKo painted the footer and returned to the
          // menu prompt — the whole list is on screen. No silence guessing.
          if (footerComplete(text)) break
          // Fallback: 800ms silence AFTER the last valid payload byte.
          if (Date.now() - (this.menuCaptureLastPayloadAt ?? 0) >= LIST_QUIET_MS) break
        }
        if (Date.now() >= deadline) break
        await sleep(100)
      }
      captured = this.menuCapture ?? ''
      truncated = this.menuCaptureTruncated
    } finally {
      // Capture is strictly per-operation: reset on every path so a failed or
      // aborted list never keeps accumulating wire bytes.
      this.menuCapture = null
      this.menuCaptureTruncated = false
      this.menuCapturePayloadAt = null
      this.menuCaptureLastPayloadAt = null
    }
    if (this.detector.detect() === 'ASSET_SHELL') {
      this.setState(SessionState.UNKNOWN)
      throw new JumpServerError('UNKNOWN_STATE', 'asset list unexpectedly landed in a shell; reconnect and retry')
    }
    const paged = looksPaged(captured)
    if (paged) {
      // The list is interactive: never risk typing into the pager on the next
      // navigation. Collapse to UNKNOWN so the next op reconnects to a clean menu.
      this.setState(SessionState.UNKNOWN)
    }
    return {
      text: captured,
      truncated,
      paged,
      payload,
      footerComplete: footerComplete(captured),
      reportedTotal: parseFooter(captured).total,
    }
  }

  async close(): Promise<void> {
    const wire = this.wire
    this.wire = null
    this.opWatcher = null
    this.wireClosed = true
    try {
      wire?.close()
    } catch {
      /* already closed */
    }
    this.currentTarget = null
    this.currentHostname = null
    this.currentUser = null
    this.currentPwd = null
    this.connectedAt = null
    this.lastActivityAt = null
    this.detector.reset()
    this.setState(SessionState.DISCONNECTED)
  }

  touch(): void {
    this.lastActivityAt = Date.now()
  }

  /** Debug aid: last normalized screen tail (never contains secrets). */
  screenTail(n = 400): string {
    return this.detector.tailPreview(n)
  }

  private attach(wire: Wire): void {
    this.wire = wire
    this.wireClosed = false
    wire.onData((chunk) => this.onData(chunk))
    wire.onError((error) => {
      this.callbacks.onLog?.('wire error: ' + error.message)
      wire.close()
    })
    wire.onClose(() => this.onWireClose())
  }

  private onData(chunk: string): void {
    this.touch()
    // Realtime mirror: every raw chunk is emitted first, then fed to the
    // screen detector and the in-flight marker watcher. Order matters — the
    // observer must never miss a chunk because a later stage threw.
    this.callbacks.onOutput?.(chunk)
    this.detector.push(chunk)
    this.opWatcher?.push(chunk)
    if (this.menuCapture !== null) {
      const clean = cleanAnsi(chunk)
      if (clean.length > 0) {
        const now = Date.now()
        if (this.menuCapturePayloadAt === null) {
          // Phase A -> B: ONLY asset payload bytes (numbered/pipe row, header,
          // footer, explicit no-asset notice) start the quiet timer; the 'p'
          // echo and a lone prompt must never do it (V0.2.5 P0).
          if (hasPayloadEvidence(clean)) {
            this.menuCapturePayloadAt = now
            this.menuCaptureLastPayloadAt = now
          }
        } else {
          // V0.2.6 P1: once the payload started, ANY captured byte — even a
          // slow/fragmented continuation that does not itself match the
          // payload regex — refreshes the quiet timer, so a >800ms gap
          // mid-stream cannot truncate the capture.
          this.menuCaptureLastPayloadAt = now
        }
        const room = MAX_ASSET_CAPTURE_BYTES - this.menuCapture.length
        if (clean.length > room) {
          this.menuCapture += clean.slice(0, Math.max(0, room))
          this.menuCaptureTruncated = true
        } else {
          this.menuCapture += clean
        }
      }
    }
  }

  private onWireClose(): void {
    this.wireClosed = true
    if (this.stateValue !== SessionState.DISCONNECTED) this.setState(SessionState.DISCONNECTED)
    this.callbacks.onLost?.()
  }

  private async waitForScreen(target: SessionState, timeoutMs: number, signal?: AbortSignal): Promise<boolean> {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      const seen = this.detector.detect()
      if (seen === this.screenFor(target)) return true
      if (this.wireClosed || this.wire === null) return false
      if (signal?.aborted === true) throw new AbortRequestedError()
      if (Date.now() >= deadline) return false
      await sleep(80)
    }
  }

  private screenFor(state: SessionState): ScreenState {
    if (state === SessionState.JUMPSERVER_MENU) return 'JUMPSERVER_MENU'
    if (state === SessionState.ASSET_SHELL) return 'ASSET_SHELL'
    return undefined
  }

  /** Run one script and watch for its marker; bounded capture, cancellable. */
  private async runOp(
    script: string,
    marker: string,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<{ matched: boolean; closed: boolean; aborted: boolean; text: string; truncated: boolean }> {
    const wire = this.wire
    if (wire === null || this.wireClosed) return { matched: false, closed: true, aborted: false, text: '', truncated: false }
    const watcher = new MarkerWatcher(marker, MAX_OUTPUT_BYTES)
    this.opWatcher = watcher
    wire.write(script + '\n')
    try {
      const deadline = Date.now() + timeoutMs
      for (;;) {
        if (watcher.matched()) return { matched: true, closed: false, aborted: false, text: watcher.buffer.peek(), truncated: watcher.buffer.truncated }
        if (this.wireClosed) return { matched: false, closed: true, aborted: false, text: watcher.buffer.peek(), truncated: watcher.buffer.truncated }
        if (signal?.aborted === true) return { matched: false, closed: false, aborted: true, text: watcher.buffer.peek(), truncated: watcher.buffer.truncated }
        if (Date.now() >= deadline) return { matched: false, closed: false, aborted: false, text: watcher.buffer.peek(), truncated: watcher.buffer.truncated }
        await sleep(80)
      }
    } finally {
      this.opWatcher = null
    }
  }

  /**
   * V0.4.4: ^C + re-probe. The single V0.4.0→V0.4.3 entry point for exec
   * recovery (timeout / abort) and any other path that MUST interrupt a
   * possibly running remote job before declaring the shell usable again.
   * Splits the V0.4.3 recoverShell() into a pure probe (probeShellOnly)
   * plus this ^C wrapper so callers that have already interrupted can
   * re-probe WITHOUT sending a second Ctrl+C.
   */
  private async interruptAndRecover(budgetMs: number, signal?: AbortSignal): Promise<boolean> {
    if (this.wire === null || this.wireClosed) return false
    try {
      this.wire.write('\u0003')
    } catch {
      return false
    }
    this.callbacks.onLog?.('command timed out; sending Ctrl+C and re-verifying the remote shell')
    return this.probeShellOnly(budgetMs, signal)
  }

  /**
   * V0.4.4: prove the shell answers a probe WITHOUT touching the wire.
   * Waits for the asset-shell prompt, runs the connector-internal probe,
   * parses the H=/U=/P= answer. Returns false when the wire is gone, the
   * prompt never arrived, the probe did not match, or the parser failed.
   * Pure side-effect-free test of "can I trust this session again".
   */
  private async probeShellOnly(budgetMs: number, signal?: AbortSignal): Promise<boolean> {
    if (this.wire === null || this.wireClosed) return false
    const promptDeadline = Date.now() + Math.min(budgetMs, 2000)
    for (;;) {
      if (signal?.aborted === true) return false
      if (this.wireClosed || this.wire === null) return false
      if (this.detector.detect() === 'ASSET_SHELL') break
      if (Date.now() >= promptDeadline) return false
      await sleep(100)
    }
    const marker = randomHex(6)
    const run = await this.runOp(buildProbeScript(marker), PROBE_PREFIX + marker, Math.min(budgetMs, 3000), signal)
    if (run.aborted || run.closed || !run.matched) return false
    return parseProbeOutput(run.text, marker) !== null
  }

  /**
   * V0.4.3: apply the outcome of an out-of-band verification (job stop).
   * recoverShell proves the shell answers a probe; the caller must then move
   * the state machine to match, or the session keeps reporting its stale
   * COMMAND_RUNNING / UNKNOWN state.
   */
  setStateForVerification(state: 'ASSET_SHELL' | 'UNKNOWN'): void {
    this.setState(state === 'ASSET_SHELL' ? SessionState.ASSET_SHELL : SessionState.UNKNOWN)
    if (state === 'ASSET_SHELL') this.touch()
  }

  private assertState(expected: SessionState, code: 'NOT_AT_MENU' | 'NOT_IN_ASSET', detail: string): void {
    if (this.stateValue !== expected) throw new JumpServerError(code, detail)
  }

  private setState(next: SessionState): void {
    if (this.stateValue === next) return
    const resolved = nextState(this.stateValue, next)
    if (resolved === SessionState.UNKNOWN && next !== SessionState.UNKNOWN) {
      this.callbacks.onLog?.('illegal state transition ' + this.stateValue + ' -> ' + next + ' collapsed to UNKNOWN')
    }
    this.stateValue = resolved
    this.callbacks.onStateChange?.(resolved)
  }

  private teardownTransport(): void {
    const wire = this.wire
    this.wire = null
    this.opWatcher = null
    this.wireClosed = true
    try {
      wire?.close()
    } catch {
      /* already closed */
    }
  }
}

export const MAX_COMMAND_SECONDS = 600
