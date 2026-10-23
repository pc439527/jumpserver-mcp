import { SshPtyWire, type Wire } from './client.js'
import { AbortRequestedError, JumpServerError } from './errors.js'
import { MarkerWatcher } from './output-buffer.js'
import { cleanAnsi } from './output-buffer.js'
import { nextState, SessionState } from './state-machine.js'
import { looksLikeAccountSelection, looksLikeMenuPrompt, looksLikeShellPrompt, ScreenDetector, type ScreenState } from './detector.js'
import { buildDoneScript, buildProbeScript, cleanCommandOutput, doneMarkerPattern, parseDoneLine, probeMarkerPattern, DONE_PREFIX, PROBE_PREFIX } from './command-runner.js'
import { parseProbeOutput } from './probe.js'
import { verifyTargetIdentity } from './target-verify.js'
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
 * V0.5.5: the SUBSET of those markers that means "the bastion cannot reach the
 * asset at all". Real KoKo banner (captured from a live session):
 *
 *   开始连接到 root(root)@10.0.0.10 error: 网络不通（连接超时）
 *
 * Kept separate from {@link ENTER_FAILURE_PATTERN} because the two need
 * different answers: a generic failure is worth a diagnostic, but an
 * unreachable asset is a STOP — the credentials, the account index and the
 * tool arguments are all irrelevant, so retrying can only burn another KoKo
 * dial timeout (measured: ~15 s per attempt) and another model round-trip.
 */
const ENTER_UNREACHABLE_PATTERN =
  /网络不通|网络不可达|无法访问|无法连接|连接超时|连接失败|连接被拒绝|拒绝连接|连接被重置|no route to host|network is unreachable|connection (?:timed out|refused|reset|closed)|connect(?:ion)? refused|unable to connect|dial tcp/i

/**
 * V0.5.5: how long a target that just failed to dial is refused outright (ms).
 * Long enough to break a model's retry loop, short enough that a real network
 * fix does not need a connector restart. Every refusal reports the remaining
 * window in `detail` so the caller knows it is a cooldown, not a new failure.
 */
const UNREACHABLE_COOLDOWN_MS = 120000

/**
 * V0.5.6: the sentence that tells the caller the prompt it just saw is still
 * answerable. Without it the model reads ACCOUNT_SELECTION_REQUIRED as "the
 * session is broken", reconnects, and only then reaches the real failure —
 * measured: one full SSH handshake + menu round trip plus a model round trip
 * (~40 s) spent on a PTY that was still waiting for the answer.
 */
const ACCOUNT_PROMPT_STAYS_LIVE =
  ' — the session stays live at the KoKo ID> prompt: call again with accountIndex to answer it (no reconnect needed)'

/**
 * V0.6.0: KoKo banners that mean "this account may not use this asset".
 *
 * Split out of the generic failure pattern on purpose. The three entry
 * failures need three different answers from the model:
 *   - the asset does not exist        → fix the name/IP
 *   - the asset exists, this account  → an administrator has to grant access;
 *     is not authorized for it          retrying (with another accountIndex,
 *                                       even) cannot help
 *   - the asset exists but is not      → wait / report, do not retry
 *     reachable from the bastion
 * Reporting all three as "enter timeout" made the model keep retrying against
 * an authorization wall.
 */
const ENTER_NOT_AUTHORIZED_PATTERN =
  /无权限|无此权限|权限不足|未授权|没有权限|不允许访问|拒绝访问|permission denied|not authorized|unauthorized|access denied|forbidden/i

/**
 * V0.6.0: KoKo banners that mean "there is no such asset".
 *
 * Deliberately does NOT match the network-level phrases — those belong to
 * {@link ENTER_UNREACHABLE_PATTERN}.
 */
const ENTER_NOT_FOUND_PATTERN =
  /未找到|不存在|没有该资产|无此资产|资产不存在|找不到|not found|no such (?:host|asset|machine)|unknown asset/i

/**
 * V0.6.0: KoKo connection banners that mention the asset it tried to reach.
 * Used for the target self-verification: the banner carries the asset's own
 * IP as the bastion saw it, which is a second, independent witness next to
 * the probe's `hostname -I`.
 */
const KOKO_TARGET_BANNER = /@([0-9]{1,3}(?:\.[0-9]{1,3}){3})/

/**
 * V0.5.5: the KoKo line that explains why an entry failed.
 *
 * Scans the tail for the last line carrying a failure MARKER rather than just
 * taking the last line — KoKo prints its prompt immediately BELOW the reason:
 *
 *   开始连接到 root(root)@10.0.0.10 error: 网络不通（连接超时）
 *   [Host]> _
 *
 * Pre-V0.5.5 the `detail` carried the regex MATCH ("error"), which told the
 * model nothing and is why it kept guessing arguments instead of reporting.
 */
function failureBanner(text: string, pattern: RegExp, max = 300): string {
  const lines = text.split('\n')
  let fallback = ''
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const flat = lines[i]!.replace(/[\s\u3000]{2,}/g, ' ').trim()
    if (flat.length === 0) continue
    if (fallback === '') fallback = flat
    if (flat.length <= max && pattern.test(flat)) return flat
  }
  return fallback.length > max ? fallback.slice(0, max) + '…' : fallback
}

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
  /**
   * V0.5.5 fail-fast cache: target -> "the bastion could not dial this asset
   * until <timestamp>, KoKo said <reason>". Deliberately NOT cleared on
   * reconnect: the gateway being re-established says nothing about the asset's
   * network path, which is the thing that actually failed.
   */
  private unreachable = new Map<string, { until: number; reason: string }>()
  /**
   * V0.5.6: set while the session is parked on KoKo's `ID>` account-selection
   * prompt — i.e. after ACCOUNT_SELECTION_REQUIRED, until the caller answers.
   *
   * The session deliberately STAYS LIVE there instead of collapsing to UNKNOWN.
   * Collapsing was meant to be fail-closed, but it broke the only way to answer:
   * `requireLiveSession()` / `ensureConnectedLocked()` refuse a non-live
   * session, so the very next call — the one carrying the `accountIndex` the
   * connector had just asked for — was rejected with CONNECTION_LOST. The
   * caller had no choice but to reconnect (fresh SSH handshake + fresh menu)
   * before it could answer a prompt on a PTY that was never dead.
   *
   * Real transcript (2026-09-14, console pid 36612), 3m56s for one dead asset:
   *
   *   enter(no session)     CONNECTION_LOST
   *   connect               ok
   *   enter                 ACCOUNT_SELECTION_REQUIRED   <- prompt raised
   *   enter(accountIndex=1) CONNECTION_LOST              <- answer refused
   *   connect               (reconnect, second SSH dial)
   *   enter(accountIndex=1) ASSET_UNREACHABLE            <- the real failure
   *
   * `pendingAccountChoice` removes the detour: the second call answers the
   * prompt that is already painted, and only then does KoKo dial the asset.
   *
   * Never auto-picked — only an explicit `accountIndex` answers this prompt.
   */
  private pendingAccountChoice: { target: string; accounts: string } | null = null

  currentTarget: string | null = null
  currentHostname: string | null = null
  currentUser: string | null = null
  currentPwd: string | null = null
  /**
   * V0.6.0: the asset's own IPv4 addresses, as reported by the last probe.
   * Used by the target self-verification and by the batch target binding.
   */
  currentIps: string[] = []
  /**
   * V0.6.0: true when the target self-verification positively confirmed that
   * the shell owns the requested asset. 'unverified' (no address evidence) is
   * NOT the same as 'verified' and must never be reported as such.
   */
  currentVerified = false
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

  /**
   * V0.5.6: true when this session is LIVE on KoKo's `ID>` prompt for `target`
   * and the caller is now supplying the `accountIndex` it asked for. Only then
   * may a caller skip the "must be at the menu" precondition: the target line
   * was already written, the numbered list is still painted, and the only byte
   * missing is the chosen ID.
   *
   * The live-session requirement is what fails closed — if KoKo timed the
   * selection out, the transport died, or the session moved on, this returns
   * false and the normal preconditions apply (reconnect and re-enter).
   */
  canResumeAccountSelection(target: string, accountIndex?: number): boolean {
    if (accountIndex === undefined) return false
    if (!this.parkedOnAccountPrompt(target)) return false
    if (this.wire === null || this.wireClosed) return false
    return looksLikeAccountSelection(this.detector.tailPreview(2048)).detected
  }

  /** V0.5.6: a previous call left this session waiting on KoKo's `ID>` prompt for `target`. */
  private parkedOnAccountPrompt(target: string): boolean {
    const pending = this.pendingAccountChoice
    return pending !== null && pending.target === target && this.stateValue === SessionState.ENTERING_ASSET
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

  /**
   * Enter a target asset through the JumpServer KoKo menu.
   *
   * @param target       Asset IP or name (must already exist on the menu).
   * @param accountIndex The account ID displayed by KoKo on the `ID>` selection
   *                    screen. Required only when the target has more than one
   *                    authorised bastion user — KoKo paints a numbered list
   *                    ending in `ID>` and waits. The value passed here is the
   *                    number shown on that screen (usually 1 or 2), NOT a
   *                    0-based array position. When omitted on a multi-user
   *                    asset this throws ACCOUNT_SELECTION_REQUIRED with the
   *                    parsed account list in `detail`. Single-user assets
   *                    auto-login and ignore this argument.
   * @param signal       Abort signal (the menu-loop polls every ~120ms).
   */
  async enter(target: string, accountIndex?: number, signal?: AbortSignal): Promise<void> {
    if (!TARGET_PATTERN.test(target)) {
      throw new JumpServerError('ASSET_NOT_FOUND', 'invalid target: ' + target)
    }
    if (accountIndex !== undefined && (!Number.isInteger(accountIndex) || accountIndex < 0)) {
      throw new JumpServerError('INVALID_ARGUMENT', 'accountIndex must be the non-negative integer shown by KoKo')
    }
    // V0.5.6: this call may be the ANSWER to a prompt we raised a moment ago.
    // Check that before the menu precondition — the session is not at the menu,
    // it is (truthfully) still mid-entry, sitting on KoKo's `ID>` prompt.
    if (this.parkedOnAccountPrompt(target)) {
      const sel = looksLikeAccountSelection(this.detector.tailPreview(2048))
      if (!sel.detected) {
        // The prompt that was on screen is gone: KoKo timed the selection out,
        // or the transport died underneath it. Nothing can be answered here, so
        // fail closed instead of typing an index into an unknown screen.
        this.pendingAccountChoice = null
        this.setState(this.wireClosed || this.wire === null ? SessionState.DISCONNECTED : SessionState.UNKNOWN)
        throw new JumpServerError(
          'ACCOUNT_SELECTION_EXPIRED',
          'the KoKo account-selection prompt for ' + target + ' is no longer on the session — reconnect and enter again',
        )
      }
      if (accountIndex === undefined) {
        throw new JumpServerError(
          'ACCOUNT_SELECTION_REQUIRED',
          'target ' + target + ' has ' + sel.options.length + ' accounts; pass accountIndex in jumpserver_enter/jumpserver_run/jumpserver_batch',
          'accounts=' + sel.preview.join(' | '),
        )
      }
    }
    // True only when the prompt is still painted on a LIVE session AND the
    // caller supplied the index — see canResumeAccountSelection().
    const resuming = this.canResumeAccountSelection(target, accountIndex)
    if (!resuming) {
      this.assertState(SessionState.JUMPSERVER_MENU, 'NOT_AT_MENU', 'enter(target) requires the JumpServer menu')
      // V0.5.5 fail-fast: a target the bastion could not dial seconds ago is
      // refused here, BEFORE any byte reaches the PTY. KoKo would otherwise
      // spend another ~15 s on the same dead dial and report the same banner,
      // which is exactly the loop that burned 2m53s of a real conversation.
      const cooldown = this.unreachable.get(target)
      if (cooldown !== undefined) {
        const remainingMs = cooldown.until - Date.now()
        if (remainingMs > 0) {
          throw new JumpServerError(
            'ASSET_UNREACHABLE',
            'asset ' + target + ' was unreachable from the bastion moments ago — not retried (fail-fast, no PTY write)',
            'koko=' + cooldown.reason + ' retryAfterMs=' + remainingMs,
          )
        }
        this.unreachable.delete(target)
      }
      this.currentTarget = target
      this.currentHostname = null
      this.currentUser = null
      this.currentPwd = null
      this.setState(SessionState.ENTERING_ASSET)
    }
    try {
      if (resuming) {
        // The list is still on screen and KoKo is still waiting: answer it in
        // place. Deliberately NO detector reset (it would wipe the rows we are
        // about to read) and no second target line (KoKo would read the IP as
        // the account ID).
        this.callbacks.onLog?.('answering the pending KoKo account prompt for ' + target + ' on the live session')
      } else {
        // V0.5.5: everything the enter loop concludes must come from THIS dial.
        // KoKo paints the failure banner just above its own prompt and we only
        // look 400 chars back, so a banner left over from a previous failed
        // attempt used to be re-matched against a perfectly healthy new one —
        // a false "failure" that is impossible to diagnose from the result.
        this.detector.reset()
        this.wire!.write(target + '\n')
        this.callbacks.onInput?.(target) // the user-visible target line
      }
      // KoKo dials the asset with a progress banner. There are four terminal
      // shapes the wait may resolve into:
      //   1. ASSET_SHELL prompt — success, probe next;
      //   2. multi-user `ID>` selection — write accountIndex, then keep waiting;
      //   3. a connection-failure banner — bail with the visible failure text;
      //   4. wire closed or deadline reached — bail with ASSET_ENTER_TIMEOUT.
      // accountChoiceWritten makes sure we only fire the index ONCE per enter,
      // even if KoKo redraws the list (or our detector briefly flickers).
      const deadline = Date.now() + this.cfg.enterAssetMs
      let shellSeen = false
      let failureText: string | undefined
      let accountChoiceWritten = accountIndex === undefined ? true : false
      for (;;) {
        const screen = this.detector.detect()
        if (screen === 'ASSET_SHELL') {
          shellSeen = true
          break
        }
        // Multi-username selection — detect before the failure pattern so we
        // never mistake a numbered "0) admin" row for a "failed" connection.
        if (!accountChoiceWritten) {
          const tail = this.detector.tailPreview(2048)
          const sel = looksLikeAccountSelection(tail)
          if (sel.detected) {
            if (accountIndex === undefined) {
              // Will not happen given the assignment above, but be explicit:
              // never auto-pick an account on the operator's behalf.
              this.pendingAccountChoice = { target, accounts: sel.preview.join(' | ') }
              throw new JumpServerError(
                'ACCOUNT_SELECTION_REQUIRED',
                'target ' + target + ' has ' + sel.options.length + ' accounts; pass accountIndex in jumpserver_enter/jumpserver_run/jumpserver_batch' + ACCOUNT_PROMPT_STAYS_LIVE,
                'accounts=' + sel.preview.join(' | '),
              )
            }
            const chosen = sel.options.find((o) => o.index === accountIndex)
            if (chosen === undefined) {
              this.pendingAccountChoice = { target, accounts: sel.preview.join(' | ') }
              throw new JumpServerError(
                'ACCOUNT_SELECTION_REQUIRED',
                'target ' + target + ' has ' + sel.options.length + ' accounts; accountIndex=' + accountIndex + ' is not one of the displayed IDs' + ACCOUNT_PROMPT_STAYS_LIVE,
                'accounts=' + sel.preview.join(' | ') + ' (requested accountIndex=' + accountIndex + ')',
              )
            }
            const line = String(chosen.index) + '\n'
            this.wire!.write(line)
            this.callbacks.onInput?.(String(chosen.index))
            accountChoiceWritten = true
            // KoKo needs a beat to repaint the shell banner — give it the
            // same 120ms cadence the rest of the loop uses, then re-detect.
            await sleep(120)
            continue
          }
        } else if (accountIndex === undefined) {
          // Caller did not supply accountIndex; if KoKo raises the selection
          // screen we MUST surface it rather than auto-pick.
          const tail = this.detector.tailPreview(2048)
          const sel = looksLikeAccountSelection(tail)
          if (sel.detected) {
            this.pendingAccountChoice = { target, accounts: sel.preview.join(' | ') }
            throw new JumpServerError(
              'ACCOUNT_SELECTION_REQUIRED',
              'target ' + target + ' has ' + sel.options.length + ' accounts; pass accountIndex in jumpserver_enter/jumpserver_run/jumpserver_batch' + ACCOUNT_PROMPT_STAYS_LIVE,
              'accounts=' + sel.preview.join(' | '),
            )
          }
        }
        const failureTail = this.detector.tailPreview(400)
        const failure = ENTER_FAILURE_PATTERN.exec(failureTail)
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
        // V0.5.5: the banner is a full SENTENCE ("开始连接到 root(root)@10.0.0.10
        // error: 网络不通（连接超时）"), not the regex token that happened to
        // match first. Reporting the token gave the model `detail: error` and
        // no way to tell a dead asset from a wrong accountIndex.
        const banner = failureBanner(this.detector.tailPreview(2000), ENTER_FAILURE_PATTERN) || failureText
        // V0.6.0: split the "enter failed" bucket into the three states that
        // need three DIFFERENT answers from the model. The order matters:
        // authorization and existence are checked BEFORE the network pattern,
        // because a banner can mention both ("无权限" + "连接失败").
        if (ENTER_NOT_AUTHORIZED_PATTERN.test(banner)) {
          throw new JumpServerError(
            'ASSET_NOT_AUTHORIZED',
            'asset ' + target + ' exists but this bastion account is not authorized to use it — an administrator has to grant access. Retrying (even with another accountIndex) cannot help.',
            'koko=' + banner,
          )
        }
        if (ENTER_NOT_FOUND_PATTERN.test(banner)) {
          throw new JumpServerError(
            'ASSET_NOT_FOUND',
            'asset ' + target + ' does not exist in this account\'s authorized asset list — check the name/IP.',
            'koko=' + banner,
          )
        }
        if (ENTER_UNREACHABLE_PATTERN.test(banner)) {
          this.unreachable.set(target, { until: Date.now() + UNREACHABLE_COOLDOWN_MS, reason: banner })
          throw new JumpServerError(
            'ASSET_UNREACHABLE',
            'asset ' + target + ' is unreachable from the bastion — KoKo reported a network-level failure. This is NOT a configuration, credential or accountIndex problem.',
            'koko=' + banner + ' retryAfterMs=' + UNREACHABLE_COOLDOWN_MS,
          )
        }
        throw new JumpServerError('ASSET_ENTER_TIMEOUT', 'asset connection reported failure while entering ' + target, 'koko=' + banner)
      }
      if (!shellSeen) {
        const tail = this.detector.tailPreview(2048)
        const sel = looksLikeAccountSelection(tail)
        // V0.6.0: the wait can also expire with an authorization / existence
        // banner on screen (the failure marker may sit outside the 400-char
        // window the loop scans). Classify it here too, so the model gets the
        // actionable code instead of a generic timeout.
        const banner = failureBanner(tail, ENTER_FAILURE_PATTERN)
        if (banner.length > 0 && ENTER_NOT_AUTHORIZED_PATTERN.test(banner)) {
          throw new JumpServerError(
            'ASSET_NOT_AUTHORIZED',
            'asset ' + target + ' exists but this bastion account is not authorized to use it — an administrator has to grant access. Retrying (even with another accountIndex) cannot help.',
            'koko=' + banner,
          )
        }
        if (banner.length > 0 && ENTER_NOT_FOUND_PATTERN.test(banner)) {
          throw new JumpServerError(
            'ASSET_NOT_FOUND',
            'asset ' + target + ' does not exist in this account\'s authorized asset list — check the name/IP.',
            'koko=' + banner,
          )
        }
        throw new JumpServerError(
          'ASSET_ENTER_TIMEOUT',
          'asset shell for ' + target + ' was not detected within the enter timeout',
          'detected=' + sel.detected + ' options=' + (sel.preview.join(' | ') || 'none') + ' tail=' + tail.slice(-500),
        )
      }
      const marker = randomHex(6)
      const probeScript = buildProbeScript(marker)
      // The probe script is connector-internal: it must NOT be recorded as a
      // user-visible input line. Its H=/U=/P= results arrive as output events
      // and are surfaced through onTarget (the terminal shows a target meta row).
      const run = await this.runOp(probeScript, PROBE_PREFIX + marker, this.cfg.probeMs, signal, probeMarkerPattern(marker))
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
      // V0.6.0: the target self-verification. Until now "a shell prompt
      // appeared" was accepted as proof that the shell IS the requested asset.
      // It is not — a batch that asked for 192.168.30.2 while the session was
      // still on 192.168.30.3 ran its commands on the WRONG machine and
      // reported success. The probe's own address list is the witness.
      const verification = verifyTargetIdentity({ target, hostname: info.hostname, ips: info.ips })
      if (verification.status === 'mismatch') {
        // Fail closed: the shell is provably a different asset. Do NOT run a
        // single command against it, and do not pretend the enter succeeded.
        this.currentHostname = info.hostname
        this.currentUser = info.user
        this.currentPwd = info.pwd
        this.setState(SessionState.UNKNOWN)
        throw new JumpServerError(
          'TARGET_VERIFICATION_FAILED',
          'the session is not on the requested asset ' + target + ' — ' + verification.reason + '. No command was executed against it.',
          'requested=' + target + ' observedIps=' + (verification.observedIps.join(',') || 'none') + ' hostname=' + (info.hostname ?? 'unknown'),
        )
      }
      this.currentHostname = info.hostname
      this.currentUser = info.user
      this.currentPwd = info.pwd
      this.currentIps = info.ips
      this.currentVerified = verification.status === 'verified'
      this.callbacks.onTarget?.(target, info.hostname, info.user, info.pwd)
      this.unreachable.delete(target)
      this.pendingAccountChoice = null
      this.setState(SessionState.ASSET_SHELL)
      this.touch()
    } catch (error) {
      this.recoverAfterFailedEnter()
      // V0.5.6: a prompt still painted stays answerable; on every other exit
      // the screen it referred to is gone, so the answer must go through a
      // fresh enter() (and that one reconnects if it has to).
      if (this.stateValue !== SessionState.ENTERING_ASSET) this.pendingAccountChoice = null
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
      const run = await this.runOp(script, DONE_PREFIX + marker, timeoutMs, options.signal, doneMarkerPattern(marker))
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
        output: cleanCommandOutput(run.text, marker, script),
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
    // V0.6.0: bounded backoff instead of a single shot.
    //
    // The pre-V0.6.0 code sent `exit` exactly once and turned a missed menu
    // confirmation into MENU_RETURN_FAILED + UNKNOWN — a deterministic
    // cross-target failure (measured: the FIRST switch to a new target always
    // failed, the identical retry always worked).
    //
    // Two facts drive the retry policy:
    //   1. `exit` is only safe to send while the screen still looks like the
    //      ASSET's shell. At the KoKo menu the same word disconnects the whole
    //      bastion session, so a blind retry would cost the gateway.
    //   2. KoKo repaints the menu as a bare navigation prompt (`[Host]> `) —
    //      the box-drawn menu is gone by then. `looksLikeMenu` needs a frame
    //      AND a numbered list, so the menu detector can miss a prompt-only
    //      screen and report a failure for a leave that actually succeeded.
    //      `looksLikeMenuPrompt` (last non-blank line) is the reliable check.
    const backoffs = [300, 800, 2000]
    for (let attempt = 0; attempt <= backoffs.length; attempt += 1) {
      this.wire!.write('exit\n')
      this.callbacks.onInput?.('exit')
      // The first attempt keeps the full leave budget (unchanged semantics);
      // the retries use a short slice — a lost exit reappears quickly, and a
      // stuck screen must not hold the queue for another full leave timeout.
      const waitMs = attempt === 0 ? this.cfg.leaveMs : Math.min(this.cfg.leaveMs, 3000)
      if (await this.waitForMenuReturn(waitMs, signal)) break
      // Still in the asset's own shell ⇒ the exit was lost; a resend is safe.
      if (!this.stillInAssetShell()) break
      if (attempt === backoffs.length) break
      await sleep(backoffs[attempt]!)
    }
    if (!this.atKoKoPrompt() && this.detector.detect() !== 'JUMPSERVER_MENU') {
      this.setState(SessionState.UNKNOWN)
      throw new JumpServerError(
        'MENU_RETURN_FAILED',
        'exit was sent but the JumpServer menu was not confirmed',
        'attempts=' + (backoffs.length + 1) + ' screen=' + (this.detector.detect() ?? 'unknown'),
      )
    }
    this.currentTarget = null
    this.currentHostname = null
    this.currentUser = null
    this.currentPwd = null
    this.setState(SessionState.JUMPSERVER_MENU)
    this.touch()
  }

  /**
   * V0.6.0: is the session sitting at a KoKo navigation prompt
   * (`[Host]> ` / `Opt> `)? This is the CONFIRMATION that a leave succeeded:
   * after `exit` KoKo repaints a bare prompt, not the framed menu, so the
   * menu detector alone reports false failures.
   */
  atKoKoPrompt(): boolean {
    return looksLikeMenuPrompt(this.detector.tailPreview(400))
  }

  /**
   * V0.6.0: does the screen still look like the ASSET's own shell? Only then
   * may another `exit` be sent — at the KoKo menu the same word would
   * disconnect the bastion session itself.
   */
  private stillInAssetShell(): boolean {
    return looksLikeShellPrompt(this.detector.tailPreview(600))
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
    // V0.5.5: an explicit close is the operator saying "start over" (the reason
    // they closed is usually that the network was just fixed), so the
    // unreachable cooldown must not outlive it. A plain reconnect() does NOT
    // clear it — re-establishing the gateway says nothing about the asset.
    this.unreachable.clear()
    // V0.5.6: same for a pending account prompt — the PTY it lived on is gone.
    this.pendingAccountChoice = null
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

  /**
   * V0.6.0: wait until the session is back at the KoKo menu.
   *
   * Accepts BOTH shapes of "we are at the menu": the framed menu the detector
   * recognises, and the bare navigation prompt (`[Host]> `) that KoKo leaves
   * behind after `exit`. The prompt-only shape is the common one and the
   * menu detector misses it (it wants a frame AND a numbered list), which is
   * exactly what made a successful leave look like a failure.
   */
  private async waitForMenuReturn(timeoutMs: number, signal?: AbortSignal): Promise<boolean> {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      if (this.detector.detect() === 'JUMPSERVER_MENU') return true
      if (this.atKoKoPrompt()) return true
      if (this.wireClosed || this.wire === null) return false
      if (signal?.aborted === true) throw new AbortRequestedError()
      if (Date.now() >= deadline) return false
      await sleep(80)
    }
  }

  /** Run one script and watch for its marker; bounded capture, cancellable. */
  private async runOp(
    script: string,
    marker: string,
    timeoutMs: number,
    signal?: AbortSignal,
    pattern?: RegExp,
  ): Promise<{ matched: boolean; closed: boolean; aborted: boolean; text: string; truncated: boolean }> {
    const wire = this.wire
    if (wire === null || this.wireClosed) return { matched: false, closed: true, aborted: false, text: '', truncated: false }
    const watcher = new MarkerWatcher(marker, MAX_OUTPUT_BYTES, pattern)
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

  /**
   * V0.5.5: leave the session in a state that is ACTUALLY true after a failed
   * asset entry.
   *
   * When KoKo cannot dial the asset it prints the reason and re-paints its own
   * menu prompt one line below, so the bastion session is intact and every
   * other asset is still one `enter()` away. Collapsing to UNKNOWN there was a
   * lie with a price: the next call needed a full reconnect (fresh SSH
   * handshake ~14 s + a fresh asset-list capture), and the model — seeing
   * `state: UNKNOWN` — had no way to know the difference between "dead
   * session" and "one bad asset". Real transcript: 8 enter/connect cycles,
   * 2m53s, all of it avoidable.
   *
   * The check is tail-anchored and positive (see looksLikeMenuPrompt), and it
   * deliberately does NOT accept an `ID>` prompt: answering that prompt with an
   * asset name would be read as an account choice. No prompt → UNKNOWN, as
   * before. A dead transport is DISCONNECTED, which is what it is.
   */
  private recoverAfterFailedEnter(): void {
    if (this.stateValue !== SessionState.ENTERING_ASSET) return
    if (this.wireClosed || this.wire === null) {
      this.setState(SessionState.DISCONNECTED)
      return
    }
    // V0.5.6: KoKo is waiting for an account ID on a LIVE session — we are
    // still mid-entry, only paused on a prompt, and the caller's next call can
    // answer it. Stay in ENTERING_ASSET so that call is allowed through.
    const accountTail = this.detector.tailPreview(2048)
    if (looksLikeAccountSelection(accountTail).detected) {
      if (this.currentTarget !== null && this.pendingAccountChoice === null) {
        this.pendingAccountChoice = {
          target: this.currentTarget,
          accounts: looksLikeAccountSelection(accountTail).preview.join(' | '),
        }
      }
      return
    }
    if (looksLikeMenuPrompt(this.detector.tailPreview(400))) {
      this.currentTarget = null
      this.currentHostname = null
      this.currentUser = null
      this.currentPwd = null
      this.setState(SessionState.JUMPSERVER_MENU)
      this.touch()
      return
    }
    this.setState(SessionState.UNKNOWN)
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
