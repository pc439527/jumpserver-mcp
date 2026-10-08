/**
 * V0.5.5: an asset the bastion cannot dial must STOP the caller, not spin it.
 *
 * Captured from a live conversation on 2026-09-14 (console pid 17584). One
 * `jumpserver_enter` on 192.168.138.56 produced, 15.1 s later:
 *
 *   开始连接到 root(root)@192.168.138.56  0.0 … 14.4
 *   开始连接到 root(root)@192.168.138.56 error: 网络不通（连接超时）
 *   [Host]>
 *
 * and the connector answered `ASSET_ENTER_TIMEOUT` with `detail: error` — the
 * REGEX MATCH, not the banner. The model could not tell a dead network from a
 * wrong `accountIndex`, and the session had collapsed to UNKNOWN, so every
 * retry needed a full reconnect. Total cost: 8 enter/connect cycles, 2m53s.
 *
 * These tests pin the four things that make the loop stop:
 *   1. the KoKo banner is classified ASSET_UNREACHABLE and reported in FULL;
 *   2. the session stays at the (real) KoKo menu — no reconnect is needed;
 *   3. a repeat enter on the same target is refused with NO PTY write;
 *   4. the refusal is per-target, and other assets keep working.
 *
 * The last test widens the blast radius to the fleet level: one dead host in a
 * survey must not take the other hosts down with it. It used to — the collapsed
 * state made the NEXT target fail with `UNKNOWN_STATE`, so a survey of ten hosts
 * stopped at the first unreachable one.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { JumpServerSession } from '../../lib/jumpserver/session.js'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'
import { looksLikeMenuPrompt } from '../../lib/jumpserver/detector.js'
import { renderResult } from '../../lib/runtime/tools-common.js'

/** Fake transport — deterministic PTY in JavaScript (mirrors session-account-selection.test.mjs). */
class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
  }
  write(text) {
    this.written.push(text)
    const probeMatch = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (probeMatch !== null) {
      const marker = probeMatch[1]
      this._emit(
        '\n__DSH_JS_PROBE_' + marker + '\n' +
        'H=jsx-app-01\n' +
        'U=root\n' +
        'P=/root\n' +
        '__DSH_JS_PROBE_END_' + marker + '\n' +
        '[root@jsx-app-01 ~]# ',
      )
    }
  }
  onData(cb) { this.cbs.push(cb) }
  onError() {}
  onClose(cb) { this.closeCbs.push(cb) }
  close() {
    if (this.closed) return
    this.closed = true
    for (const cb of this.closeCbs) cb()
  }
  _emit(text) { for (const cb of this.cbs) cb(text) }
}

const MENU_SCREEN = [
  '┌──────────────────────────────────────────┐',
  '│  JumpServer · 堡垒机 / KoKo 终端          │',
  '│  1) 输入 IP/主机名 进行搜索登录            │',
  '│  3) 输入 p 进行显示您有权限的资产          │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

/**
 * The real failure shape, byte-for-byte in structure: the banner, then KoKo's
 * own asset-list prompt on the next line. The `\b` progress ticks are how the
 * PTY actually paints the counter (one chunk per tick, backspaces in between).
 */
const UNREACHABLE_SCREEN = [
  '192.168.138.56\r\n',
  '开始连接到 root(root)@192.168.138.56  0.0',
  '\b\b\b0.1',
  '\b\b\b0.2',
  '\r\n',
  '开始连接到 root(root)@192.168.138.56 error: 网络不通（连接超时）',
  '\r\n',
  '[Host]> ',
].join('')

const ASSET_SHELL_PROMPT = '\n[root@jsx-app-01 ~]# '

const UNREACHABLE = '192.168.138.56'
const REACHABLE = '192.168.138.57'

function buildSession() {
  /** Every transport the session opens, newest last (reconnects build a new one). */
  const holder = { wire: null, log: [] }
  const session = new JumpServerSession(
    {
      host: '127.0.0.1', port: 22, username: 'u', password: 'p',
      connectTimeoutMs: 2000, enterAssetMs: 4000, probeMs: 2000,
      commandMs: 2000, leaveMs: 2000, listAssetsMs: 2000,
      wireFactory: () => {
        const wire = new FakeWire()
        holder.wire = wire
        return Promise.resolve(wire)
      },
    },
    { onLog: (line) => holder.log.push(line) },
  )
  return { session, holder }
}

async function connectAtMenu() {
  const { session, holder } = buildSession()
  const connectP = session.connect()
  setTimeout(() => holder.wire._emit(MENU_SCREEN), 30)
  await connectP
  return { session, holder }
}

/** Drive one failing enter and return (session, holder, error). */
async function failOnce() {
  const { session, holder } = await connectAtMenu()
  const enterP = session.enter(UNREACHABLE)
  setTimeout(() => holder.wire._emit(UNREACHABLE_SCREEN), 30)
  const error = await enterP.then(() => null, (e) => e)
  assert.ok(error !== null, 'enter() on an unreachable asset must reject')
  return { session, holder, error }
}

test('a KoKo 网络不通 banner is ASSET_UNREACHABLE, not ASSET_ENTER_TIMEOUT', async () => {
  const { error } = await failOnce()
  assert.equal(error.code, 'ASSET_UNREACHABLE')
})

test('the reported detail is the WHOLE banner, not the first regex token', async () => {
  const { error } = await failOnce()
  // Pre-V0.5.5 this was literally `detail: error`.
  assert.ok(error.detail.includes('网络不通'), 'detail must carry the KoKo reason: ' + error.detail)
  assert.ok(
    error.detail.includes('开始连接到 root(root)@192.168.138.56'),
    'detail must carry the full banner line: ' + error.detail,
  )
  assert.ok(/retryAfterMs=\d+/.test(error.detail), 'detail must state the cooldown: ' + error.detail)
})

test('the message tells the caller this is not a parameter problem', async () => {
  const { error } = await failOnce()
  assert.match(error.message, /unreachable/i)
  assert.match(error.message, /NOT a configuration, credential or accountIndex problem/i)
})

test('after the failure the session is back AT the menu — no reconnect needed', async () => {
  const { session, holder } = await failOnce()
  assert.equal(session.state, SessionState.JUMPSERVER_MENU)
  assert.equal(session.currentTarget, null, 'a target that was never entered must not be reported as current')
  // And it is genuinely usable: another asset enters with the same session.
  const enterP = session.enter(REACHABLE)
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 30)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
  assert.equal(session.currentTarget, REACHABLE)
})

test('a repeat enter on the same target is refused with NO PTY write', async () => {
  const { session, holder, error } = await failOnce()
  const writesBefore = holder.wire.written.length
  assert.ok(writesBefore > 0)
  const started = Date.now()
  const second = await session.enter(UNREACHABLE).then(() => null, (e) => e)
  const elapsed = Date.now() - started
  assert.equal(second.code, 'ASSET_UNREACHABLE')
  assert.match(second.message, /fail-fast, no PTY write/)
  assert.equal(holder.wire.written.length, writesBefore, 'fail-fast must not touch the PTY')
  assert.ok(elapsed < 250, 'fail-fast must be immediate, took ' + elapsed + 'ms')
  // The cooldown is the same window, restated so the caller can wait it out.
  assert.ok(Number(/retryAfterMs=(\d+)/.exec(second.detail)?.[1]) > 0)
  // ...and the original reason survives the refusal.
  assert.ok(second.detail.includes('网络不通'), second.detail)
  assert.equal(error.code, second.code)
})

test('the cooldown clears on an explicit close (the operator escape hatch)', async () => {
  const { session, holder } = await failOnce()
  await session.close()
  const connectP = session.connect()
  setTimeout(() => holder.wire._emit(MENU_SCREEN), 30)
  await connectP
  // Same target, minutes of cooldown left — but the operator asked to start
  // over, so the connector must actually try again.
  const enterP = session.enter(UNREACHABLE)
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 30)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
})

test('a stale failure banner from a previous attempt is not re-matched', async () => {
  const { session, holder } = await failOnce()
  // The tail still holds `网络不通（连接超时）` from the failed attempt. A fresh
  // enter on another asset must NOT read it as its own failure.
  const enterP = session.enter(REACHABLE)
  setTimeout(() => holder.wire._emit('[root@jsx-app-01 ~]# '), 60)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
})

test('the cooldown is per-target: a reachable asset is not collateral damage', async () => {
  const { session, holder } = await failOnce()
  const enterP = session.enter(REACHABLE)
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 30)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
})

test('a non-network enter failure stays retryable (ASSET_ENTER_TIMEOUT)', async () => {
  const { session, holder } = await connectAtMenu()
  const enterP = session.enter(UNREACHABLE)
  setTimeout(() => holder.wire._emit('开始连接到 root(root)@192.168.138.56 error: 资产不存在\r\n[Host]> '), 30)
  const error = await enterP.then(() => null, (e) => e)
  assert.ok(error !== null)
  assert.equal(error.code, 'ASSET_ENTER_TIMEOUT', 'a fixable failure must not be reported as unreachable')
  assert.ok(error.detail.includes('资产不存在'), error.detail)
  // ...and it must not poison the target for the next attempt.
  const retry = session.enter(UNREACHABLE)
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 30)
  await retry
  assert.equal(session.state, SessionState.ASSET_SHELL)
})

test('looksLikeMenuPrompt accepts the two navigation prompts only', () => {
  // Real prompts seen in the captured session.
  assert.equal(looksLikeMenuPrompt('开始连接到 root(root)@10.0.0.10 error: 网络不通（连接超时）\r\n[Host]> '), true)
  assert.equal(looksLikeMenuPrompt('...\r\nOpt> '), true)
  assert.equal(looksLikeMenuPrompt('...\r\n[jsx-node-01]> '), true)
  // `ID>` waits for an ACCOUNT choice — writing an asset name there would be
  // read as a choice, so it must never be treated as navigable.
  assert.equal(looksLikeMenuPrompt('[Host] 10.0.0.10\r\n1    | root     | root\r\n2    | 手动输入 | @INPUT\r\nID> '), false)
  // Stale menu text higher in the window must not outvote a live non-prompt line.
  assert.equal(looksLikeMenuPrompt('│  1) 输入 IP/主机名  │\r\n└──────┘\r\nOpt> \r\n开始连接到 root(root)@10.0.0.10  3.4'), false)
  assert.equal(looksLikeMenuPrompt(''), false)
})

test('renderResult prints the STOP line for ASSET_UNREACHABLE only', () => {
  const unreachable = renderResult({ ok: false, code: 'ASSET_UNREACHABLE', message: 'asset X is unreachable from the bastion' })
  assert.match(unreachable, /next: STOP/)
  assert.match(unreachable, /Do NOT retry/)
  // A fixable failure must NOT tell the model to give up.
  const fixable = renderResult({ ok: false, code: 'ACCOUNT_SELECTION_REQUIRED', message: 'pass accountIndex' })
  assert.doesNotMatch(fixable, /next: STOP/)
  assert.doesNotMatch(renderResult({ ok: false, code: 'ASSET_ENTER_TIMEOUT', message: 'no shell' }), /next: STOP/)
})

/* ------------------------------------------------------------------ *
 * Fleet level: the manager, not just the session.
 * ------------------------------------------------------------------ */

/**
 * Wire that answers the connector's own protocol (probe / done / exit) AND —
 * crucially — answers a TARGET LINE like a real PTY does.
 *
 * The pre-timer version of this test emitted the banner 30 ms after starting
 * the tool call. That is wrong: `runTargetBatch` leaves the previous asset
 * first, so the banner could land BEFORE the target line was written, and the
 * enter loop's own `detector.reset()` (V0.5.5: only judge THIS dial) then wiped
 * it. A green test with a wiped banner is worse than no test.
 */
class FleetWire extends FakeWire {
  write(text) {
    // leave() sends exactly one 'exit' and waits for the menu again.
    if (text === 'exit\n') {
      this.written.push(text)
      setTimeout(() => this._emit(MENU_SCREEN), 10)
      return
    }
    const done = /__DSH_JS_DONE_([0-9a-fA-F]+)/.exec(text)
    if (done !== null) {
      this.written.push(text)
      this._emit('__DSH_JS_DONE_' + done[1] + ':0\n[root@jsx-app-01 ~]# ')
      return
    }
    const dial = /^(10\.0\.0\.\d+)\n$/.exec(text)
    if (dial !== null) {
      setTimeout(() => this._emit(dial[1] === '10.0.0.2' ? UNREACHABLE_SCREEN : ASSET_SHELL_PROMPT), 10)
    }
    super.write(text)
  }
}

function makeManager(wire) {
  return new SessionManager({
    getConfig: () => ({
      enabled: true,
      host: '127.0.0.1',
      port: 22,
      username: 'u',
      connectTimeout: 5,
      commandTimeout: 5,
      assetCacheTtlSeconds: 60,
      idleTimeout: 30,
      listAssets: false,
      batchConcurrency: 1,
      maxSessions: 1,
      permissionMode: 'AUTO',
    }),
    resolvePassword: async () => 'p',
    onAudit: async () => undefined,
    onLog: () => undefined,
    wireFactory: async () => wire,
  })
}

test('one unreachable host does not abort the rest of a survey', async () => {
  const wire = new FleetWire()
  const manager = makeManager(wire)
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP

  const hosts = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
  const results = []
  for (const target of hosts) {
    results.push(await manager.runTargetBatch({ target, commands: [{ command: 'uptime', risk: 'READ', timeoutMs: 800 }] }))
  }

  // Host 1 and 3 are unaffected — pre-V0.5.5 both died with UNKNOWN_STATE.
  assert.equal(results[0].error, null)
  assert.equal(results[0].commands[0]?.commandStatus, 'SUCCESS')
  assert.equal(results[2].error, null)
  assert.equal(results[2].commands[0]?.commandStatus, 'SUCCESS')
  // Host 2 reports the failure ONCE, WITH THE BANNER (V0.5.5: errorDetail used
  // to drop `detail`, so a batch caller saw a bare code and no reason), and
  // runs nothing.
  assert.equal(results[1].error?.code, 'ASSET_UNREACHABLE')
  assert.ok(results[1].error.message.includes('unreachable from the bastion'), results[1].error.message)
  assert.ok(results[1].error.detail.includes('网络不通'), 'batch-level detail must carry the banner: ' + results[1].error.detail)
  assert.deepEqual(results[1].commands, [])
  // The host stays usable-as-reported: the target is NOT left half-entered.
  assert.equal(manager.status().state, SessionState.ASSET_SHELL)
  assert.equal(manager.status().target, '10.0.0.3')
})
