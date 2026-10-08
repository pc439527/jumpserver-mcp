/**
 * V0.5.3: KoKo multi-username `ID>` selection screen.
 *
 * Some JumpServer assets have more than one authorised bastion user. Instead
 * of going straight to the asset shell, KoKo paints a numbered list of users
 * and waits at an `ID>` prompt for the caller to type an index.
 *
 * Pre-V0.5.3 the connector's enter() loop never matched that screen, so the
 * wait timed out with ASSET_ENTER_TIMEOUT — a misdiagnosis on the operator's
 * side ("it's not a timeout, you have to select the user"). These tests
 * drive a fake PTY and verify:
 *
 *   1. With `accountIndex` provided, enter() writes the index, then waits
 *      for the asset shell.
 *   2. Without `accountIndex`, enter() throws ACCOUNT_SELECTION_REQUIRED
 *      with the parsed user list in `detail` so the model can prompt the
 *      user and retry.
 *   3. On a normal single-user asset (no `ID>` prompt), the new code path is
 *      a no-op — single-user entries keep working exactly as before.
 *
 * V0.5.6 adds the part V0.5.3 got wrong: the RETRY has to land on the same
 * session. Collapsing to UNKNOWN after the prompt made the answer
 * undeliverable — `requireLiveSession()` refused the follow-up call with
 * CONNECTION_LOST, so the model had to reconnect before it could type the
 * account ID the connector had just asked for. Real transcript (2026-09-14,
 * console pid 36612): enter → ACCOUNT_SELECTION_REQUIRED →
 * enter(accountIndex=1) → CONNECTION_LOST → connect → enter → only THEN the
 * asset's actual failure. Tests 5-9 pin the resume path and its fail-closed
 * edges.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { JumpServerSession } from '../../lib/jumpserver/session.js'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { JumpServerError } from '../../lib/jumpserver/errors.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

/** Fake transport — deterministic PTY in JavaScript. */
class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
  }
  write(text) {
    this.written.push(text)
    // The probe script — KoKo never emits it directly, the connector
    // sends it AFTER the asset shell is up. Mirror the real test in
    // session-abort.test.mjs.
    const probeMatch = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (probeMatch !== null) {
      const marker = probeMatch[1]
      this._emit(
        '\n__DSH_JS_PROBE_' + marker + '\n' +
        'H=oa-nginx\n' +
        'U=root\n' +
        'P=/root\n' +
        '__DSH_JS_PROBE_END_' + marker + '\n' +
        '[root@oa-nginx ~]# ',
      )
      return
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
  '│  1) oa-nginx                              │',
  '│  2) oa-app                                │',
  '│  请输入资产名或编号：                       │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

// KoKo's "which user?" screen — the connector MUST recognize this BEFORE
// failing, and the model MUST pass accountIndex to answer it.
const ACCOUNT_SELECT_SCREEN_3 = [
  '[Host 192.168.138.56]',
  '[Users]',
  '0) admin (created 2023-12-01)',
  '1) ops (created 2023-12-01)',
  '2) deploy (created 2023-12-01)',
  '',
  'ID>',
].join('\n')

// Real KoKo layout observed on 2026-09-12: 1-based IDs with pipe-separated columns.
const ACCOUNT_SELECT_SCREEN_TABLE = [
  '[Host] 192.168.138.56',
  '提示：输入 [jsx-c138056-...] 的账号ID',
  'ID   | 名称     | 用户名',
  '-----|----------|----------',
  '1    | root     | root',
  '2    | 手动输入 | @INPUT',
  '',
  'ID>',
].join('\n')

const ASSET_SHELL_PROMPT = '\n[root@oa-nginx ~]# '

function buildSession() {
  /** Every transport the session opens, oldest first (a reconnect adds one). */
  const wires = []
  const session = new JumpServerSession(
    {
      host: '127.0.0.1', port: 22, username: 'u', password: 'p',
      connectTimeoutMs: 2000, enterAssetMs: 4000, probeMs: 2000,
      commandMs: 2000, leaveMs: 2000, listAssetsMs: 2000,
      wireFactory: () => {
        const wire = new FakeWire()
        wires.push(wire)
        return Promise.resolve(wire)
      },
    },
    { onLog: () => undefined },
  )
  return {
    session,
    wires,
    /** The transport the session is on right now (newest). */
    get wire() { return wires[wires.length - 1] },
  }
}

async function connectAtMenu() {
  const holder = buildSession()
  const connectP = holder.session.connect()
  setTimeout(() => holder.wire._emit(MENU_SCREEN), 30)
  await connectP
  return holder
}

test('enter() with accountIndex writes the index, then waits for the asset shell', async () => {
  const { session, wire } = await connectAtMenu()
  // 1. Caller enters the target.
  const enterP = session.enter('192.168.138.56', 1)
  // 2. KoKo replies with the ID> prompt instead of the shell.
  setTimeout(() => wire._emit(ACCOUNT_SELECT_SCREEN_3), 30)
  // 3. After the connector writes "1\n", KoKo dials the asset and lands the shell.
  setTimeout(() => wire._emit(ASSET_SHELL_PROMPT), 200)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
  // The wire must record BOTH the target line AND the chosen index, in that order.
  const userInputs = wire.written.filter((s) => s.endsWith('\n') || s === '\u0003')
  assert.ok(userInputs.includes('192.168.138.56\n'), 'the target line was not written')
  assert.ok(userInputs.includes('1\n'), 'the accountIndex 1 was not written to the wire')
  // The connector MUST NOT have written any other digit.
  const digits = userInputs.filter((s) => /^[0-9]+\n$/.test(s))
  assert.deepEqual(digits, ['1\n'], 'unexpected extra numeric writes: ' + digits.join(','))
})

test('enter() with accountIndex on the 1-based table screen writes the displayed ID', async () => {
  const { session, wire } = await connectAtMenu()
  const enterP = session.enter('192.168.138.56', 1)
  setTimeout(() => wire._emit(ACCOUNT_SELECT_SCREEN_TABLE), 30)
  setTimeout(() => wire._emit(ASSET_SHELL_PROMPT), 200)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
  const userInputs = wire.written.filter((s) => s.endsWith('\n') || s === '\u0003')
  assert.ok(userInputs.includes('192.168.138.56\n'), 'the target line was not written')
  // accountIndex=1 must map to the displayed ID 1, even though it is the first row.
  assert.ok(userInputs.includes('1\n'), 'the displayed account ID 1 was not written')
  const digits = userInputs.filter((s) => /^[0-9]+\n$/.test(s))
  assert.deepEqual(digits, ['1\n'], 'unexpected extra numeric writes')
})

test('enter() without accountIndex throws ACCOUNT_SELECTION_REQUIRED with the parsed list', async () => {
  const { session, wire } = await connectAtMenu()
  const enterP = session.enter('192.168.138.56')
  // KoKo shows the selection screen. The connector MUST surface it instead
  // of waiting the full enter timeout out.
  setTimeout(() => wire._emit(ACCOUNT_SELECT_SCREEN_3), 30)
  await assert.rejects(enterP, (err) => {
    assert.ok(err instanceof JumpServerError, 'expected JumpServerError, got ' + err?.constructor?.name)
    assert.equal(err.code, 'ACCOUNT_SELECTION_REQUIRED')
    assert.ok(typeof err.detail === 'string', 'detail must carry the parsed list')
    // The detail lists every option so the model can pass the right index
    // without re-querying the bastion.
    assert.ok(err.detail.includes('0) admin'), 'detail missing 0) admin: ' + err.detail)
    assert.ok(err.detail.includes('1) ops'), 'detail missing 1) ops: ' + err.detail)
    assert.ok(err.detail.includes('2) deploy'), 'detail missing 2) deploy: ' + err.detail)
    assert.ok(err.detail.startsWith('accounts='), 'detail format must be accounts=...: ' + err.detail)
    return true
  })
  // V0.5.6: the session stays LIVE (ENTERING_ASSET), parked on KoKo's prompt.
  // It must NOT collapse to UNKNOWN: the answer the connector just asked for
  // has to be deliverable on THIS PTY (see the file header).
  assert.equal(session.state, SessionState.ENTERING_ASSET)
  assert.equal(session.canResumeAccountSelection('192.168.138.56', 1), true)
  // ...but only with an explicit index, and only for the target that asked.
  assert.equal(session.canResumeAccountSelection('192.168.138.56'), false)
  assert.equal(session.canResumeAccountSelection('192.168.78.51', 1), false)
  // The connector MUST NOT have written any digit (it didn't auto-pick).
  const digits = wire.written.filter((s) => /^[0-9]+\n$/.test(s))
  assert.deepEqual(digits, [], 'the connector auto-picked despite the missing accountIndex: ' + digits.join(','))
})

test('enter() with an out-of-range accountIndex throws ACCOUNT_SELECTION_REQUIRED naming the bad choice', async () => {
  const { session, wire } = await connectAtMenu()
  const enterP = session.enter('192.168.138.56', 9)
  setTimeout(() => wire._emit(ACCOUNT_SELECT_SCREEN_3), 30)
  await assert.rejects(enterP, (err) => {
    assert.ok(err instanceof JumpServerError)
    // Bad index is a model-side mistake; surface the parsed list so the
    // model can retry with a valid one.
    assert.equal(err.code, 'ACCOUNT_SELECTION_REQUIRED')
    assert.ok(err.detail.includes('0) admin') && err.detail.includes('requested accountIndex=9'))
    return true
  })
  const digits = wire.written.filter((s) => /^[0-9]+\n$/.test(s))
  assert.deepEqual(digits, [], 'a bad accountIndex must NOT be echoed to the wire')
})

test('enter() with a negative or non-integer accountIndex refuses at the API boundary', async () => {
  const { session } = await connectAtMenu()
  await assert.rejects(session.enter('192.168.138.56', -1), (err) => {
    assert.equal(err.code, 'INVALID_ARGUMENT')
    return true
  })
  await assert.rejects(session.enter('192.168.138.56', 1.5), (err) => {
    assert.equal(err.code, 'INVALID_ARGUMENT')
    return true
  })
})

test('enter() with accountIndex but no ID> screen (single-user asset) is a no-op', async () => {
  const { session, wire } = await connectAtMenu()
  // Single-user asset: target -> shell directly, no ID> screen.
  const enterP = session.enter('192.168.78.51', 0)
  setTimeout(() => wire._emit(ASSET_SHELL_PROMPT), 30)
  await enterP
  assert.equal(session.state, SessionState.ASSET_SHELL)
  // Only the target line was written — accountIndex was a no-op (the screen
  // never asked for it).
  const digits = wire.written.filter((s) => /^[0-9]+\n$/.test(s))
  assert.deepEqual(digits, [], 'accountIndex leaked into the wire on a single-user asset: ' + digits.join(','))
})

/* ------------------------------------------------------------------ *
 * V0.5.6: answering the prompt must land on the SAME live session.
 * ------------------------------------------------------------------ */

test('the ACCOUNT_SELECTION_REQUIRED answer lands on the same PTY — no reconnect', async () => {
  const holder = await connectAtMenu()
  const ask = holder.session.enter('192.168.138.56')
  setTimeout(() => holder.wire._emit(ACCOUNT_SELECT_SCREEN_TABLE), 30)
  const first = await ask.then(() => null, (e) => e)
  assert.equal(first.code, 'ACCOUNT_SELECTION_REQUIRED')
  assert.match(first.message, /stays live at the KoKo ID> prompt/, first.message)
  assert.equal(holder.wires.length, 1, 'raising the prompt must not cost a reconnect')

  const answer = holder.session.enter('192.168.138.56', 1)
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 80)
  await answer
  assert.equal(holder.session.state, SessionState.ASSET_SHELL)
  // One SSH transport for the whole exchange...
  assert.equal(holder.wires.length, 1, 'answering the prompt opened a second transport')
  // ...one target line (the answer must not look like a fresh dial)...
  const targetLines = holder.wire.written.filter((s) => s === '192.168.138.56\n')
  assert.equal(targetLines.length, 1, 'the target line was written twice: ' + JSON.stringify(holder.wire.written))
  // ...and exactly the displayed ID.
  const digits = holder.wire.written.filter((s) => /^[0-9]+\n$/.test(s))
  assert.deepEqual(digits, ['1\n'])
})

test('an out-of-range accountIndex leaves the prompt answerable', async () => {
  const holder = await connectAtMenu()
  const bad = holder.session.enter('192.168.138.56', 9)
  setTimeout(() => holder.wire._emit(ACCOUNT_SELECT_SCREEN_TABLE), 30)
  const err = await bad.then(() => null, (e) => e)
  assert.equal(err.code, 'ACCOUNT_SELECTION_REQUIRED')
  assert.ok(err.detail.includes('requested accountIndex=9'), err.detail)
  assert.equal(holder.session.state, SessionState.ENTERING_ASSET)

  const good = holder.session.enter('192.168.138.56', 1)
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 80)
  await good
  assert.equal(holder.session.state, SessionState.ASSET_SHELL)
  assert.deepEqual(
    holder.wire.written.filter((s) => /^[0-9]+\n$/.test(s)),
    ['1\n'],
    'a rejected index must never reach the wire',
  )
})

test('a repeat call without accountIndex re-raises the selection, not NOT_AT_MENU', async () => {
  const holder = await connectAtMenu()
  const first = holder.session.enter('192.168.138.56')
  setTimeout(() => holder.wire._emit(ACCOUNT_SELECT_SCREEN_TABLE), 30)
  await first.then(() => null, () => null)

  const second = await holder.session.enter('192.168.138.56').then(() => null, (e) => e)
  assert.equal(second.code, 'ACCOUNT_SELECTION_REQUIRED')
  assert.ok(second.detail.includes('1) root'), second.detail)
  assert.equal(holder.wires.length, 1, 're-raising the prompt must not reconnect')
})

test('resuming is refused when the prompt is gone (fail-closed)', async () => {
  const holder = await connectAtMenu()
  const first = holder.session.enter('192.168.138.56')
  setTimeout(() => holder.wire._emit(ACCOUNT_SELECT_SCREEN_TABLE), 30)
  await first.then(() => null, () => null)
  assert.equal(holder.session.canResumeAccountSelection('192.168.138.56', 1), true)

  // KoKo gives the selection up and repaints its asset prompt; 2.2 KiB of new
  // output pushes the old `ID>` screen out of the 2048-char window the
  // detector looks at (the same window a real terminal scroll would move).
  holder.wire._emit('\n' + 'y'.repeat(2200) + '\n[Host]> ')
  assert.equal(holder.session.canResumeAccountSelection('192.168.138.56', 1), false)
  const err = await holder.session.enter('192.168.138.56', 1).then(() => null, (e) => e)
  assert.equal(err.code, 'ACCOUNT_SELECTION_EXPIRED')
  assert.equal(holder.session.state, SessionState.UNKNOWN, 'an expired prompt must not stay resumable')
  assert.deepEqual(
    holder.wire.written.filter((s) => /^[0-9]+\n$/.test(s)),
    [],
    'nothing may be typed into a screen we no longer recognize',
  )
})

test('close() drops the parked prompt (the operator escape hatch)', async () => {
  const holder = await connectAtMenu()
  const first = holder.session.enter('192.168.138.56')
  setTimeout(() => holder.wire._emit(ACCOUNT_SELECT_SCREEN_TABLE), 30)
  await first.then(() => null, () => null)
  await holder.session.close()
  assert.equal(holder.session.canResumeAccountSelection('192.168.138.56', 1), false)
})

/* ------------------------------------------------------------------ *
 * Manager level — the path the MCP tools actually take (V0.5.6).
 *
 * Session-level green is not enough: `navigateToTarget` had its own
 * fail-closed guards, and those are what answered the caller's accountIndex
 * with NOT_AT_MENU / CONNECTION_LOST.
 * ------------------------------------------------------------------ */

const TARGET = '192.168.138.56'

/** Answers the connector's protocol AND the KoKo dial like a real PTY. */
class SelectionWire extends FakeWire {
  write(text) {
    const done = /__DSH_JS_DONE_([0-9a-fA-F]+)/.exec(text)
    if (done !== null) {
      this.written.push(text)
      this._emit('__DSH_JS_DONE_' + done[1] + ':0\n[root@oa-nginx ~]# ')
      return
    }
    if (/__DSH_JS_PROBE_/.test(text)) {
      super.write(text) // base class answers the probe
      return
    }
    if (new RegExp('^' + TARGET.replace(/\./g, '\\.') + '\\n$').test(text)) {
      this.written.push(text)
      setTimeout(() => this._emit(ACCOUNT_SELECT_SCREEN_TABLE), 10)
      return
    }
    if (/^[0-9]+\n$/.test(text)) {
      this.written.push(text)
      setTimeout(() => this._emit(ASSET_SHELL_PROMPT), 10)
      return
    }
    super.write(text)
  }
}

function makeManager(makeWire) {
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
    wireFactory: async () => makeWire(),
  })
}

test('manager: the account answer completes the navigation on the SAME transport', async () => {
  let transports = 0
  const wire = new SelectionWire()
  const manager = makeManager(() => { transports += 1; return wire })
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP

  // 1st attempt: no accountIndex -> the prompt is surfaced, with the list.
  const asked = await manager.runTargetBatch({ target: TARGET, commands: [{ command: 'uptime', risk: 'READ', timeoutMs: 800 }] })
  assert.equal(asked.error?.code, 'ACCOUNT_SELECTION_REQUIRED')
  assert.ok(asked.error.detail.includes('1) root'), 'the batch failure must carry the parsed list: ' + asked.error.detail)
  assert.deepEqual(asked.commands, [], 'nothing may run while the account is unanswered')

  // 2nd attempt: the answer. It must not dial the bastion again.
  const answered = await manager.runTargetBatch({ target: TARGET, accountIndex: 1, commands: [{ command: 'uptime', risk: 'READ', timeoutMs: 800 }] })
  assert.equal(answered.error, null, JSON.stringify(answered.error))
  assert.equal(answered.commands[0]?.commandStatus, 'SUCCESS')
  assert.equal(transports, 1, 'answering the prompt must not open a second SSH transport')
  assert.deepEqual(wire.written.filter((s) => /^[0-9]+\n$/.test(s)), ['1\n'])
})