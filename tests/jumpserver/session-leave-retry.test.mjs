/**
 * V0.6.0 (A-1): leaving an asset must be RELIABLE.
 *
 * The 泛微 OA rollout found the worst kind of bug: the first command against
 * the second target ALWAYS failed, and re-issuing the same call worked.
 * Root cause (session.ts): `leave()` sent `exit` ONCE and then waited for a
 * JUMPSERVER_MENU screen — but the KoKo menu detector needs a BOX + numbered
 * entries, while KoKo actually paints a bare `[Host]> ` prompt after `exit`.
 * A successful leave was therefore reported as MENU_RETURN_FAILED, and the
 * next target's enter failed with the session in UNKNOWN state.
 *
 * These tests pin the fixed behaviour:
 *   1. a bare `[Host]> ` prompt IS a confirmed menu return;
 *   2. `exit` is retried (bounded) while the screen still looks like the
 *      asset's own shell — sending `exit` at the KoKo menu would kill the
 *      whole bastion session;
 *   3. when no menu ever appears, the failure is reported with the attempts.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { JumpServerSession } from '../../lib/jumpserver/session.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
    /** How many `exit` writes before the menu finally appears. */
    this.exitAttemptsBeforeMenu = 1
    this.exitCount = 0
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
      return
    }
    if (text.trim() === 'exit') {
      this.exitCount += 1
      if (this.exitCount >= this.exitAttemptsBeforeMenu) {
        // KoKo paints a BARE prompt after exit — no box, no numbered entries.
        this._emit('\r\n[Host]> ')
      }
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
  '│  1) 输入 IP/主机名 进行搜索登录            │',
  '│  3) 输入 p 进行显示您有权限的资产          │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

const ASSET_SHELL_PROMPT = '\n[root@jsx-app-01 ~]# '

function buildSession() {
  const holder = { wire: null, log: [] }
  const session = new JumpServerSession(
    {
      host: '127.0.0.1', port: 22, username: 'u', password: 'p',
      connectTimeoutMs: 2000, enterAssetMs: 4000, probeMs: 2000,
      commandMs: 2000, leaveMs: 1500, listAssetsMs: 2000,
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

async function connectAndEnter() {
  const { session, holder } = buildSession()
  const connectP = session.connect()
  setTimeout(() => holder.wire._emit(MENU_SCREEN), 30)
  await connectP
  const enterP = session.enter('192.168.30.2')
  setTimeout(() => holder.wire._emit(ASSET_SHELL_PROMPT), 30)
  await enterP
  return { session, holder }
}

test('a bare [Host]> prompt after exit IS a confirmed menu return', async () => {
  const { session, holder } = await connectAndEnter()
  holder.wire.exitAttemptsBeforeMenu = 1
  await session.leave()
  assert.equal(session.state, SessionState.JUMPSERVER_MENU)
  assert.equal(holder.wire.exitCount, 1)
})

test('exit is retried while the screen still looks like the asset shell', async () => {
  const { session, holder } = await connectAndEnter()
  // The first two `exit` writes are swallowed (the PTY is busy); the third
  // one really returns to the menu.
  holder.wire.exitAttemptsBeforeMenu = 3
  await session.leave()
  assert.equal(session.state, SessionState.JUMPSERVER_MENU)
  assert.ok(holder.wire.exitCount >= 2, 'exit must be retried, not sent once')
})

test('a leave that never reaches the menu reports MENU_RETURN_FAILED with the attempt count', async () => {
  const { session, holder } = await connectAndEnter()
  holder.wire.exitAttemptsBeforeMenu = 99
  const error = await session.leave().then(() => null, (e) => e)
  assert.ok(error !== null, 'leave must reject when no menu appears')
  assert.equal(error.code, 'MENU_RETURN_FAILED')
  assert.ok(String(error.detail).includes('attempts='), error.detail)
  assert.equal(session.state, SessionState.UNKNOWN)
})
