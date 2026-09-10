/**
 * Session abort contract (V0.4.0 P0):
 *   when the MCP request is aborted mid-command the remote shell MUST receive
 *   Ctrl+C and the shell MUST be re-verified; the connector never declares the
 *   asset usable blindly. Also covers the out-of-band interrupt() path that
 *   the jumpserver_interrupt tool / console button rely on.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { JumpServerSession } from '../../lib/jumpserver/session.js'
import { AbortRequestedError } from '../../lib/jumpserver/errors.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

/** Fake transport: deterministic PTY in JavaScript. */
class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
  }
  write(text) {
    this.written.push(text)
    if (text === '\u0003') {
      // Simulate the remote shell recovering: prompt is back, ready for the probe.
      this._emit('\n[root@oa-nginx ~]# ')
      return
    }
    // Probe script -> answer H=/U=/P= in the same format the connector expects.
    // Math.random().toString(16) returns UPPERCASE hex on Node 22, so the marker
    // is matched case-insensitively.
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
    // Done script (for the command itself) -> do NOT respond: the test will
    // abort the command before it completes.
  }
  onData(cb) { this.cbs.push(cb) }
  onError() {}
  onClose(cb) { this.closeCbs.push(cb) }
  close() {
    if (this.closed) return
    this.closed = true
    // A real Wire.close() fires its onClose listeners so the session can
    // flip into the DISCONNECTED state; mirror that.
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

function buildSession() {
  const wire = new FakeWire()
  return {
    session: new JumpServerSession(
      {
        host: '127.0.0.1', port: 22, username: 'u', password: 'p',
        connectTimeoutMs: 2000, enterAssetMs: 2000, probeMs: 2000,
        commandMs: 2000, leaveMs: 2000, listAssetsMs: 2000,
        wireFactory: () => Promise.resolve(wire),
      },
      { onLog: () => undefined },
    ),
    wire,
  }
}

async function connectAndEnter() {
  const { session, wire } = buildSession()
  // Drive the session: after connect, wait for the fake wire to push the menu.
  const connectP = session.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  const enterP = session.enter('192.168.79.99')
  setTimeout(() => wire._emit('\n[root@oa-nginx ~]# '), 30)
  await enterP
  return { session, wire }
}

test('abort mid-command sends Ctrl+C, re-verifies the shell, then throws AbortRequestedError', async () => {
  const { session, wire } = await connectAndEnter()
  assert.equal(session.state, SessionState.ASSET_SHELL)

  const controller = new AbortController()
  const execP = session.exec('tail -f /var/log/app.log', { signal: controller.signal })
  // Give the session a moment to actually start, then abort.
  setTimeout(() => controller.abort(), 80)
  await assert.rejects(execP, AbortRequestedError)

  // The connector MUST have written Ctrl+C to the wire before declaring the
  // shell usable again, and the shell MUST have answered the probe.
  const sawInterrupt = wire.written.includes('\u0003')
  assert.ok(sawInterrupt, 'no Ctrl+C was sent after abort; remote job is still running')
  assert.equal(session.state, SessionState.ASSET_SHELL, 'shell was not re-verified after abort')
})

test('out-of-band interrupt() Ctrl+C and re-verifies without aborting anything', async () => {
  const { session, wire } = await connectAndEnter()
  const before = wire.written.length
  const result = await session.interrupt()
  assert.equal(result.sent, true)
  assert.equal(result.verified, true)
  assert.equal(result.state, SessionState.ASSET_SHELL)
  assert.ok(wire.written.slice(before).includes('\u0003'), 'interrupt() did not write Ctrl+C')
})

test('interrupt() on a dead wire does not throw and reports sent=false', async () => {
  const { session, wire } = await connectAndEnter()
  wire.close()
  const result = await session.interrupt()
  assert.equal(result.sent, false)
  assert.equal(result.verified, false)
})
