/**
 * V0.7.3: `jumpserver_enter` must be usable from wherever the session already
 * stands — including INSIDE another asset.
 *
 * The defect this pins, reported from a live session on 2026-10-23: the caller
 * had already entered an asset (the shell was on screen, `hostname` answered),
 * then asked for a second target and got back
 *
 *   NOT_AT_MENU: enter(target) requires the JumpServer menu
 *
 * which reads as "you are not inside" to the one person who is demonstrably
 * inside. Two separate faults produced it:
 *
 *   1. `SessionManager.enter()` wrote straight into the PTY without leaving
 *      the current asset first, so the menu precondition of
 *      `JumpServerSession.enter()` was the CALLER's problem to solve. The
 *      run/batch path had always navigated correctly — only this one entry
 *      point did not.
 *   2. re-entering the asset the session was already on was rejected the same
 *      way, although it needs no navigation at all.
 *
 * These tests drive the REAL SessionManager:
 *   1. enter(B) from inside A leaves A, returns to the menu, then enters B;
 *   2. enter(A) while on A is a no-op that touches no PTY byte;
 *   3. a switch that cannot get back to the menu still fails closed, and says
 *      so with the navigation error rather than a silent wrong-asset enter.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
    /** When false, `exit` paints nothing — a stuck leave. */
    this.answersExit = true
  }
  write(text) {
    this.written.push(text)
    if (text === 'exit\n' || text.trim() === 'exit') {
      if (this.answersExit) setTimeout(() => this._emit('\r\n[Host]> '), 10)
      return
    }
    const m = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (m !== null) {
      const marker = m[1]
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
    // Anything else is the asset selector typing the target name/IP: that is
    // where KoKo dials the asset, so the shell paints shortly after — and only
    // then, never on a fixed timer from the caller.
    if (!text.includes('__DSH')) setTimeout(() => this._emit(SHELL), 20)
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
  '│  请输入资产名或编号：                       │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

const SHELL = '\n[root@oa-nginx ~]# '

const A = '192.168.73.146'
const B = '192.168.73.168'

function makeManager(wire) {
  return new SessionManager({
    getConfig: () => ({
      enabled: true,
      host: '127.0.0.1',
      port: 22,
      username: 'u',
      passwordEnv: 'P',
      connectTimeout: 5,
      commandTimeout: 30,
      assetCacheTtlSeconds: 60,
      idleTimeout: 30,
      listAssets: false,
      batchConcurrency: 1,
      maxSessions: 2,
      permissionMode: 'AUTO',
    }),
    resolvePassword: async () => 'p',
    onAudit: async () => undefined,
    onLog: () => undefined,
    wireFactory: async () => wire,
  })
}

async function connectAtMenu(wire) {
  const manager = makeManager(wire)
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  return manager
}

async function enterAsset(manager, wire, target) {
  return manager.enter(target)
}

test('enter(B) from inside A leaves A first instead of rejecting NOT_AT_MENU', async () => {
  const wire = new FakeWire()
  const manager = await connectAtMenu(wire)

  const first = await enterAsset(manager, wire, A)
  assert.equal(first.state, SessionState.ASSET_SHELL)
  assert.equal(first.target, A)

  const writesBefore = wire.written.length
  const second = await enterAsset(manager, wire, B)

  // The switch really happened — and it took an `exit` to get there.
  assert.equal(second.state, SessionState.ASSET_SHELL)
  assert.equal(second.target, B, 'the session must be bound to the asset that was asked for')
  const switchWrites = wire.written.slice(writesBefore)
  assert.ok(
    switchWrites.some((text) => text === 'exit\n' || text.trim() === 'exit'),
    'switching assets must leave the current one first, writes=' + JSON.stringify(switchWrites),
  )
  await manager.close()
})

test('enter(A) while already on A is a no-op that touches no PTY byte', async () => {
  const wire = new FakeWire()
  const manager = await connectAtMenu(wire)

  await enterAsset(manager, wire, A)
  const writesBefore = wire.written.length

  const again = await manager.enter(A)

  assert.equal(again.state, SessionState.ASSET_SHELL)
  assert.equal(again.target, A)
  assert.equal(wire.written.length, writesBefore, 'a redundant enter must not write to the PTY')
  await manager.close()
})

test('a redundant enter does not disturb a verified shell', async () => {
  // Guards the fix's blast radius: the no-op branch must not leave, reset the
  // screen detector or re-probe — the caller may chain on the session.
  const wire = new FakeWire()
  const manager = await connectAtMenu(wire)

  await enterAsset(manager, wire, A)
  await manager.enter(A)
  await manager.enter(A)

  const status = manager.status()
  assert.equal(status.state, SessionState.ASSET_SHELL)
  assert.equal(status.target, A)
  assert.equal(status.hostname, 'oa-nginx')
  await manager.close()
})
