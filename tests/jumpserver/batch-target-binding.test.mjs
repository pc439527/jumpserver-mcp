/**
 * V0.6.0 (A-3): a batch must never run on a machine it was not asked for.
 *
 * The CRM rollout's "假成功": `jumpserver_batch` asked for 192.168.30.2, the
 * commands actually landed on the shell of 192.168.30.3 (hostname
 * `k8s-192-168-30-3`), and the tool reported success. Nothing in the
 * connector noticed, because the shell was never asked who it was (A-2) and
 * the batch never checked whose shell it was holding (A-3).
 *
 * These tests drive the REAL SessionManager with a fake wire:
 *   1. a probe that reports a DIFFERENT asset aborts the enter with
 *      TARGET_VERIFICATION_FAILED — and no command runs;
 *   2. a batch whose session is bound to another target is REJECTED, not
 *      executed;
 *   3. a normal batch still works end to end (no regression).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

class FakeWire {
  constructor(options = {}) {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
    /** The hostname the probe reports for the asset shell. */
    this.probeHostname = options.probeHostname ?? 'oa-nginx'
    /** The asset's own IPv4 addresses (the `A=` probe line). */
    this.probeIps = options.probeIps ?? []
  }
  write(text) {
    this.written.push(text)
    if (text === 'exit\n' || text.trim() === 'exit') {
      this._emit('\r\n[Host]> ')
      return
    }
    const m = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (m !== null) {
      const marker = m[1]
      const ipLine = this.probeIps.length > 0 ? 'A=' + this.probeIps.join(',') + '\n' : ''
      this._emit(
        '\n__DSH_JS_PROBE_' + marker + '\n' +
        'H=' + this.probeHostname + '\n' +
        'U=root\n' +
        'P=/root\n' +
        ipLine +
        '__DSH_JS_PROBE_END_' + marker + '\n' +
        '[root@' + this.probeHostname + ' ~]# ',
      )
      return
    }
    const done = /__DSH_JS_DONE_([0-9a-fA-F]+)/.exec(text)
    if (done !== null) {
      const marker = done[1]
      setTimeout(() => this._emit('__DSH_JS_DONE_' + marker + ':0\n[root@' + this.probeHostname + ' ~]# '), 20)
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
  '│  请输入资产名或编号：                       │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

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

test('an asset whose probe reports a DIFFERENT machine aborts the enter', async () => {
  // The session will answer as `k8s-192-168-30-3` although the caller asked
  // for 192.168.30.2 — the exact CRM false-success scenario.
  const wire = new FakeWire({ probeHostname: 'k8s-192-168-30-3', probeIps: ['192.168.30.3'] })
  const manager = makeManager(wire)
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  const enterP = manager.enter('192.168.30.2')
  setTimeout(() => wire._emit('\n[root@k8s-192-168-30-3 ~]# '), 30)
  const error = await enterP.then(() => null, (e) => e)
  assert.ok(error !== null, 'entering the wrong machine must reject')
  assert.equal(error.code, 'TARGET_VERIFICATION_FAILED')
  assert.ok(String(error.detail).includes('192.168.30.2'), error.detail)
  await manager.close()
})

test('no command is executed on the wrong machine', async () => {
  const wire = new FakeWire({ probeHostname: 'k8s-192-168-30-3', probeIps: ['192.168.30.3'] })
  const manager = makeManager(wire)
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  const batchP = manager.runTargetBatch({
    target: '192.168.30.2',
    commands: [{ command: 'hostname' }],
  })
  setTimeout(() => wire._emit('\n[root@k8s-192-168-30-3 ~]# '), 30)
  const result = await batchP
  assert.ok(result.error !== null, 'the batch must report the verification failure')
  assert.equal(result.error.code, 'TARGET_VERIFICATION_FAILED')
  assert.equal(result.commands.length, 0)
  // The wire must never have received the command itself. The PROBE script
  // also contains the word `hostname`, so the check looks for the done-script
  // wrapper that only a real command carries.
  const commandWrites = wire.written.filter((w) => w.includes('__DSH_JS_DONE_'))
  assert.equal(commandWrites.length, 0, 'no command may reach the wrong machine')
  await manager.close()
})

test('a matching asset is accepted and the command runs', async () => {
  const wire = new FakeWire({ probeHostname: 'oa-nginx', probeIps: ['192.168.79.99'] })
  const manager = makeManager(wire)
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  const batchP = manager.runTargetBatch({
    target: '192.168.79.99',
    commands: [{ command: 'hostname' }],
  })
  setTimeout(() => wire._emit('\n[root@oa-nginx ~]# '), 30)
  const result = await batchP
  assert.equal(result.error, null, JSON.stringify(result.error))
  assert.equal(result.commands.length, 1)
  assert.equal(result.commands[0].commandStatus, 'SUCCESS')
  assert.equal(manager.status().state, SessionState.ASSET_SHELL)
  await manager.close()
})
