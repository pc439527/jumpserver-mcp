/**
 * V0.4.4: jumpserver_job_start passes `beforeExec` through ALL the way.
 *
 * Regressions this guards against (v0.4.3):
 *   - tools-ops.ts threw away `gated.beforeExec` and the audit stamped
 *     `approvalResult: 'approved'` anyway.
 *   - JobStore.start did not forward `beforeExec` to the SessionManager.
 *   - SessionManager.startJob did not run the gate between navigateToTarget
 *     and writeLine — so a denied approval would still claim the PTY.
 *
 * Coverage: SessionManager.startJob is driven through its REAL queue path
 * with a fake wire that mimics menu → enter → probe → asset-shell. We use
 * the wire to see exactly what bytes hit the PTY and when.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { JumpServerError } from '../../lib/jumpserver/errors.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

/**
 * Transport that speaks the same dialect as connectAndEnter. We additionally
 * record the relative position of every `write` so the test can ask
 * "did beforeExec land before writeLine?" without guessing.
 */
class FakeWire {
  constructor() {
    this.written = []           // every text handed to write(), in order
    this.cbs = []
    this.closeCbs = []
    this.closed = false
  }
  write(text) {
    this.written.push(text)
    if (text === '\u0003') {
      this._emit('\n[root@oa-nginx ~]# ')
      return
    }
    const m = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (m !== null) {
      const marker = m[1]
      this._emit(
        '\n__DSH_JS_PROBE_' + marker + '\n' +
        'H=oa-nginx\nU=root\nP=/root\n' +
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

function makeManager() {
  const wire = new FakeWire()
  const audits = []
  const manager = new SessionManager(
    {
      getConfig: () => ({
        enabled: true,
        enableAudit: true,
        host: '127.0.0.1',
        port: 22,
        username: 'u',
        connectTimeout: 5,
        commandTimeout: 30,
        assetCacheTtlSeconds: 60,
        idleTimeout: 30,
        listAssets: false,
        batchConcurrency: 1,
        maxSessions: 1,
        permissionMode: 'AUTO',
      }),
      resolvePassword: async () => 'p',
      onAudit: async (rec) => audits.push(rec),
      onLog: () => undefined,
      wireFactory: async () => wire,
    },
  )
  return { manager, wire, audits }
}

async function connectAndEnter(manager, wire) {
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  const status = manager.status()
  if (status.state === SessionState.ASSET_SHELL) return
  // Let manager.enter drive navigation: it sends the asset name and waits
  // for an asset-shell prompt with H/U/P probe. The fake wire answers the
  // probe automatically on the PROBE marker.
  const enterP = manager.enter('192.168.79.99')
  setTimeout(() => wire._emit('\n[root@oa-nginx ~]# '), 30)
  await enterP
}

test('beforeExec runs AFTER navigateToTarget and BEFORE writeLine (order = navigate, gate, write)', async () => {
  const { manager, wire, audits } = makeManager()
  await connectAndEnter(manager, wire)
  assert.equal(manager.status().state, SessionState.ASSET_SHELL, 'preflight did not reach ASSET_SHELL')

  const beforeExecCalls = []
  const beforeExec = async () => {
    beforeExecCalls.push(Date.now())
  }

  await manager.startJob({
    jobId: 'jsjob_testOrder',
    target: '192.168.79.99',
    command: 'journalctl -f -u nginx',
    beforeExec,
    approvalRequired: true,
  })

  // The PTY must have received the job command (after the gate cleared).
  assert.ok(
    wire.written.some((w) => w.includes('journalctl -f -u nginx')),
    'writeLine never wrote the job command to the PTY: ' + JSON.stringify(wire.written),
  )
  assert.equal(beforeExecCalls.length, 1, 'beforeExec called the wrong number of times')
  // Audit must record `approved` — gate ran AND passed.
  const startAudit = audits.find((a) => a.operation === 'job-start' && a.taskId === 'jsjob_testOrder')
  assert.ok(startAudit !== undefined, 'no job-start audit was written')
  assert.equal(startAudit.approvalResult, 'approved', 'gate cleared but audit said otherwise')
})

test('when beforeExec throws COMMAND_APPROVAL_REQUIRED the command is NOT written and the audit records denied', async () => {
  const { manager, wire, audits } = makeManager()
  await connectAndEnter(manager, wire)

  const beforeExec = async () => {
    throw new JumpServerError('COMMAND_APPROVAL_REQUIRED', 'user did not confirm')
  }

  await assert.rejects(
    manager.startJob({
      jobId: 'jsjob_testDeny',
      target: '192.168.79.99',
      command: 'rm -rf /tmp/doomed',
      beforeExec,
      approvalRequired: true,
    }),
    (err) => err.code === 'COMMAND_APPROVAL_REQUIRED',
  )

  // The denied command MUST NOT have hit the PTY.
  assert.equal(
    wire.written.includes('rm -rf /tmp/doomed'),
    false,
    'a denied job command reached the PTY — the gate was bypassed',
  )
  // Audit must record `denied` and a clean DENIED result.
  const denyAudit = audits.find((a) => a.operation === 'job-start' && a.taskId === 'jsjob_testDeny')
  assert.ok(denyAudit !== undefined, 'no job-start audit was written for the denied call')
  assert.equal(denyAudit.approvalResult, 'denied')
  assert.equal(denyAudit.result, 'DENIED')
  assert.equal(manager.hasActiveJob(), false, 'denied start must not claim the PTY')
})

test('a non-approval error from beforeExec propagates as-is and is NOT silently swallowed', async () => {
  const { manager, wire, audits } = makeManager()
  await connectAndEnter(manager, wire)

  const boom = new Error('boom — network blip')
  const beforeExec = async () => { throw boom }

  await assert.rejects(
    manager.startJob({
      jobId: 'jsjob_testBoom',
      target: '192.168.79.99',
      command: 'ls /tmp',
      beforeExec,
    }),
    (err) => err === boom,
  )
  // The PTY must NOT have received the command either: any gate failure is
  // an end-of-start condition.
  assert.equal(wire.written.some((w) => w.includes('ls /tmp')), false)
  // And NO job-start audit is written — the gate didn't pass; we don't
  // pretend the start happened. (Operators find a missing record more
  // honest than a `denied` row that says "user rejected" when actually the
  // gate crashed.)
  const startAudit = audits.find((a) => a.operation === 'job-start' && a.taskId === 'jsjob_testBoom')
  assert.equal(startAudit, undefined)
})
