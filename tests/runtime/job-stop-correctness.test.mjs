/**
 * V0.4.4: Job stop path sends EXACTLY ONE Ctrl+C, holds activeJob for the
 * whole recovery, and lets the maxDuration auto-stop go through JobStore.stop.
 *
 * P1-A regression guard: a V0.4.3 stopJob did
 *     sendInterrupt()          // 1st ^C
 *     verifyShell()            // recoverShell also writes ^C -> 2nd ^C
 * so a streaming job that took the wind out of the operator's hands got
 * two Ctrl+C's. With the new interruptAndVerify() there is exactly one.
 *
 * P1-B regression guard: V0.4.3 cleared activeJob = null BEFORE the verify
 * shell probe. Another exec/startJob could land on the wire while the PTY
 * was still mid-recovery. V0.4.4 holds activeJob + sets stoppingJob; the
 * SESSION_BUSY guard fires until interruptAndVerify resolves.
 *
 * P1-C regression guard: V0.4.3's pump() did
 *     void manager.stopJob(...).catch(...)  // fire-and-forget
 *     this.finish(job, 'STOPPED', 'maxDuration reached...')  // stamp
 * So even when the remote shell could not be re-verified the job still
 * showed STOPPED. V0.4.4 makes maxDuration go through JobStore.stop and
 * trusts the {sent, verified} outcome — a non-verified stop becomes LOST.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { JumpServerError } from '../../lib/jumpserver/errors.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
    this.ctrlCCount = 0
  }
  write(text) {
    this.written.push(text)
    if (text === '\u0003') {
      this.ctrlCCount += 1
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
  if (manager.status().state === SessionState.ASSET_SHELL) return
  const enterP = manager.enter('192.168.79.99')
  setTimeout(() => wire._emit('\n[root@oa-nginx ~]# '), 30)
  await enterP
}

test('P1-A: stopJob sends EXACTLY ONE Ctrl+C to the wire (was twice in v0.4.3)', async () => {
  const { manager, wire } = makeManager()
  await connectAndEnter(manager, wire)

  await manager.startJob({
    jobId: 'jsjob_singleCC',
    target: '192.168.79.99',
    command: 'tail -f /var/log/app.log',
  })
  const beforeStop = wire.ctrlCCount

  const result = await manager.stopJob('jsjob_singleCC')

  assert.equal(result.sent, true)
  assert.equal(result.verified, true)
  // The V0.4.3 path did sendInterrupt() then verifyShell() (which itself
  // wrote ^C inside recoverShell). V0.4.4 funnels through interruptAndVerify
  // so the wire sees ONE Ctrl+C, not two.
  const sentCC = wire.ctrlCCount - beforeStop
  assert.equal(sentCC, 1, 'stopJob sent ' + sentCC + ' Ctrl+C(s); expected 1')
})

test('P1-B: while stopJob is recovering the shell, another startJob gets SESSION_BUSY', async () => {
  const { manager, wire } = makeManager()
  await connectAndEnter(manager, wire)

  // Start a job so activeJob is set.
  await manager.startJob({
    jobId: 'jsjob_occupy',
    target: '192.168.79.99',
    command: 'journalctl -f',
  })
  assert.equal(manager.hasActiveJob(), true)

  // Hand-craft a "verify is slow" probe: intercept runOp by replacing the
  // session's verify path with a never-resolving promise. Easiest is to
  // wrap the manager's session.interruptAndVerify before stopJob runs.
  const session = manager['session']
  const original = session.interruptAndVerify.bind(session)
  let resolveSlowProbe = null
  const slowProbe = new Promise((res) => { resolveSlowProbe = res })
  session.interruptAndVerify = async () => {
    const sent = session.sendInterrupt()
    if (!sent) return { sent: false, verified: false, state: session.state }
    // Hang the probe — this is the window the race used to live in.
    await slowProbe
    session.setState(SessionState.ASSET_SHELL)
    return { sent: true, verified: true, state: SessionState.ASSET_SHELL }
  }

  // Kick off stopJob but DO NOT await yet — the verify is hung.
  const stopP = manager.stopJob('jsjob_occupy')

  // While stopJob is mid-recovery: another startJob MUST be refused.
  let busy = null
  try {
    await manager.startJob({
      jobId: 'jsjob_intruder',
      target: '192.168.79.99',
      command: 'ls /tmp',
    })
  } catch (e) {
    busy = e
  }
  assert.ok(busy !== null, 'a second startJob during stop recovery did NOT get SESSION_BUSY')
  assert.equal(busy.code, 'SESSION_BUSY')

  // Let the slow probe finish; stopJob resolves cleanly.
  resolveSlowProbe('ok')
  const result = await stopP
  assert.equal(result.sent, true)
  assert.equal(result.verified, true)
  // After stopJob the manager must release both fields.
  assert.equal(manager.hasActiveJob(), false)

  // Restore and clean up so a later test can use this manager-shaped state.
  session.interruptAndVerify = original
})

test('P1-C: JobStore.stop() with reason "maxDuration" goes through the same path as manual stop', async () => {
  const { JobStore } = await import('../../lib/runtime/job-store.js')
  const { SessionRegistry } = await import('../../lib/jumpserver/session-registry.js')
  const { manager, wire, audits } = makeManager()
  await connectAndEnter(manager, wire)

  const registry = new SessionRegistry({ create: () => ({ manager, observer: { snapshotSince: () => [], cursorSeq: 0 }, lastUsedAt: 0 }) })
  registry.getOrCreate('sess-1')
  const store = new JobStore(registry)

  await manager.startJob({
    jobId: 'jsjob_maxdur',
    target: '192.168.79.99',
    command: 'tail -f /var/log/app.log',
  })
  // JobStore.start needs to know about the job so stop() can find it.
  store['jobs'].set('jsjob_maxdur', {
    id: 'jsjob_maxdur',
    sessionId: 'sess-1',
    target: '192.168.79.99',
    hostname: 'oa-nginx',
    command: 'tail -f /var/log/app.log',
    state: 'RUNNING',
    startedAt: Date.now(),
    stoppedAt: null,
    maxDurationMs: 1000,
    bytes: 0,
    truncated: false,
    error: null,
    lastSeq: 0,
    output: '',
  })

  // The auto-stop pump would call this with a "maxDuration reached …" reason.
  // The V0.4.3 path stamped STOPPED without waiting for verify; V0.4.4
  // decides STOPPED/LOST from the actual probe outcome.
  const before = wire.ctrlCCount
  const stopped = await store.stop('jsjob_maxdur', 'maxDuration reached (1s)')

  assert.equal(stopped.state, 'STOPPED')
  assert.equal(stopped.error, 'maxDuration reached (1s)')
  assert.equal(wire.ctrlCCount - before, 1, 'JobStore.stop() must end with exactly one Ctrl+C, not two')
  // The job-stop audit must reflect the success outcome (STOPPED, not LOST).
  const stopAudit = audits.find((a) => a.operation === 'job-stop' && a.taskId === 'jsjob_maxdur')
  assert.ok(stopAudit !== undefined)
  assert.equal(stopAudit.result, 'STOPPED')
})

test('P1-C (negative): when the probe fails verify, JobStore.stop() records LOST, not STOPPED', async () => {
  const { JobStore } = await import('../../lib/runtime/job-store.js')
  const { SessionRegistry } = await import('../../lib/jumpserver/session-registry.js')
  const { manager, wire, audits } = makeManager()
  await connectAndEnter(manager, wire)

  // Force interruptAndVerify to return verified=false (simulate a wedged PTY).
  const session = manager['session']
  const original = session.interruptAndVerify.bind(session)
  session.interruptAndVerify = async () => {
    session.sendInterrupt()
    return { sent: true, verified: false, state: session.state }
  }

  const registry = new SessionRegistry({ create: () => ({ manager, observer: { snapshotSince: () => [], cursorSeq: 0 }, lastUsedAt: 0 }) })
  registry.getOrCreate('sess-2')
  const store = new JobStore(registry)

  await manager.startJob({
    jobId: 'jsjob_wedged',
    target: '192.168.79.99',
    command: 'tail -f /var/log/app.log',
  })
  store['jobs'].set('jsjob_wedged', {
    id: 'jsjob_wedged',
    sessionId: 'sess-2',
    target: '192.168.79.99',
    hostname: 'oa-nginx',
    command: 'tail -f /var/log/app.log',
    state: 'RUNNING',
    startedAt: Date.now(),
    stoppedAt: null,
    maxDurationMs: 1000,
    bytes: 0,
    truncated: false,
    error: null,
    lastSeq: 0,
    output: '',
  })

  const stopped = await store.stop('jsjob_wedged', 'maxDuration reached (1s)')

  assert.equal(stopped.state, 'LOST', 'a non-verified stop MUST be LOST, not STOPPED')
  // The audit must say LOST too — otherwise downstream consumers will think
  // the job ended cleanly.
  const stopAudit = audits.find((a) => a.operation === 'job-stop' && a.taskId === 'jsjob_wedged')
  assert.ok(stopAudit !== undefined)
  assert.equal(stopAudit.result, 'LOST')

  session.interruptAndVerify = original
})
