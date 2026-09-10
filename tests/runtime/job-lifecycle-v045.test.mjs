/**
 * V0.4.5: Job lifecycle & isolation correctness.
 *
 * Guards the five production-path defects found in the v0.4.4 review:
 *
 *  P1-A double Ctrl+C — jumpserver_interrupt / the console sent
 *       manager.interrupt() (^C #1) and THEN jobs.stop() (^C #2) for the same
 *       streaming job. interruptSession() must pick exactly ONE owner.
 *  P1-B concurrent JobStore.stop() — caller B used to observe state
 *       VERIFYING, skip the probe branch and stamp STOPPED while caller A's
 *       probe later failed with LOST. Both callers must share ONE decision.
 *  P1-C ghost activeJob — SessionManager.close() left activeJob set, so a
 *       reconnect inherited a permanent SESSION_BUSY.
 *  P1-D masked LOST after a fast reconnect — the pump only looked at
 *       DISCONNECTED; a reconnect landing inside one interval left a dead job
 *       RUNNING. PTY ownership (activeJobId()) is now the authority.
 *  P1-E cross-conversation jobs — a multiplexed process let conversation B
 *       list / read / stop conversation A's jobs.
 *  P1-F job_read was not incremental — every call returned the buffer TAIL,
 *       so a polling model re-consumed and re-judged old log lines.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { SessionRegistry } from '../../lib/jumpserver/session-registry.js'
import { JobStore, MAX_JOBS } from '../../lib/runtime/job-store.js'
import { interruptSession } from '../../lib/runtime/interrupt.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

class FakeWire {
  constructor(counter) {
    this.counter = counter
    this.written = []
    this.cbs = []
    this.closeCbs = []
    this.closed = false
  }
  write(text) {
    this.written.push(text)
    if (text === '\u0003') {
      this.counter.ctrlC += 1
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

/** A manager whose wireFactory hands out a FRESH wire per connect (reconnect-safe). */
function makeManager() {
  const state = { ctrlC: 0, wire: null }
  const audits = []
  const manager = new SessionManager({
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
    wireFactory: async () => {
      const wire = new FakeWire(state)
      state.wire = wire
      return wire
    },
  })
  return { manager, state, audits, get wire() { return state.wire } }
}

async function connectAndEnter(m) {
  const connectP = m.manager.connect()
  setTimeout(() => m.wire._emit(MENU_SCREEN), 30)
  await connectP
  if (m.manager.status().state === SessionState.ASSET_SHELL) return
  const enterP = m.manager.enter('192.168.79.99')
  setTimeout(() => m.wire._emit('\n[root@oa-nginx ~]# '), 30)
  await enterP
}

/** Registry with one real manager + a stub observer (JobStore only needs these). */
function registryWith(manager, sessionId = 'sess-1') {
  const registry = new SessionRegistry({
    create: () => ({ manager, observer: { cursorSeq: 0, oldestSeq: 1, snapshotSince: () => [], snapshot: () => [] }, lastUsedAt: 0 }),
  })
  registry.getOrCreate(sessionId)
  return registry
}

// ------------------------------------------------------------------ P1-A
test('P1-A: interruptSession on a job-owning session sends exactly ONE Ctrl+C', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  const store = new JobStore(registryWith(m.manager))
  const job = await store.start({
    sessionId: 'sess-1',
    target: '192.168.79.99',
    command: 'tail -f /var/log/app.log',
  })

  // Spy: the raw out-of-band interrupt must NOT be used while a job owns the PTY.
  let rawInterrupts = 0
  const original = m.manager.interrupt.bind(m.manager)
  m.manager.interrupt = async () => { rawInterrupts += 1; return original() }

  const before = m.state.ctrlC
  const outcome = await interruptSession(store, m.manager, 'sess-1')

  assert.equal(outcome.mode, 'job', 'a streaming job must own the interrupt')
  assert.equal(outcome.jobState, 'STOPPED')
  assert.equal(outcome.verified, true)
  assert.equal(outcome.jobsStopped, 1)
  assert.equal(rawInterrupts, 0, 'manager.interrupt() must NOT run while a job owns the shell')
  assert.equal(m.state.ctrlC - before, 1, 'the whole interrupt must send exactly one Ctrl+C')
  assert.equal(store.get(job.id, 'sess-1').state, 'STOPPED')
})

test('P1-A: interruptSession with no streaming job falls back to the raw shell interrupt', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  const store = new JobStore(registryWith(m.manager))

  let rawInterrupts = 0
  const original = m.manager.interrupt.bind(m.manager)
  m.manager.interrupt = async () => { rawInterrupts += 1; return original() }

  const before = m.state.ctrlC
  const outcome = await interruptSession(store, m.manager, 'sess-1')

  assert.equal(outcome.mode, 'shell')
  assert.equal(rawInterrupts, 1)
  assert.equal(m.state.ctrlC - before, 1, 'still exactly one Ctrl+C')
})

// ------------------------------------------------------------------ P1-B
test('P1-B: two concurrent JobStore.stop() calls share ONE decision and one Ctrl+C', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  const store = new JobStore(registryWith(m.manager))
  const job = await store.start({
    sessionId: 'sess-1',
    target: '192.168.79.99',
    command: 'journalctl -f',
  })

  // Hang the verify so both callers overlap inside the critical window, and
  // make it FAIL: the truth is LOST, so nobody may stamp STOPPED.
  const session = m.manager['session']
  let releaseProbe = null
  const gate = new Promise((resolve) => { releaseProbe = resolve })
  session.interruptAndVerify = async () => {
    session.sendInterrupt()
    await gate
    session.setState(SessionState.UNKNOWN)
    return { sent: true, verified: false, state: session.state }
  }

  const before = m.state.ctrlC
  const first = store.stop(job.id, 'manual job_stop')
  const second = store.stop(job.id, 'maxDuration reached (1s)')

  releaseProbe('done')
  const [a, b] = await Promise.all([first, second])

  assert.equal(a.state, 'LOST', 'a failed verify must be LOST')
  assert.equal(b.state, 'LOST', 'the second caller must NOT overwrite the verdict')
  assert.equal(a, b, 'both callers must resolve to the same record')
  assert.equal(b.error, 'manual job_stop', 'the first caller owns the recorded reason')
  assert.equal(m.state.ctrlC - before, 1, 'concurrent stops must not re-send Ctrl+C')
  const stopAudits = m.audits.filter((rec) => rec.operation === 'job-stop' && rec.taskId === job.id)
  assert.equal(stopAudits.length, 1, 'exactly one job-stop audit')
  assert.equal(stopAudits[0].result, 'LOST')

  session.interruptAndVerify = session.constructor.prototype.interruptAndVerify.bind(session)
})

test('P1-B: a completed stop is returned as-is to a later caller (idempotent)', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  const store = new JobStore(registryWith(m.manager))
  const job = await store.start({ sessionId: 'sess-1', target: '192.168.79.99', command: 'top -b' })

  const before = m.state.ctrlC
  const first = await store.stop(job.id, 'manual')
  const second = await store.stop(job.id, 'manual again')

  assert.equal(first.state, 'STOPPED')
  assert.equal(second.state, 'STOPPED')
  assert.equal(second.error, 'manual', 'reason of the first stop is preserved')
  assert.equal(m.state.ctrlC - before, 1, 'the second stop must not touch the wire again')
})

// ------------------------------------------------------------------ P1-C
test('P1-C: close() releases PTY ownership so a reconnect is not permanently SESSION_BUSY', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  await m.manager.startJob({ jobId: 'jsjob_ghost', target: '192.168.79.99', command: 'tail -f /var/log/app.log' })
  assert.equal(m.manager.hasActiveJob(), true)
  assert.equal(m.manager.activeJobId(), 'jsjob_ghost')

  await m.manager.close()
  assert.equal(m.manager.hasActiveJob(), false, 'close() must clear activeJob')
  assert.equal(m.manager.activeJobId(), null)

  // Reconnect and prove the shell is usable again (the ghost used to answer
  // SESSION_BUSY forever).
  const connectP = m.manager.connect()
  setTimeout(() => m.wire._emit(MENU_SCREEN), 30)
  await connectP
  const enterP = m.manager.enter('192.168.79.99')
  setTimeout(() => m.wire._emit('\n[root@oa-nginx ~]# '), 30)
  await enterP

  const started = await m.manager.startJob({ jobId: 'jsjob_after', target: '192.168.79.99', command: 'ls /tmp' })
  assert.equal(started.target, '192.168.79.99')
  assert.equal(m.manager.activeJobId(), 'jsjob_after')
})

// ------------------------------------------------------------------ P1-D
test('P1-D: a job whose shell was replaced (fast reconnect) is reported LOST', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  const store = new JobStore(registryWith(m.manager))
  const job = await store.start({ sessionId: 'sess-1', target: '192.168.79.99', command: 'tail -f /var/log/app.log' })

  // Simulate an auto-reconnect that landed inside one pump interval: the
  // transport looks healthy again, but this job no longer owns any PTY.
  const healthy = m.manager.status.bind(m.manager)
  m.manager.status = () => ({ ...healthy(), state: SessionState.ASSET_SHELL })
  m.manager.activeJobId = () => null

  const listed = store.list('sess-1').find((j) => j.id === job.id)
  assert.equal(listed.state, 'LOST', 'a job without PTY ownership must not stay RUNNING')
  assert.match(String(listed.error), /no longer owned/)
})

test('P1-D: the transport-loss path still marks the job LOST', async () => {
  const m = makeManager()
  await connectAndEnter(m)
  const store = new JobStore(registryWith(m.manager))
  const job = await store.start({ sessionId: 'sess-1', target: '192.168.79.99', command: 'tail -f /var/log/app.log' })

  m.wire.close() // onClose -> manager.onSessionLost -> releasePtyOwnership
  assert.equal(m.manager.activeJobId(), null)

  const listed = store.list('sess-1').find((j) => j.id === job.id)
  assert.equal(listed.state, 'LOST')
})

// ------------------------------------------------------------------ P1-E
test('P1-E: read/list/stop are scoped to the calling conversation', async () => {
  const a = makeFakeBundle('s-A')
  const b = makeFakeBundle('s-B')
  const store = new JobStore(fakeRegistry({ 's-A': a, 's-B': b }))

  const jobA = await store.start({ sessionId: 's-A', target: 'oa-A', command: 'tail -f a.log' })
  const jobB = await store.start({ sessionId: 's-B', target: 'oa-B', command: 'tail -f b.log' })

  assert.deepEqual(store.list('s-A').map((j) => j.id), [jobA.id])
  assert.deepEqual(store.list('s-B').map((j) => j.id), [jobB.id])
  assert.equal(store.list().length, 2, 'the console view still sees every session')

  assert.equal(store.read(jobA.id, { sessionId: 's-B' }), null, 'B must not read A')
  assert.equal(store.get(jobA.id, 's-B'), null, 'B must not see A')
  await assert.rejects(
    store.stop(jobA.id, null, 's-B'),
    (err) => /not part of this conversation/.test(err.message),
  )
  // A's job is untouched by B's refused stop.
  assert.equal(store.get(jobA.id, 's-A').state, 'RUNNING')
})

test('P1-E: the RUNNING cap is per conversation, not per process', async () => {
  const a = makeFakeBundle('s-A')
  const b = makeFakeBundle('s-B')
  const store = new JobStore(fakeRegistry({ 's-A': a, 's-B': b }))

  for (let i = 0; i < MAX_JOBS; i += 1) {
    await store.start({ sessionId: 's-A', target: 'oa-A', command: 'tail -f a' + i })
  }
  await assert.rejects(
    store.start({ sessionId: 's-A', target: 'oa-A', command: 'tail -f overflow' }),
    (err) => /too many running jobs/.test(err.message),
  )
  // Conversation B is unaffected by A exhausting its budget.
  const jobB = await store.start({ sessionId: 's-B', target: 'oa-B', command: 'tail -f b' })
  assert.equal(jobB.state, 'RUNNING')
})

// ------------------------------------------------------------------ P1-F
test('P1-F: job_read is a cursor read — the second call returns only what arrived', async () => {
  const a = makeFakeBundle('s-1')
  const store = new JobStore(fakeRegistry({ 's-1': a }))
  const job = await store.start({ sessionId: 's-1', target: 'oa-1', command: 'tail -f x' })

  a.push('AAAA')
  const first = store.read(job.id, { sessionId: 's-1' })
  assert.equal(first.output, 'AAAA')
  assert.equal(first.nextSeq, 4)
  assert.equal(first.partial, false)

  a.push('BBBB')
  const second = store.read(job.id, { sessionId: 's-1' })
  assert.equal(second.output, 'BBBB', 'the second read must NOT repeat the old lines')
  assert.equal(second.nextSeq, 8)

  a.push('CCCC')
  const explicit = store.read(job.id, { sessionId: 's-1', sinceSeq: 4 })
  assert.equal(explicit.output, 'BBBBCCCC', 'an explicit sinceSeq resumes exactly there')

  const full = store.read(job.id, { sessionId: 's-1', full: true })
  assert.equal(full.output, 'AAAABBBBCCCC')
  assert.equal(full.mode, 'full')
  assert.equal(full.nextSeq, 12)
})

test('P1-F: maxChars caps one window and nextSeq resumes after it', async () => {
  const a = makeFakeBundle('s-1')
  const store = new JobStore(fakeRegistry({ 's-1': a }))
  const job = await store.start({ sessionId: 's-1', target: 'oa-1', command: 'tail -f x' })

  a.push('0123456789')
  const first = store.read(job.id, { sessionId: 's-1', maxChars: 4 })
  assert.equal(first.output, '0123')
  assert.equal(first.partial, true)
  const second = store.read(job.id, { sessionId: 's-1', maxChars: 4 })
  assert.equal(second.output, '4567')
  const third = store.read(job.id, { sessionId: 's-1', maxChars: 4 })
  assert.equal(third.output, '89')
  assert.equal(third.partial, false)
})

test('P1-F: evicted output is reported as droppedChars instead of silently skipped', async () => {
  const a = makeFakeBundle('s-1')
  const store = new JobStore(fakeRegistry({ 's-1': a }))
  const job = await store.start({ sessionId: 's-1', target: 'oa-1', command: 'tail -f x' })

  a.push('A'.repeat(300 * 1024)) // force the 256KB buffer trim
  const view = store.read(job.id, { sessionId: 's-1', sinceSeq: 0, maxChars: 200 })
  assert.ok(view.droppedChars > 0, 'the caller must learn that the cursor fell off the buffer')
  assert.equal(view.output.length, 200)
})

/** A registry whose bundles are deterministic fakes (no SSH involved). */
function fakeRegistry(bundles) {
  const registry = new SessionRegistry({ create: (sessionId) => (bundles[sessionId] ?? makeFakeBundle(sessionId)).bundle })
  // JobStore.start() reads an EXISTING bundle (registry.get), exactly like the
  // real runtime where the tool host created it first.
  for (const id of Object.keys(bundles)) registry.getOrCreate(id)
  return registry
}

/**
 * Fake bundle + its mutable state. `push()` appends a TerminalObserver-style
 * output event; the jobs here are driven by the JobStore only.
 */
function makeFakeBundle(sessionId) {
  const state = {
    activeJob: null,
    events: [],
    seq: 1,
    stops: 0,
    interrupts: 0,
  }
  const manager = {
    sessionId,
    activeJobId: () => state.activeJob,
    status: () => ({ state: SessionState.ASSET_SHELL, target: 'oa-1', hostname: 'oa-1' }),
    startJob: async ({ jobId, target }) => {
      state.activeJob = jobId
      return { target, hostname: 'oa-1', state: SessionState.ASSET_SHELL, startSeq: 0 }
    },
    stopJob: async () => {
      state.stops += 1
      state.activeJob = null
      return { sent: true, verified: true, state: SessionState.ASSET_SHELL }
    },
    interrupt: async () => {
      state.interrupts += 1
      return { sent: true, verified: true, state: SessionState.ASSET_SHELL, target: 'oa-1' }
    },
  }
  const observer = {
    cursorSeq: 0,
    oldestSeq: 1,
    snapshotSince: (since) => state.events.filter((event) => event.seq > since),
    snapshot: () => state.events,
  }
  return {
    bundle: { manager, observer, lastUsedAt: 0 },
    manager,
    observer,
    state,
    push(data) {
      state.events.push({ seq: state.seq, type: 'output', data })
      state.seq += 1
    },
  }
}
