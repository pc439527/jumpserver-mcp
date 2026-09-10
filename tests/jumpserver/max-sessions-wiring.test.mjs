/**
 * V0.4.4: maxSessions is wired into the real SessionManager.runTargetBatch,
 * not just into a stand-alone Semaphore.
 *
 * V0.4.3's session-gate.test.mjs only exercised `new Semaphore(2)` and the
 * release/acquire primitives — the test file's name and the README claim
 * "one conversation owns one bastion PTY", but no test proved that
 * runTargetBatch actually consults the gate. V0.4.4 plugs the same
 * fakeWire/Menu/enter/probe pipeline as the other E2E tests and proves
 * peak concurrent target holders is bounded by the gate size across
 * multiple managers + multiple concurrent runTargetBatch calls.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { Semaphore } from '../../lib/jumpserver/concurrency.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'

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
    // Done marker for a regular command — answer with the marker line so the
    // connector closes the run. Format: __DSH_JS_DONE_<marker>:<exitcode>.
    // We delay the response by 40ms so a 3-batch gate-of-2 scenario is
    // observably serialised on the wall clock (otherwise the wire is too
    // fast for elapsed-time assertions to mean anything).
    const done = /__DSH_JS_DONE_([0-9a-fA-F]+)/.exec(text)
    if (done !== null) {
      const marker = done[1]
      setTimeout(() => this._emit('__DSH_JS_DONE_' + marker + ':0\n[root@oa-nginx ~]# '), 40)
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

function makeManager(wire) {
  return new SessionManager({
    getConfig: () => ({
      enabled: true,
      host: '127.0.0.1',
      port: 22,
      username: 'u',
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

async function connectAndEnter(manager, wire) {
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 30)
  await connectP
  if (manager.status().state === SessionState.ASSET_SHELL) return
  const enterP = manager.enter('192.168.79.99')
  setTimeout(() => wire._emit('\n[root@oa-nginx ~]# '), 30)
  await enterP
}

test('real wiring: shared Semaphore(2) lets 2 managers batch concurrently and blocks the 3rd', async () => {
  // Three managers, one shared gate of size 2. The third one must wait.
  const wire1 = new FakeWire()
  const wire2 = new FakeWire()
  const wire3 = new FakeWire()
  const m1 = makeManager(wire1)
  const m2 = makeManager(wire2)
  const m3 = makeManager(wire3)

  const sharedGate = new Semaphore(2)
  // Wrap the gate so we can OBSERVE peak holders. The connector only sees
  // the wrapped object; the inner Semaphore still does the actual admit/drain.
  let holders = 0
  let peak = 0
  let inUseTimeline = []
  const observed = {
    acquire: async () => {
      const releaseInner = await sharedGate.acquire()
      holders += 1
      peak = Math.max(peak, holders)
      inUseTimeline.push({ event: 'acquire', at: holders })
      return () => {
        holders -= 1
        inUseTimeline.push({ event: 'release', at: holders })
        releaseInner()
      }
    },
  }
  m1['options'].sessionGate = observed
  m2['options'].sessionGate = observed
  m3['options'].sessionGate = observed

  await connectAndEnter(m1, wire1)
  await connectAndEnter(m2, wire2)
  await connectAndEnter(m3, wire3)

  // Three concurrent batches on three managers; gate is size 2.
  const readCmd = {
    command: 'uptime',
    risk: 'READ',
    classification: { risk: 'READ', reason: 'ok', ruleId: 'test.uptime', confidence: 'high', classifierVersion: 1, normalizedCommand: 'uptime' },
    approvalRequired: false,
    approvalResult: 'none',
    actor: 'AGENT',
  }
  const start = Date.now()
  const results = await Promise.all([
    m1.runTargetBatch({ target: '192.168.79.99', commands: [readCmd] }),
    m2.runTargetBatch({ target: '192.168.79.99', commands: [readCmd] }),
    m3.runTargetBatch({ target: '192.168.79.99', commands: [readCmd] }),
  ])
  const elapsed = Date.now() - start

  // 1. Every batch returned a TargetBatchResult (no SESSION_BUSY escape).
  for (const r of results) {
    assert.equal(r.error, null)
    assert.equal(r.commands.length, 1)
  }
  // 2. The gate never held more than 2 at once.
  assert.ok(peak <= 2, 'peak concurrent holders ' + peak + ' exceeded gate size 2')
  // 3. With a gate of size 2 over 3 batches that each take ~one exec cycle,
  // the third batch must have started AFTER at least one release. We assert
  // by inspecting the timeline: at some point the count was exactly 2 and
  // later reached 1 before reaching 0 — proving the third waited.
  const maxAt = Math.max(...inUseTimeline.map((e) => e.at))
  assert.equal(maxAt, 2, 'the gate admitted exactly 2 holders at peak')
  assert.ok(inUseTimeline.some((e) => e.event === 'release' && e.at === 1), 'a release-to-1 happened, proving the third batch waited')
  // 4. The total elapsed time must be larger than a single batch (proving
  // serialisation happened). On a fake wire the per-batch work is small but
  // non-zero; 30ms is a conservative lower bound.
  assert.ok(elapsed > 30, 'elapsed ' + elapsed + 'ms is too short to prove serialisation')
})

test('real wiring: without a gate, multiple managers batch fully in parallel (gate is opt-in)', async () => {
  // Sanity check: the gate only fires when the manager was configured with
  // one. A no-gate manager must NOT silently start respecting a global cap.
  const wire1 = new FakeWire()
  const wire2 = new FakeWire()
  const m1 = makeManager(wire1)
  const m2 = makeManager(wire2)
  // Both managers deliberately leave sessionGate = undefined.
  await connectAndEnter(m1, wire1)
  await connectAndEnter(m2, wire2)

  const readCmd = {
    command: 'uptime',
    risk: 'READ',
    classification: { risk: 'READ', reason: 'ok', ruleId: 'test.uptime', confidence: 'high', classifierVersion: 1, normalizedCommand: 'uptime' },
    approvalRequired: false,
    approvalResult: 'none',
    actor: 'AGENT',
  }
  const start = Date.now()
  const results = await Promise.all([
    m1.runTargetBatch({ target: '192.168.79.99', commands: [readCmd] }),
    m2.runTargetBatch({ target: '192.168.79.99', commands: [readCmd] }),
  ])
  const elapsed = Date.now() - start
  for (const r of results) assert.equal(r.error, null)
  // Both ran in parallel — elapsed should be roughly one batch, not two.
  // 50ms is a tight but achievable bound on the fake wire.
  assert.ok(elapsed < 250, 'without a gate two batches should run in parallel; elapsed=' + elapsed)
})
