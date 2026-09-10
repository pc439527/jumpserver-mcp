/**
 * Baseline drift detection (V0.4.1).
 *
 * Contract: only REAL differences are reported (load jitter and small memory
 * shifts are suppressed), an unreachable host is never "unchanged", and a
 * baseline name can never escape the storage directory.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { BaselineStore, diffBaseline, diffHost, isValidBaselineName } from '../../lib/runtime/baseline-store.js'
import { JumpServerError } from '../../lib/jumpserver/errors.js'

function host(target, overrides = {}) {
  return {
    target,
    hostname: target,
    reachable: true,
    error: null,
    os: 'CentOS 7',
    kernel: '3.10.0',
    cores: 4,
    memoryTotalMb: 8000,
    memoryUsedPct: 50,
    load: [1.0, 1.0, 1.0],
    disks: [{ mount: '/', usePct: 40 }],
    listening: [{ port: 22, process: 'sshd' }],
    services: ['nginx'],
    roles: ['nginx'],
    ...overrides,
  }
}

test('isValidBaselineName rejects path traversal and separators', () => {
  assert.equal(isValidBaselineName('oa-prechange-20260910'), true)
  assert.equal(isValidBaselineName('../etc/passwd'), false)
  assert.equal(isValidBaselineName('a/b'), false)
  assert.equal(isValidBaselineName(''), false)
  assert.equal(isValidBaselineName('.hidden'), false)
})

test('BaselineStore: save then load round-trips, list reports the name', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bl-'))
  try {
    const store = new BaselineStore(dir)
    store.save({ name: 'snap1', createdAt: '2026-09-10T00:00:00Z', profile: 'basic', targets: ['a'], hosts: [host('a')] })
    assert.deepEqual(store.list(), ['snap1'])
    const loaded = store.load('snap1')
    assert.equal(loaded.hosts.length, 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('BaselineStore: load of an unknown name errors with UNKNOWN_BASELINE', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bl-'))
  try {
    const store = new BaselineStore(dir)
    assert.throws(
      () => store.load('nope'),
      (e) => e instanceof JumpServerError && e.code === 'UNKNOWN_BASELINE',
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('BaselineStore: save with an invalid name refuses (no traversal)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bl-'))
  try {
    const store = new BaselineStore(dir)
    assert.throws(
      () => store.save({ name: '../evil', createdAt: '', profile: 'basic', targets: [], hosts: [] }),
      (e) => e instanceof JumpServerError && e.code === 'INVALID_ARGUMENT',
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('diffHost: identical hosts are unchanged', () => {
  const drift = diffHost(host('a'), host('a'))
  assert.equal(drift.status, 'unchanged')
  assert.deepEqual(drift.changes, [])
})

test('diffHost: load jitter under 25% is suppressed', () => {
  const drift = diffHost(host('a', { load: [1.0, 1, 1] }), host('a', { load: [1.1, 1, 1] }))
  assert.equal(drift.status, 'unchanged')
})

test('diffHost: a material load shift IS reported', () => {
  const drift = diffHost(host('a', { load: [1.0, 1, 1] }), host('a', { load: [5.0, 1, 1] }))
  assert.equal(drift.status, 'changed')
  assert.ok(drift.changes.some((c) => c.field === 'load'))
})

test('diffHost: a new listening port is reported as added', () => {
  const before = host('a', { listening: [{ port: 22, process: 'sshd' }] })
  const after = host('a', { listening: [{ port: 22, process: 'sshd' }, { port: 8080, process: 'java' }] })
  const drift = diffHost(before, after)
  assert.equal(drift.status, 'changed')
  const added = drift.changes.find((c) => c.field === 'added')
  assert.notEqual(added, undefined)
  assert.ok(added.after.includes('8080'))
})

test('diffHost: a removed listening port is reported', () => {
  const before = host('a', { listening: [{ port: 22, process: 'sshd' }, { port: 8080, process: 'java' }] })
  const after = host('a', { listening: [{ port: 22, process: 'sshd' }] })
  const drift = diffHost(before, after)
  const removed = drift.changes.find((c) => c.field === 'removed')
  assert.notEqual(removed, undefined)
  assert.ok(removed.before.includes('8080'))
})

test('diffHost: an unreachable host is reported as unreachable, not unchanged', () => {
  const drift = diffHost(host('a'), host('a', { reachable: false }))
  assert.equal(drift.status, 'unreachable')
  assert.notEqual(drift.changes.length, 0)
})

test('diffHost: a disk usage change is reported', () => {
  const drift = diffHost(host('a', { disks: [{ mount: '/', usePct: 40 }] }), host('a', { disks: [{ mount: '/', usePct: 92 }] }))
  assert.equal(drift.status, 'changed')
  assert.ok(drift.changes.some((c) => c.after.includes('92')))
})

test('diffHost: service set changes are reported', () => {
  const drift = diffHost(host('a', { services: ['nginx'] }), host('a', { services: ['nginx', 'redis'] }))
  assert.ok(drift.changes.some((c) => c.field === 'services.added'))
})

test('diffBaseline: summarises changed / unchanged / unreachable counts', () => {
  const baseline = {
    name: 'b',
    createdAt: '2026-09-10T00:00:00Z',
    profile: 'full',
    targets: ['a', 'b', 'c'],
    hosts: [host('a'), host('b'), host('c')],
  }
  const current = [
    host('a'),
    host('b', { memoryUsedPct: 90 }),
    host('c', { reachable: false }),
  ]
  const drift = diffBaseline(baseline, current, '2026-09-11T00:00:00Z')
  assert.equal(drift.changed, 1)
  assert.equal(drift.unchanged, 1)
  assert.equal(drift.unreachable, 1)
})

test('diffBaseline: a target present now but absent from the baseline is "added"', () => {
  const baseline = { name: 'b', createdAt: '', profile: 'full', targets: ['a'], hosts: [host('a')] }
  const drift = diffBaseline(baseline, [host('a'), host('new')], 'now')
  assert.ok(drift.hosts.some((h) => h.target === 'new' && h.status === 'added'))
})
