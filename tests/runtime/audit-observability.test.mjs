/**
 * V0.7.1 (D-6/D-7/D-8): audit observability.
 *
 *   D-6  every failure record carries a machine-readable errorCode
 *   D-7  the audit file rotates per day, with retention and daily aggregates
 *   D-8  the failure statistics separate "the command returned non-zero" from
 *        "the operation failed", and an interrupt with no job is not a failure
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { AuditStore, auditDayOf, dailyAuditFileName, dailyMetricsFileName, daysBetween, readJsonlRecords } from '../../lib/runtime/audit-store.js'
import { classifyAuditRecord, computeAuditStats, aggregateDayMetrics } from '../../lib/runtime/audit-metrics.js'

// ---------------------------------------------------------------- D-8

test('D-8: a command that ran and returned non-zero is its OWN class', () => {
  assert.equal(classifyAuditRecord({ result: 'EXIT_NONZERO', exitCode: 127 }), 'exitNonzero')
})

test('D-8: an interrupt with no job behind it is NOT a failure', () => {
  assert.equal(classifyAuditRecord({ result: 'unverified' }), 'unverified')
})

test('D-8: the real failure classes are told apart', () => {
  assert.equal(classifyAuditRecord({ result: 'TIMEOUT' }), 'timeout')
  assert.equal(classifyAuditRecord({ result: 'CONNECTION_LOST' }), 'connectionLost')
  assert.equal(classifyAuditRecord({ result: 'DENIED' }), 'denied')
  assert.equal(classifyAuditRecord({ result: 'BLOCKED' }), 'blocked')
  assert.equal(classifyAuditRecord({ result: 'error' }), 'error')
  assert.equal(classifyAuditRecord({ result: 'UNKNOWN' }), 'unknown')
  assert.equal(classifyAuditRecord({ result: 'SUCCESS' }), 'success')
  assert.equal(classifyAuditRecord({ result: 'ok' }), 'success')
})

test('D-8: a pending approval is its own class', () => {
  assert.equal(
    classifyAuditRecord({ result: 'COMPLETED', approvalRequired: true, approvalResult: 'pending' }),
    'pendingApproval',
  )
})

test('D-8: the exit code decides for pre-V0.4.3 records', () => {
  assert.equal(classifyAuditRecord({ result: 'COMPLETED', exitCode: 0 }), 'success')
  assert.equal(classifyAuditRecord({ result: 'COMPLETED', exitCode: 127 }), 'exitNonzero')
})

test('D-8: the D-6 errorCode is used when the status is unknown', () => {
  assert.equal(classifyAuditRecord({ result: 'weird', errorCode: 'APPROVAL_DENIED' }), 'denied')
  assert.equal(classifyAuditRecord({ result: 'weird', errorCode: 'COMMAND_TIMEOUT' }), 'timeout')
  assert.equal(classifyAuditRecord({ result: 'weird', errorCode: 'COMMAND_BLOCKED' }), 'blocked')
})

test('D-8: the failure rate EXCLUDES exit-non-zero and unverified', () => {
  const records = [
    { result: 'SUCCESS' },
    { result: 'EXIT_NONZERO', exitCode: 1 },
    { result: 'unverified' },
    { result: 'TIMEOUT' },
  ]
  const stats = computeAuditStats(records)
  assert.equal(stats.total, 4)
  assert.equal(stats.failed, 1, 'only the timeout is an operation failure')
  assert.equal(stats.exitNonzero, 1)
  assert.equal(stats.unverified, 1)
  assert.equal(stats.failedIncludingExitNonzero, 2)
  assert.equal(stats.failureRate, 0.25)
})

test('D-8: the by-class breakdown counts every record', () => {
  const stats = computeAuditStats([{ result: 'SUCCESS' }, { result: 'EXIT_NONZERO' }, { result: 'TIMEOUT' }])
  assert.equal(stats.byClass.success, 1)
  assert.equal(stats.byClass.exitNonzero, 1)
  assert.equal(stats.byClass.timeout, 1)
})

test('D-8: the errorCode breakdown is reported', () => {
  const stats = computeAuditStats([
    { result: 'EXIT_NONZERO', errorCode: 'COMMAND_EXIT_NONZERO' },
    { result: 'EXIT_NONZERO', errorCode: 'COMMAND_EXIT_NONZERO' },
    { result: 'TIMEOUT', errorCode: 'COMMAND_TIMEOUT' },
  ])
  assert.equal(stats.byErrorCode.COMMAND_EXIT_NONZERO, 2)
  assert.equal(stats.byErrorCode.COMMAND_TIMEOUT, 1)
})

test('D-8: the failure rate of an empty set is 0, not NaN', () => {
  const stats = computeAuditStats([])
  assert.equal(stats.failureRate, 0)
  assert.equal(stats.total, 0)
})

// ---------------------------------------------------------------- D-7

test('D-7: the audit file rotates per day and the day file holds every record', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-audit-'))
  try {
    const file = join(dir, 'audit.jsonl')
    const store = new AuditStore(file, { retainDays: 30 })
    store.append({ timestamp: '2026-10-22T10:00:00.000Z', operation: 'run', result: 'SUCCESS' })
    store.append({ timestamp: '2026-10-22T10:00:01.000Z', operation: 'exec', result: 'EXIT_NONZERO', errorCode: 'COMMAND_EXIT_NONZERO' })
    await store.flush()

    const result = await store.rotateForDay('2026-10-22')
    assert.equal(result.rotated, true)
    assert.equal(result.path, dailyAuditFileName(dir, '2026-10-22'))
    assert.ok(existsSync(result.path), 'the daily file must exist')

    const records = readJsonlRecords(result.path)
    assert.equal(records.length, 2)
    assert.equal(records[0].operation, 'run')
    assert.ok(!existsSync(file), 'the live file is renamed away')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-7: the daily aggregation file is written next to the day file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-audit-'))
  try {
    const file = join(dir, 'audit.jsonl')
    const store = new AuditStore(file, { retainDays: 30 })
    store.append({ timestamp: '2026-10-22T10:00:00.000Z', operation: 'run', result: 'SUCCESS', risk: 'READ', target: 'a' })
    store.append({ timestamp: '2026-10-22T10:00:01.000Z', operation: 'exec', result: 'TIMEOUT', risk: 'READ', target: 'a' })
    await store.flush()

    const result = await store.rotateForDay('2026-10-22')
    assert.notEqual(result.metricsPath, null)
    const metrics = JSON.parse(readFileSync(result.metricsPath, 'utf8'))
    assert.equal(metrics.date, '2026-10-22')
    assert.equal(metrics.total, 2)
    assert.equal(metrics.failed, 1)
    assert.equal(metrics.exitNonzero, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-7: files older than the retention window are swept', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-audit-'))
  try {
    const file = join(dir, 'audit.jsonl')
    const store = new AuditStore(file, { retainDays: 30 })
    // An old daily file and a recent one.
    writeFileSync(dailyAuditFileName(dir, '2026-01-01'), '{}\n')
    writeFileSync(dailyMetricsFileName(dir, '2026-01-01'), '{}\n')
    writeFileSync(dailyAuditFileName(dir, '2026-10-01'), '{}\n')
    store.append({ timestamp: '2026-10-22T10:00:00.000Z', operation: 'run', result: 'SUCCESS' })
    await store.flush()

    const result = await store.rotateForDay('2026-10-22')
    assert.equal(result.pruned.length, 2, 'both old files must be swept')
    assert.ok(!existsSync(dailyAuditFileName(dir, '2026-01-01')))
    assert.ok(!existsSync(dailyMetricsFileName(dir, '2026-01-01')))
    assert.ok(existsSync(dailyAuditFileName(dir, '2026-10-01')), 'a file inside the window must survive')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-7: the retention sweep NEVER deletes the live file or a manual archive', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-audit-'))
  try {
    const file = join(dir, 'audit.jsonl')
    const store = new AuditStore(file, { retainDays: 1 })
    writeFileSync(join(dir, 'audit.2026-01-01T00-00-00-000Z.jsonl'), '{}\n')
    store.append({ timestamp: '2026-10-22T10:00:00.000Z', operation: 'run', result: 'SUCCESS' })
    await store.flush()

    await store.rotateForDay('2026-10-22')
    assert.ok(existsSync(join(dir, 'audit.2026-01-01T00-00-00-000Z.jsonl')), 'a manual archive must survive')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-7: rotating an empty audit file is a no-op, not an error', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-audit-'))
  try {
    const store = new AuditStore(join(dir, 'audit.jsonl'), { retainDays: 30 })
    const result = await store.rotateForDay('2026-10-22')
    assert.equal(result.rotated, false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-7: the day key helpers are correct', () => {
  assert.equal(auditDayOf({ timestamp: '2026-10-22T10:00:00.000Z' }), '2026-10-22')
  assert.equal(auditDayOf({}), '')
  assert.equal(daysBetween('2026-10-01', '2026-10-22'), 21)
  assert.equal(daysBetween('2026-10-22', '2026-10-22'), 0)
})

test('D-7: the daily metrics carry the top targets only', () => {
  const records = Array.from({ length: 30 }, (_, i) => ({ timestamp: '2026-10-22T10:00:00.000Z', target: 't' + (i % 3), result: 'SUCCESS' }))
  const metrics = aggregateDayMetrics('2026-10-22', records)
  assert.equal(metrics.total, 30)
  assert.ok(Object.keys(metrics.byTarget).length <= 20)
})

test('D-7: the directory only holds the expected daily files after a rotation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-audit-'))
  try {
    const store = new AuditStore(join(dir, 'audit.jsonl'), { retainDays: 30 })
    store.append({ timestamp: '2026-10-22T10:00:00.000Z', operation: 'run', result: 'SUCCESS' })
    await store.flush()
    await store.rotateForDay('2026-10-22')
    const names = readdirSync(dir).sort()
    assert.deepEqual(names, ['audit-2026-10-22.jsonl', 'audit-metrics-2026-10-22.json'])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
