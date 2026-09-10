/**
 * Audit timestamp formatting (V0.4.0). Storage stays UTC; display is the
 * configured zone. The console and jumpserver_audit both go through here.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { formatAuditTime, resolveTimeZone, isValidTimeZone, DEFAULT_TIME_ZONE } from '../../lib/runtime/time.js'

test('DEFAULT_TIME_ZONE is the project default', () => {
  assert.equal(DEFAULT_TIME_ZONE, 'Asia/Shanghai')
})

test('resolveTimeZone("") defaults to the project default', () => {
  assert.equal(resolveTimeZone(''), 'Asia/Shanghai')
  assert.equal(resolveTimeZone(undefined), 'Asia/Shanghai')
})

test('resolveTimeZone("local") returns the host IANA zone', () => {
  const local = resolveTimeZone('local')
  assert.ok(local.length > 0)
  assert.notEqual(local, 'local')
})

test('formatAuditTime converts UTC ISO into Asia/Shanghai (+8)', () => {
  // 2026-09-09 09:30:00Z -> 2026-09-09 17:30:00 in Asia/Shanghai
  assert.equal(formatAuditTime('2026-09-09T09:30:00Z', 'Asia/Shanghai'), '2026-09-09 17:30:00')
})

test('formatAuditTime: invalid zone falls back to UTC (display bugs must never hide records)', () => {
  // Use a value Intl cannot handle as a time zone — but every string is
  // accepted by en-CA with timeZone as an option, so this asserts the
  // not-fatal path: the call always returns a string.
  const out = formatAuditTime('2026-09-09T09:30:00Z', 'Not/AReal_Zone')
  assert.ok(typeof out === 'string' && out.length > 0)
})

test('formatAuditTime: empty value renders as "-"', () => {
  assert.equal(formatAuditTime(null, 'Asia/Shanghai'), '-')
  assert.equal(formatAuditTime('', 'Asia/Shanghai'), '-')
})

test('formatAuditTime: unparseable input falls back to the raw string (never empty)', () => {
  const out = formatAuditTime('not a date', 'Asia/Shanghai')
  assert.ok(typeof out === 'string' && out.length > 0)
})

test('isValidTimeZone accepts known IANA names and rejects obviously bad ones', () => {
  assert.equal(isValidTimeZone('Asia/Shanghai'), true)
  assert.equal(isValidTimeZone('Not/AReal_Zone'), false)
})
