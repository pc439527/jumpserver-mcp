/**
 * V0.7.1 (D-5): the output normalization layer.
 *
 * The central rule: normalization NEVER rewrites the raw capture. It produces
 * a second VIEW. A normalizer that quietly edits facts is worse than none.
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  compressBlankRuns,
  normalizeForCompare,
  normalizeTimestampText,
  stripIpv4MappedPrefix,
  summarizeOutput,
} from '../../lib/jumpserver/output-normalize.js'
import { normalizeLines } from '../../lib/jumpserver/compare.js'

test('the IPv4-mapped prefix is stripped (same address, two notations)', () => {
  assert.equal(stripIpv4MappedPrefix('[::ffff:192.168.1.10]:443'), '192.168.1.10:443')
  assert.equal(stripIpv4MappedPrefix('::ffff:10.0.0.1'), '10.0.0.1')
})

test('a REAL different address is NOT changed', () => {
  const out = stripIpv4MappedPrefix('connect to 192.168.1.11:443')
  assert.equal(out, 'connect to 192.168.1.11:443')
  assert.ok(out.includes('192.168.1.11'))
})

test('the timestamp keeps the instant but drops the sub-second part and the zone', () => {
  assert.equal(normalizeTimestampText('at 2026-10-23T09:12:33.123+08:00 ok'), 'at 2026-10-23T09:12:33 ok')
  assert.equal(normalizeTimestampText('at 2026-10-23T09:12:33Z ok'), 'at 2026-10-23T09:12:33 ok')
  assert.equal(normalizeTimestampText('at 2026-10-23 09:12:33 ok'), 'at 2026-10-23T09:12:33 ok')
})

test('a non-timestamp is untouched', () => {
  assert.equal(normalizeTimestampText('version 2026-10-23'), 'version 2026-10-23')
})

test('runs of blanks collapse to one space, line breaks survive', () => {
  assert.equal(compressBlankRuns('a    b\t\tc'), 'a b c')
  assert.equal(compressBlankRuns('a  \nb  '), 'a\nb')
})

test('normalizeForCompare applies the whole view', () => {
  const raw = '[::ffff:192.168.1.10]:443   opened   2026-10-23T09:12:33.5+08:00'
  const out = normalizeForCompare(raw)
  assert.ok(out.includes('192.168.1.10:443'))
  assert.ok(!out.includes('::ffff:'))
  assert.ok(out.includes('2026-10-23T09:12:33'))
  assert.ok(!out.includes('  '))
})

test('the input string is never modified', () => {
  const raw = '[::ffff:192.168.1.10]:443'
  normalizeForCompare(raw)
  assert.equal(raw, '[::ffff:192.168.1.10]:443')
})

test('the compare diff no longer reports the IPv4-mapped form as a difference', () => {
  const a = normalizeLines('[::ffff:192.168.1.10]:443')
  const b = normalizeLines('192.168.1.10:443')
  assert.deepEqual(a, b)
})

test('the compare diff still reports a REAL address difference', () => {
  const a = normalizeLines('192.168.1.10:443')
  const b = normalizeLines('192.168.1.11:443')
  assert.notDeepEqual(a, b)
})

test('the compare diff does NOT hide a real timestamp difference by default', () => {
  const a = normalizeLines('2026-10-23T09:12:33.1+08:00')
  const b = normalizeLines('2026-10-23T10:12:33.1+08:00')
  assert.notDeepEqual(a, b)
})

test('the compare diff CAN normalize timestamps when the caller opts in', () => {
  const a = normalizeLines('2026-10-23T09:12:33.1+08:00', { normalizeTimestamps: true })
  const b = normalizeLines('2026-10-23T09:12:33.9+08:00', { normalizeTimestamps: true })
  assert.deepEqual(a, b)
})

test('the digest keeps the head and the tail and counts the rest', () => {
  const text = Array.from({ length: 50 }, (_, i) => 'line ' + String(i)).join('\n')
  const r = summarizeOutput(text, { headLines: 3 })
  assert.ok(r.digest.includes('line 0'))
  assert.ok(r.digest.includes('line 49'))
  assert.ok(r.digest.includes('省略'))
  assert.equal(r.omittedLines, 44)
  assert.equal(r.totalLines, 50)
})

test('the digest of a short output is the output', () => {
  const r = summarizeOutput('only one line')
  assert.ok(r.digest.includes('only one line'))
  assert.equal(r.omittedLines, 0)
})

test('the digest of an empty output is empty', () => {
  const r = summarizeOutput('')
  assert.equal(r.digest, '')
  assert.equal(r.shownLines, 0)
})
