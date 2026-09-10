/**
 * Multi-host comparison (V0.4.1).
 *
 * The diff must be order-insensitive (diagnostic output is not stably ordered)
 * but must still flag a real content difference. A failed target must never be
 * counted as "identical".
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeLines, groupBySignature } from '../../lib/jumpserver/compare.js'

const target = (name, lines, ok = true) => ({ target: name, hostname: name, ok, exitCode: 0, error: null, durationMs: 0, lines, truncated: false })

test('normalizeLines drops blank lines and collapses internal whitespace', () => {
  const lines = normalizeLines('a   b\n\n  \nc\td\n')
  assert.deepEqual(lines, ['a b', 'c d'])
})

test('normalizeLines can keep blank lines when ignoreBlank=false', () => {
  const lines = normalizeLines('a\n\nb', { ignoreBlank: false })
  assert.deepEqual(lines, ['a', '', 'b'])
})

test('normalizeLines strips configured prefixes before comparing', () => {
  const lines = normalizeLines('2026-09-10 a\n2026-09-10 b', { stripPrefixes: ['2026-09-10 '] })
  assert.deepEqual(lines, ['a', 'b'])
})

test('groupBySignature: identical line sets collapse into ONE group (order-insensitive)', () => {
  const a = target('a', ['x', 'y', 'z'])
  const b = target('b', ['z', 'y', 'x'])
  const c = target('c', ['y', 'z', 'x'])
  const { distinct, groups } = groupBySignature([a, b, c])
  assert.equal(distinct, 1)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].outliers.length, 0)
})

test('groupBySignature: an outlier is reported with missing and extra lines vs the majority', () => {
  const a = target('a', ['x', 'y'])
  const b = target('b', ['x', 'y'])
  const c = target('c', ['x', 'y', 'z']) // extra z
  const { distinct, groups } = groupBySignature([a, b, c])
  assert.equal(distinct, 2)
  const majority = groups[0]
  assert.equal(majority.outliers.length, 1)
  assert.equal(majority.outliers[0].target, 'c')
  assert.deepEqual(majority.outliers[0].extra, ['z'])
  assert.deepEqual(majority.outliers[0].missing, [])
})

test('groupBySignature: missing lines are reported for a host lacking a shared line', () => {
  const a = target('a', ['x', 'y', 'z'])
  const b = target('b', ['x', 'y', 'z'])
  const c = target('c', ['x', 'y'])
  const { groups } = groupBySignature([a, b, c])
  const outlier = groups[0].outliers.find((o) => o.target === 'c')
  assert.notEqual(outlier, undefined)
  assert.deepEqual(outlier.missing, ['z'])
  assert.deepEqual(outlier.extra, [])
})

test('groupBySignature: a failed target is excluded, never treated as identical', () => {
  const a = target('a', ['x'])
  const b = target('b', ['x'])
  const dead = target('dead', [], false)
  const { distinct, groups } = groupBySignature([a, b, dead])
  assert.equal(distinct, 1)
  assert.equal(groups[0].outliers.length, 0)
  // the dead target is not a member of any group
  const members = groups.flatMap((g) => g.outliers.map((o) => o.target))
  assert.ok(!members.includes('dead'))
})

test('groupBySignature: no successful targets yields zero groups', () => {
  const { distinct, groups } = groupBySignature([target('dead', [], false)])
  assert.equal(distinct, 0)
  assert.deepEqual(groups, [])
})

test('groupBySignature: duplicate lines within a target do not create a false outlier', () => {
  const a = target('a', ['x', 'x', 'y'])
  const b = target('b', ['x', 'y'])
  const { distinct } = groupBySignature([a, b])
  assert.equal(distinct, 1)
})
