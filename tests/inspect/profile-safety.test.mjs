/**
 * Profile-safety: every command the inspector might run on a target must be
 * classified READ by the time the test runs. A profile that regresses to a
 * non-READ rule MUST be rejected by the inspector (and the failure is
 * surfaced here, not silently "probably fine" in production).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyCommand } from '../../lib/security/command-classifier.js'
import { PROFILE_STEPS, INSPECT_PROFILES, resolveProfile } from '../../lib/jumpserver/profiles.js'

test('every inspect profile command is READ', () => {
  for (const name of INSPECT_PROFILES) {
    if (name === 'full') continue
    const steps = PROFILE_STEPS[name]
    for (const step of steps) {
      const r = classifyCommand(step.command)
      assert.equal(r.risk, 'READ', 'profile=' + name + ' step=' + step.id + ' command=' + step.command + ' classified ' + r.risk + ' (' + r.ruleId + ')')
    }
  }
})

test('resolveProfile("full") is the union of every other profile', () => {
  const full = resolveProfile('full')
  const union = new Set()
  for (const name of INSPECT_PROFILES) {
    if (name === 'full') continue
    for (const step of PROFILE_STEPS[name]) union.add(step.id + ' ' + step.command)
  }
  const got = new Set()
  for (const step of full.steps) got.add(step.id + ' ' + step.command)
  assert.equal(got.size, union.size, 'full profile is not the union of all other profiles')
  for (const item of union) assert.ok(got.has(item))
})

test('resolveProfile: unknown profile is reported, basic is used as fallback', () => {
  const r = resolveProfile(['network', 'does-not-exist'])
  assert.deepEqual(r.unknown, ['does-not-exist'])
  assert.ok(r.used.includes('network'))
})

test('resolveProfile: same probe appears at most once (first occurrence wins)', () => {
  const r = resolveProfile(['network', 'process', 'web'])
  const ps = r.steps.filter((s) => s.id === 'ps')
  assert.equal(ps.length, 1)
})
