/**
 * Runbook planning (V0.4.1).
 *
 * planRunbook is pure: it decides which steps are runnable and which must be
 * SKIPPED. The safety contract is that a non-READ command step is never
 * scheduled — it is reported as skipped with its risk, so a runbook cannot
 * smuggle a mutating command past the classifier.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { planRunbook, resolveRunbook } from '../../lib/jumpserver/runbook.js'
import { JumpServerError } from '../../lib/jumpserver/errors.js'

test('planRunbook: profile step expands into READ probes only', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'host', profile: 'basic' }] })
  assert.equal(plan.runnable, 1)
  assert.equal(plan.skipped, 0)
  assert.ok(plan.steps[0].commands.length > 0)
  assert.equal(plan.steps[0].kind, 'profile')
})

test('planRunbook: a read-only command step is runnable', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'free', command: 'free -m' }] })
  assert.equal(plan.runnable, 1)
  assert.equal(plan.steps[0].skipped, null)
  assert.deepEqual(plan.steps[0].commands, ['free -m'])
})

test('planRunbook: a mutating command step is SKIPPED, never scheduled', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'rm', command: 'rm -rf /tmp/x' }] })
  assert.equal(plan.runnable, 0)
  assert.equal(plan.skipped, 1)
  assert.deepEqual(plan.steps[0].commands, [])
  assert.notEqual(plan.steps[0].skipped, null)
  assert.equal(plan.steps[0].skipped.risk, 'MODIFY')
})

test('planRunbook: a host-destructive command step is SKIPPED as DANGEROUS', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'wipe', command: 'rm -rf /' }] })
  assert.equal(plan.runnable, 0)
  assert.equal(plan.steps[0].skipped.risk, 'DANGEROUS')
})

test('planRunbook: a step with both profile and command is skipped as invalid', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'bad', profile: 'basic', command: 'hostname' }] })
  assert.equal(plan.runnable, 0)
  assert.equal(plan.steps[0].skipped.ruleId, 'runbook.invalid')
})

test('planRunbook: a step with neither profile nor command is skipped as invalid', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'empty' }] })
  assert.equal(plan.runnable, 0)
  assert.equal(plan.steps[0].skipped.ruleId, 'runbook.invalid')
})

test('planRunbook: unknown profile is skipped, not silently defaulted to basic', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'x', profile: 'does-not-exist' }] })
  assert.equal(plan.runnable, 0)
  assert.equal(plan.steps[0].skipped.ruleId, 'runbook.unknown-profile')
})

test('planRunbook: mixed runbook reports runnable and skipped counts', () => {
  const plan = planRunbook('rb', {
    steps: [
      { id: 'a', profile: 'basic' },
      { id: 'b', command: 'rm -rf /' },
      { id: 'c', command: 'uptime' },
    ],
  })
  assert.equal(plan.runnable, 2)
  assert.equal(plan.skipped, 1)
})

test('resolveRunbook: name lookup is case-insensitive', () => {
  const def = resolveRunbook({ 'oa-health': { steps: [{ id: 'a', command: 'uptime' }] } }, 'OA-HEALTH')
  assert.equal(def.steps.length, 1)
})

test('resolveRunbook: unknown name errors with UNKNOWN_RUNBOOK and lists configured names', () => {
  assert.throws(
    () => resolveRunbook({ a: { steps: [{ id: 's', command: 'uptime' }] } }, 'nope'),
    (error) => error instanceof JumpServerError && error.code === 'UNKNOWN_RUNBOOK' && error.message.includes('a'),
  )
})

test('resolveRunbook: no runbooks configured errors clearly', () => {
  assert.throws(
    () => resolveRunbook(undefined, 'x'),
    (error) => error instanceof JumpServerError && error.code === 'UNKNOWN_RUNBOOK',
  )
})
