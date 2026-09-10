/**
 * V0.4.2: target scope guard. Deny wins over allow, matching is a case-insensitive
 * substring, and an empty/blank target is always allowed (nothing to gate).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { requireTargetAllowed } from '../../lib/security/target-scope.js'

function denied(cfg, target) {
  try {
    requireTargetAllowed(cfg, target)
    return null
  } catch (error) {
    return error
  }
}

test('no lists configured => everything is allowed', () => {
  assert.equal(denied({}, '10.0.0.1'), null)
  assert.equal(denied({ allowedTargets: [], deniedTargets: [] }, '10.0.0.1'), null)
})

test('deniedTargets blocks by substring, case-insensitively', () => {
  const err = denied({ deniedTargets: ['db-prod'] }, 'DB-PROD-01')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')
  assert.match(err.message, /deniedTargets/)
})

test('an IP prefix denies the whole subnet', () => {
  const err = denied({ deniedTargets: ['192.168.79.'] }, '192.168.79.55')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')
})

test('deny wins even when the target is also on the allow-list', () => {
  const err = denied({ allowedTargets: ['oa-'], deniedTargets: ['oa-legacy'] }, 'oa-legacy-2')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')
  assert.match(err.message, /deniedTargets/)
})

test('an allow-list rejects anything that does not match', () => {
  const err = denied({ allowedTargets: ['192.168.79.', 'oa-'] }, '10.20.30.40')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')
  assert.match(err.message, /allowedTargets/)
})

test('an allow-list accepts a matching target', () => {
  assert.equal(denied({ allowedTargets: ['192.168.79.'] }, '192.168.79.10'), null)
  assert.equal(denied({ allowedTargets: ['OA-'] }, 'oa-portal-01'), null)
})

test('blank / missing targets are never gated (connect has no target yet)', () => {
  assert.equal(denied({ allowedTargets: ['x'], deniedTargets: ['y'] }, null), null)
  assert.equal(denied({ allowedTargets: ['x'], deniedTargets: ['y'] }, undefined), null)
  assert.equal(denied({ allowedTargets: ['x'], deniedTargets: ['y'] }, '   '), null)
})

test('blank entries never act as a wildcard match', () => {
  // A configured-but-blank allow-list is treated as "configured": the blank
  // entry matches nothing, so the target is refused. Failing closed is the
  // safe direction here — a blank rule must not silently allow the world.
  const err = denied({ allowedTargets: ['', '  '] }, 'anything')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')

  // A blank entry in the DENY list must not deny everything either.
  assert.equal(denied({ deniedTargets: ['', '  '] }, 'anything'), null)
})
