/**
 * V0.4.2: target scope guard. Deny wins over allow, matching is a case-insensitive
 * substring, and an empty/blank target is always allowed (nothing to gate).
 *
 * V0.4.3: the plain substring matcher leaked. An exact entry
 * "192.168.79.10" also matched "192.168.79.100". Entries now declare intent:
 * exact / prefix (trailing . - :) / glob (*) / CIDR (/).
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

test('deniedTargets blocks a name prefix, case-insensitively', () => {
  // V0.4.3: a bare entry is EXACT, so a name fragment needs an explicit glob.
  const err = denied({ deniedTargets: ['*db-prod*'] }, 'DB-PROD-01')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')
  assert.match(err.message, /deniedTargets/)

  // A trailing dash is the prefix form.
  const prefix = denied({ deniedTargets: ['db-prod-'] }, 'DB-PROD-01')
  assert.notEqual(prefix, null)
  assert.equal(prefix.code, 'TARGET_DENIED')
})

test('an IP prefix denies the whole subnet', () => {
  const err = denied({ deniedTargets: ['192.168.79.'] }, '192.168.79.55')
  assert.notEqual(err, null)
  assert.equal(err.code, 'TARGET_DENIED')
})

test('deny wins even when the target is also on the allow-list', () => {
  const err = denied({ allowedTargets: ['oa-'], deniedTargets: ['oa-legacy-'] }, 'oa-legacy-2')
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

/* ---------------------------------------------------- V0.4.3 precise scope */

test('an exact IP entry does NOT leak to a longer IP (79.10 vs 79.100)', () => {
  const cfg = { allowedTargets: ['192.168.79.10'] }
  assert.equal(denied(cfg, '192.168.79.10'), null)
  assert.notEqual(denied(cfg, '192.168.79.100'), null)
  assert.notEqual(denied(cfg, '192.168.79.1'), null)
})

test('an exact NAME entry does not match a longer name', () => {
  const cfg = { allowedTargets: ['oa-app-01'] }
  assert.equal(denied(cfg, 'oa-app-01'), null)
  assert.notEqual(denied(cfg, 'oa-app-011'), null)
})

test('a trailing dot keeps the prefix behaviour existing configs rely on', () => {
  const cfg = { allowedTargets: ['192.168.79.'] }
  assert.equal(denied(cfg, '192.168.79.10'), null)
  assert.equal(denied(cfg, '192.168.79.100'), null)
  assert.notEqual(denied(cfg, '192.168.80.1'), null)
})

test('a trailing dash keeps name-prefix behaviour', () => {
  const cfg = { allowedTargets: ['oa-'] }
  assert.equal(denied(cfg, 'oa-app-01'), null)
  assert.notEqual(denied(cfg, 'prod-oa-01'), null)
})

test('an explicit glob matches a name fragment anywhere', () => {
  const cfg = { allowedTargets: ['*oa*'] }
  assert.equal(denied(cfg, 'prod-oa-01'), null)
  assert.notEqual(denied(cfg, 'prod-db-01'), null)
})

test('CIDR entries match by network range', () => {
  const cfg = { allowedTargets: ['192.168.79.0/24'] }
  assert.equal(denied(cfg, '192.168.79.10'), null)
  assert.equal(denied(cfg, '192.168.79.255'), null)
  assert.notEqual(denied(cfg, '192.168.80.1'), null)
  // A /32 is exactly one host.
  assert.equal(denied({ allowedTargets: ['10.0.0.5/32'] }, '10.0.0.5'), null)
  assert.notEqual(denied({ allowedTargets: ['10.0.0.5/32'] }, '10.0.0.6'), null)
})

test('a CIDR entry never matches a non-IPv4 asset name', () => {
  assert.notEqual(denied({ allowedTargets: ['192.168.79.0/24'] }, 'oa-app-01'), null)
})

test('an exact deny still beats a broader allow', () => {
  const cfg = { allowedTargets: ['192.168.79.0/24'], deniedTargets: ['192.168.79.10'] }
  assert.equal(denied(cfg, '192.168.79.11'), null)
  assert.notEqual(denied(cfg, '192.168.79.10'), null)
})
