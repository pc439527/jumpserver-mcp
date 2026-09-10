/**
 * Permission gate + target scope tests (V0.4.0).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { gateDecision } from '../../lib/security/permission.js'
import { requireTargetAllowed } from '../../lib/security/target-scope.js'

const MATRIX = [
  // [risk, mode, expected kind, expected code?, privilegedReadInReadOnly?]
  ['READ', 'READ_ONLY', 'allow'],
  ['PRIVILEGED_READ', 'READ_ONLY', 'deny', 'COMMAND_BLOCKED'],
  ['PRIVILEGED_READ', 'READ_ONLY', 'allow', undefined, true], // with privilegedReadInReadOnly
  ['UNKNOWN', 'READ_ONLY', 'deny', 'COMMAND_BLOCKED'],
  ['MODIFY', 'READ_ONLY', 'deny', 'COMMAND_BLOCKED'],
  ['DANGEROUS', 'READ_ONLY', 'deny', 'COMMAND_BLOCKED'],

  ['READ', 'AUTO', 'allow'],
  ['PRIVILEGED_READ', 'AUTO', 'allow'],
  ['UNKNOWN', 'AUTO', 'deny', 'COMMAND_APPROVAL_REQUIRED'],
  ['MODIFY', 'AUTO', 'deny', 'COMMAND_APPROVAL_REQUIRED'],
  ['DANGEROUS', 'AUTO', 'deny', 'COMMAND_APPROVAL_REQUIRED'],

  ['READ', 'FULL_ACCESS', 'allow'],
  ['PRIVILEGED_READ', 'FULL_ACCESS', 'allow'],
  ['UNKNOWN', 'FULL_ACCESS', 'deny', 'COMMAND_APPROVAL_REQUIRED'],
  ['MODIFY', 'FULL_ACCESS', 'allow'],
  // V0.4.0: DANGEROUS must always be approval-gated, even in FULL_ACCESS.
  ['DANGEROUS', 'FULL_ACCESS', 'deny', 'COMMAND_APPROVAL_REQUIRED'],
]

for (const [risk, mode, kind, code, priv] of MATRIX) {
  test('gateDecision: ' + risk + ' in ' + mode + (priv ? ' (priv)' : '') + ' => ' + kind, () => {
    const d = gateDecision(risk, mode, { privilegedReadInReadOnly: priv === true })
    assert.equal(d.kind, kind)
    if (code !== undefined) assert.equal(d.code, code)
  })
}

test('requireTargetAllowed: empty target is a no-op', () => {
  assert.doesNotThrow(() => requireTargetAllowed({}, null))
  assert.doesNotThrow(() => requireTargetAllowed({ allowedTargets: ['192.168.79.'] }, ''))
})

test('requireTargetAllowed: deny always wins', () => {
  const cfg = { allowedTargets: ['192.168.79.'], deniedTargets: ['101'] }
  assert.throws(
    () => requireTargetAllowed(cfg, '192.168.79.101'),
    (err) => err.code === 'TARGET_DENIED',
  )
})

test('requireTargetAllowed: substring allow', () => {
  const cfg = { allowedTargets: ['oa-', '192.168.79.'] }
  assert.doesNotThrow(() => requireTargetAllowed(cfg, 'oa-app-01'))
  assert.doesNotThrow(() => requireTargetAllowed(cfg, '192.168.79.99'))
  assert.throws(
    () => requireTargetAllowed(cfg, '192.168.80.99'),
    (err) => err.code === 'TARGET_DENIED',
  )
})

test('requireTargetAllowed: unrestricted when neither list is set', () => {
  assert.doesNotThrow(() => requireTargetAllowed({}, '10.0.0.1'))
})
