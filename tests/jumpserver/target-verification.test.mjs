/**
 * V0.6.0 (A-2): the target self-verification.
 *
 * The "false success" reported from the CRM rollout: a batch asked for
 * 192.168.30.2, the command landed on a machine whose hostname was
 * `k8s-192-168-30-3`, and the tool reported SUCCESS. The root cause was that
 * entering an asset was accepted as soon as ANY shell prompt appeared — the
 * shell was never asked whether it really sits on the requested machine.
 *
 * These tests pin the pure decision function:
 *   verified   → the shell is provably on the requested asset
 *   unverified → nothing to compare (no evidence) — NOT a failure
 *   mismatch   → the shell is provably on a DIFFERENT asset — a hard failure
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { hostnameEmbeddedIp, isIpv4Literal, verifyTargetIdentity } from '../../lib/jumpserver/target-verify.js'

test('isIpv4Literal accepts only dotted quads', () => {
  assert.equal(isIpv4Literal('192.168.30.2'), true)
  assert.equal(isIpv4Literal('10.0.0.1'), true)
  assert.equal(isIpv4Literal('999.1.1.1'), false)
  assert.equal(isIpv4Literal('192.168.30'), false)
  assert.equal(isIpv4Literal('jsx-node-01'), false)
  assert.equal(isIpv4Literal(''), false)
})

test('hostnameEmbeddedIp extracts the IP a hostname encodes', () => {
  assert.equal(hostnameEmbeddedIp('k8s-192-168-30-3'), '192.168.30.3')
  assert.equal(hostnameEmbeddedIp('web-10-0-0-8'), '10.0.0.8')
  assert.equal(hostnameEmbeddedIp('jsx-app-01'), null)
  assert.equal(hostnameEmbeddedIp(null), null)
})

test('an IP target whose asset reports a different IP is a MISMATCH', () => {
  // The exact false-success case from the CRM rollout.
  const r = verifyTargetIdentity({ target: '192.168.30.2', hostname: 'k8s-192-168-30-3', ips: ['192.168.30.3'] })
  assert.equal(r.status, 'mismatch')
  assert.ok(r.reason.length > 0)
  assert.deepEqual(r.observedIps, ['192.168.30.3'])
})

test('an IP target that IS in the asset address list is VERIFIED', () => {
  const r = verifyTargetIdentity({ target: '192.168.30.2', hostname: 'k8s-192-168-30-2', ips: ['192.168.30.2', '10.0.0.4'] })
  assert.equal(r.status, 'verified')
})

test('an IP target with NO address evidence is UNVERIFIED, never a failure', () => {
  // `hostname -I` does not exist on every host — the check must be skipped,
  // not turned into a false alarm.
  const r = verifyTargetIdentity({ target: '192.168.30.2', hostname: 'jsx-app-01', ips: [] })
  assert.equal(r.status, 'unverified')
})

test('a NAME target with a differing embedded IP stays UNVERIFIED (display name != hostname)', () => {
  // The asset's DISPLAY name in the menu is not necessarily its hostname, so
  // a name↔hostname difference must not be turned into a false alarm.
  const r = verifyTargetIdentity({ target: 'jsx-app-01', hostname: 'k8s-192-168-30-3', ips: ['192.168.30.3'] })
  assert.equal(r.status, 'unverified')
})

test('a NAME target with no comparable evidence is UNVERIFIED', () => {
  const r = verifyTargetIdentity({ target: 'jsx-app-01', hostname: 'jsx-app-01', ips: [] })
  assert.equal(r.status, 'unverified')
})

test('a NAME target whose hostname equals the requested name stays UNVERIFIED (the address list is the only positive witness)', () => {
  const r = verifyTargetIdentity({ target: 'jsx-app-01', hostname: 'jsx-app-01', ips: [] })
  assert.equal(r.status, 'unverified')
})

test('an IP target that IS in the asset address list is VERIFIED even without a hostname', () => {
  const r = verifyTargetIdentity({ target: '192.168.30.3', hostname: null, ips: ['192.168.30.3'] })
  assert.equal(r.status, 'verified')
})

test('the address list alone can prove a MISMATCH (no hostname needed)', () => {
  const r = verifyTargetIdentity({ target: '192.168.30.2', hostname: null, ips: ['192.168.30.3'] })
  assert.equal(r.status, 'mismatch')
})
