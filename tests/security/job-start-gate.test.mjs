/**
 * V0.4.3: jumpserver_job_start must share the ONE permission gate.
 *
 * Regression guard: before V0.4.3 the streaming-job tool did its own
 * classify + confirm check. Consequences:
 *   - in READ_ONLY a MODIFY job started anyway when confirm:true was passed;
 *   - the audit hardcoded risk:'READ', so `rm -rf` looked like a read;
 *   - target verification (state===ASSET_SHELL) was never performed.
 *
 * These tests drive the real gateCommandForNavigation with a fake manager, so
 * they assert the actual decision path the tool now uses.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { gateCommandForNavigation } from '../../lib/security/permission-gate.js'

/** A manager standing in for a live ASSET_SHELL session on one target. */
function fakeManager(state = 'ASSET_SHELL', target = '10.0.0.1', hostname = 'oa-app-01') {
  return {
    status: () => ({ state, target, hostname }),
  }
}

function services(permissionMode, manager = fakeManager()) {
  return { getConfig: () => ({ permissionMode }), manager }
}

const exec = (confirm) => ({ name: 'jumpserver_job_start', callId: 'c1', confirm })

test('READ_ONLY + MODIFY + confirm:true => BLOCKED (confirm cannot bypass)', async () => {
  await assert.rejects(
    gateCommandForNavigation(services('READ_ONLY'), exec(true), 'systemctl restart nginx'),
    (err) => err.code === 'COMMAND_BLOCKED',
  )
})

test('READ_ONLY + UNKNOWN + confirm:true => BLOCKED', async () => {
  await assert.rejects(
    gateCommandForNavigation(services('READ_ONLY'), exec(true), './some-opaque-binary --flag'),
    (err) => err.code === 'COMMAND_BLOCKED',
  )
})

test('READ_ONLY + DANGEROUS + confirm:true => BLOCKED', async () => {
  await assert.rejects(
    gateCommandForNavigation(services('READ_ONLY'), exec(true), 'dd if=/dev/zero of=/dev/sda'),
    (err) => err.code === 'COMMAND_BLOCKED',
  )
})

test('AUTO + MODIFY + confirm:false => APPROVAL_REQUIRED (deferred to beforeExec)', async () => {
  // The navigation gate cannot ask before the asset is entered, so the refusal
  // is raised by beforeExec — which is exactly where the job tool awaits it.
  const gated = await gateCommandForNavigation(services('AUTO'), exec(false), 'systemctl restart nginx')
  assert.equal(gated.approvalRequired, true)
  assert.ok(gated.beforeExec !== undefined)
  await assert.rejects(gated.beforeExec(), (err) => err.code === 'COMMAND_APPROVAL_REQUIRED')
})

test('AUTO + MODIFY + confirm:true => allowed AND approvalRequired is recorded', async () => {
  const gated = await gateCommandForNavigation(services('AUTO'), exec(true), 'systemctl restart nginx')
  assert.equal(gated.risk, 'MODIFY')
  assert.equal(gated.approvalRequired, true, 'the audit must record that a human approved this')
  assert.equal(gated.classification.risk, 'MODIFY')
  assert.ok(typeof gated.classification.ruleId === 'string' && gated.classification.ruleId.length > 0)
})

test('AUTO + READ => allowed with no approval', async () => {
  const gated = await gateCommandForNavigation(services('AUTO'), exec(false), 'tail -f /var/log/nginx/access.log')
  assert.equal(gated.risk, 'READ')
  assert.equal(gated.approvalRequired, false)
})

test('FULL_ACCESS + DANGEROUS => still requires approval', async () => {
  const gated = await gateCommandForNavigation(services('FULL_ACCESS'), exec(false), 'dd if=/dev/zero of=/dev/sda')
  assert.equal(gated.risk, 'DANGEROUS')
  assert.equal(gated.approvalRequired, true)
  await assert.rejects(gated.beforeExec(), (err) => err.code === 'COMMAND_APPROVAL_REQUIRED')

  // And once the human confirms, the same call is allowed — still flagged.
  const confirmed = await gateCommandForNavigation(services('FULL_ACCESS'), exec(true), 'dd if=/dev/zero of=/dev/sda')
  assert.equal(confirmed.risk, 'DANGEROUS')
  assert.equal(confirmed.approvalRequired, true)
  await assert.doesNotReject(confirmed.beforeExec())
})

test('AUTO + MODIFY on an unverified target => approval path verifies first', async () => {
  // The session is still at the JumpServer menu: the target is not verified,
  // so beforeExec must refuse before any approval can be granted.
  const manager = fakeManager('JUMPSERVER_MENU', null, null)
  const gated = await gateCommandForNavigation(services('AUTO', manager), exec(true), 'systemctl restart nginx')
  assert.equal(gated.approvalRequired, true)
  assert.ok(gated.beforeExec !== undefined, 'a navigation gate must defer verification to beforeExec')
  await assert.rejects(gated.beforeExec(), (err) => err.code === 'TARGET_VERIFICATION_FAILED')
})
