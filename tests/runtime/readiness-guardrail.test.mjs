/**
 * V0.7.1 (D-9/D-10): readiness + the dangerous-command guardrail.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  computeReadiness,
  consoleUrlOf,
  parseEndpointHostPort,
  readConsoleInstances,
} from '../../lib/runtime/readiness.js'
import { applyGuardrail, estimateImpact, DEFAULT_DANGEROUS_TIMEOUT_MS, DEFAULT_UNKNOWN_TIMEOUT_MS } from '../../lib/security/guardrail.js'

// ---------------------------------------------------------------- D-9

test('D-9: a fresh discovery file is a LIVE console instance', () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-ready-'))
  try {
    writeFileSync(join(dir, '1234.json'), JSON.stringify({
      pid: 1234,
      port: 8765,
      role: 'owner',
      startedAt: new Date().toISOString(),
      heartbeatAt: new Date().toISOString(),
      summary: { state: 'ASSET_SHELL', target: '192.168.1.1', sessions: 1 },
    }))
    const { live, stale } = readConsoleInstances(dir)
    assert.equal(live.length, 1)
    assert.equal(live[0].pid, 1234)
    assert.equal(live[0].port, 8765)
    assert.equal(live[0].target, '192.168.1.1')
    assert.equal(stale.length, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-9: a stale discovery file belongs to a dead process', () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-ready-'))
  try {
    const old = new Date(Date.now() - 120_000).toISOString()
    writeFileSync(join(dir, '999.json'), JSON.stringify({ pid: 999, port: 8765, heartbeatAt: old }))
    const { live, stale } = readConsoleInstances(dir)
    assert.equal(live.length, 0)
    assert.equal(stale.length, 1)
    assert.equal(stale[0].pid, 999)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-9: a missing console directory is not an error', () => {
  const { live, stale } = readConsoleInstances(join(tmpdir(), 'js-ready-does-not-exist-' + String(process.pid)))
  assert.equal(live.length, 0)
  assert.equal(stale.length, 0)
})

test('D-9: a broken discovery file is skipped, not fatal', () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-ready-'))
  try {
    writeFileSync(join(dir, 'bad.json'), '{not json')
    const { live } = readConsoleInstances(dir)
    assert.equal(live.length, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-9: the console URL pins the instance pid', () => {
  const { live } = (() => {
    const dir = mkdtempSync(join(tmpdir(), 'js-ready-'))
    writeFileSync(join(dir, '4321.json'), JSON.stringify({
      pid: 4321, port: 8765, role: 'owner', heartbeatAt: new Date().toISOString(),
    }))
    const result = readConsoleInstances(dir)
    rmSync(dir, { recursive: true, force: true })
    return result
  })()
  assert.equal(consoleUrlOf(live[0]), 'http://127.0.0.1:8765/?inst=4321')
})

test('D-9: READY — the bastion is reachable and the scope allows a target', async () => {
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 134,
    probe: async () => 'reachable',
  })
  assert.equal(report.verdict, 'ready')
  assert.equal(report.gateway, 'reachable')
  assert.equal(report.allowedTargets, 134)
})

test('D-9: NOT READY — the bastion is unreachable', async () => {
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 134,
    probe: async () => 'unreachable',
  })
  assert.equal(report.verdict, 'not-ready')
  assert.ok(report.reason.includes('bastion'))
})

test('D-9: an EMPTY allow list means NO RESTRICTION, not "nothing is allowed"', async () => {
  // target-scope.ts: an empty allowedTargets passes EVERY target. Treating
  // it as "the scope allows nothing" would have told every operator with an
  // unrestricted deployment that the connector was broken.
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 0,
    deniedTargets: 0,
    probe: async () => 'reachable',
  })
  assert.equal(report.verdict, 'ready')
})

test('D-9: NOT READY — no bastion address is configured (a CONFIG blocker)', async () => {
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '',
    gatewayPort: 2222,
    allowedTargets: 134,
    probe: async () => 'unknown',
  })
  assert.equal(report.verdict, 'not-ready')
  assert.equal(report.blockerIsConfig, true, 'a missing address is a configuration problem')
})

test('D-9: an unreachable bastion is NOT a configuration blocker', async () => {
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 134,
    probe: async () => 'unreachable',
  })
  assert.equal(report.verdict, 'not-ready')
  assert.equal(report.blockerIsConfig, false, 'a network condition must not fail the configuration verdict')
})

test('D-9: DEGRADED — a stale console discovery file (a dead process)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-ready-'))
  try {
    writeFileSync(join(dir, '999.json'), JSON.stringify({
      pid: 999, port: 8765, heartbeatAt: new Date(Date.now() - 120_000).toISOString(),
    }))
    const report = await computeReadiness({
      consoleDir: dir,
      gatewayHost: '192.168.74.130',
      gatewayPort: 2222,
      allowedTargets: 10,
      probe: async () => 'reachable',
    })
    assert.equal(report.verdict, 'degraded')
    assert.equal(report.staleConsoles.length, 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-9: a MISSING console is not a degradation (doctor runs standalone)', async () => {
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 10,
    probe: async () => 'reachable',
  })
  assert.equal(report.verdict, 'ready')
  assert.equal(report.consoleUrl, null)
})

test('D-9: DEGRADED — the risk judge is unreachable', async () => {
  const report = await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 10,
    judgeEnabled: true,
    judgeHost: 'api.typesafe.ai',
    judgePort: 443,
    probe: async (host) => (host === 'api.typesafe.ai' ? 'unreachable' : 'reachable'),
  })
  assert.equal(report.verdict, 'degraded')
  assert.equal(report.judge, 'unreachable')
})

test('D-9: the judge is not probed when it is disabled', async () => {
  const probed = []
  await computeReadiness({
    consoleDir: join(tmpdir(), 'js-ready-none-' + String(process.pid)),
    gatewayHost: '192.168.74.130',
    gatewayPort: 2222,
    allowedTargets: 10,
    judgeEnabled: false,
    probe: async (host) => { probed.push(host); return 'reachable' },
  })
  assert.deepEqual(probed, ['192.168.74.130'])
})

test('D-9: the endpoint host and port are parsed, with the scheme default', () => {
  assert.deepEqual(parseEndpointHostPort('https://api.typesafe.ai/v1/systemone'), { host: 'api.typesafe.ai', port: 443 })
  assert.deepEqual(parseEndpointHostPort('http://example.com:8080/x'), { host: 'example.com', port: 8080 })
  assert.equal(parseEndpointHostPort('not-a-url'), null)
  assert.equal(parseEndpointHostPort(''), null)
})

// ---------------------------------------------------------------- D-10

test('D-10: a READ command is NEVER capped', () => {
  const d = applyGuardrail('READ', 'cat /var/log/big.log', 600000, 60000)
  assert.equal(d.timeoutMs, 600000)
  assert.equal(d.capped, false)
  assert.equal(d.impact, null)
})

test('D-10: a DANGEROUS command is capped', () => {
  const d = applyGuardrail('DANGEROUS', 'rm -rf /data/*', 600000, 60000)
  assert.equal(d.timeoutMs, DEFAULT_DANGEROUS_TIMEOUT_MS)
  assert.equal(d.capped, true)
})

test('D-10: an UNKNOWN command gets the tighter cap', () => {
  const d = applyGuardrail('UNKNOWN', 'some-weird-thing --go', 600000, 60000)
  assert.equal(d.timeoutMs, DEFAULT_UNKNOWN_TIMEOUT_MS)
  assert.equal(d.capped, true)
})

test('D-10: the cap never RAISES a shorter requested timeout', () => {
  const d = applyGuardrail('DANGEROUS', 'rm -rf /data/*', 5000, 60000)
  assert.equal(d.timeoutMs, 5000)
  assert.equal(d.capped, false)
})

test('D-10: the impact hint counts the lines when the command says so', () => {
  const h = estimateImpact('tail -n 100 /var/log/app.log')
  assert.equal(h.estimatedLines, 100)
  assert.ok(h.basis.includes('tail'))
})

test('D-10: a sed range is understood', () => {
  const h = estimateImpact("sed -i '10,20d' /etc/hosts")
  assert.equal(h.estimatedLines, 11)
})

test('D-10: a destructive command is flagged', () => {
  const h = estimateImpact('rm -rf /var/data')
  assert.equal(h.destructive, true)
  assert.ok(h.summary.includes('删除'))
})

test('D-10: an in-place write is flagged', () => {
  const h = estimateImpact("sed -i 's/a/b/' /etc/hosts")
  assert.equal(h.writesInPlace, true)
})

test('D-10: a filesystem walk is flagged', () => {
  const h = estimateImpact("find / -name '*.log' -delete")
  assert.equal(h.walksFilesystem, true)
  assert.ok(h.basis.includes('filesystem') || h.basis.includes('遍历'))
})

test('D-10: the estimate is labelled — it is never presented as a measured fact', () => {
  const h = estimateImpact('rm -rf /')
  assert.equal(h.estimatedLines, null)
  assert.ok(h.basis.length > 0, 'the basis must always be explained')
})

test('D-10: the note always says what the guardrail did', () => {
  const d = applyGuardrail('DANGEROUS', 'rm -rf /data/*', 600000, 60000)
  assert.ok(d.note.includes('影响面'))
  assert.ok(d.note.includes('护栏'))
})

test('D-10: a READ command produces no note at all', () => {
  const d = applyGuardrail('READ', 'ls -la', undefined, 60000)
  assert.equal(d.note, null)
  assert.equal(d.timeoutMs, 60000)
})
