/**
 * V0.4.4: jumpserver_compare consumes commandStatus, not just the error field.
 *
 * Regressions guarded against (v0.4.3):
 *   - A batch whose command exited 127 (command not found) carried no `error`
 *     but did carry commandStatus='EXIT_NONZERO'. compare() only checked
 *     `error !== null` and reported the target as ok=true, then diffed the
 *     "command not found" stderr as if it were healthy output. V0.4.4
 *     treats commandStatus !== 'SUCCESS' as a failed probe and excludes the
 *     target from the majority signature, exactly the V0.4.3 design intent.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { compareTargets } from '../../lib/jumpserver/compare.js'

/**
 * Stand-in for SessionManager. compare() only needs runTargetBatch, status,
 * and the lifecycle hook; everything else is exercised in the full E2E.
 */
function makeFakeManager(perTarget) {
  return {
    runTargetBatch: async ({ target }) => {
      const next = perTarget[target] ?? []
      return {
        target,
        hostname: target + '-host',
        error: null,
        commands: next,
      }
    },
  }
}

const successCmd = {
  command: 'cat /etc/os-release',
  executionState: 'COMPLETED',
  commandStatus: 'SUCCESS',
  exitCode: 0,
  output: 'NAME=Ubuntu\nVERSION=22.04',
  truncated: false,
  durationMs: 12,
  error: null,
}

const exitNonZeroCmd = {
  command: 'jps -lv',
  executionState: 'COMPLETED',
  commandStatus: 'EXIT_NONZERO',
  exitCode: 127,
  output: 'jps: command not found',
  truncated: false,
  durationMs: 8,
  error: null,
}

const timeoutCmd = {
  command: 'cat /etc/hosts',
  executionState: 'TIMEOUT',
  commandStatus: 'TIMEOUT',
  exitCode: null,
  output: '...',
  truncated: true,
  durationMs: 5000,
  error: null,
}

const lostCmd = {
  command: 'ls /',
  executionState: 'UNKNOWN',
  commandStatus: 'CONNECTION_LOST',
  exitCode: null,
  output: '',
  truncated: false,
  durationMs: 0,
  error: null,
}

test('compare: a SUCCESS target is reported as ok=true', async () => {
  const manager = makeFakeManager({
    'oa-1': [{ ...successCmd }],
    'oa-2': [{ ...successCmd, output: 'NAME=Ubuntu\nVERSION=22.04' }],
  })
  const result = await compareTargets(
    manager,
    () => ({}),
    { command: 'cat /etc/os-release', targets: ['oa-1', 'oa-2'] },
  )
  const ok = result.results.filter((t) => t.ok)
  assert.equal(ok.length, 2, 'both healthy targets should be ok=true')
  for (const t of ok) assert.equal(t.exitCode, 0)
})

test('compare: an EXIT_NONZERO target is reported as ok=false and excluded from the majority', async () => {
  const manager = makeFakeManager({
    'oa-1': [{ ...successCmd, output: 'A\nB' }],
    'oa-2': [{ ...successCmd, output: 'A\nB' }],
    'oa-3': [{ ...exitNonZeroCmd }], // "command not found" with no `error` field
  })
  const result = await compareTargets(
    manager,
    () => ({}),
    { command: 'jps -lv', targets: ['oa-1', 'oa-2', 'oa-3'] },
  )
  const failedTarget = result.results.find((t) => t.target === 'oa-3')
  assert.ok(failedTarget !== undefined, 'oa-3 should be in the result list')
  assert.equal(failedTarget.ok, false, 'EXIT_NONZERO must surface as ok=false')
  assert.equal(failedTarget.exitCode, 127, 'the real exit code must be reported')
  // oa-1 + oa-2 are the only healthy ones and agree; oa-3 is excluded from
  // the majority so the diff contains zero missing/extra lines.
  const group = result.groups[0]
  assert.ok(group !== undefined, 'a successful compare must surface a majority group')
  const oa3Diff = (group.outliers ?? []).find((o) => o.target === 'oa-3')
  assert.equal(oa3Diff, undefined, 'a failed target must NOT contribute to the outliers diff')
})

test('compare: a TIMEOUT target is reported as ok=false and excluded from the majority', async () => {
  const manager = makeFakeManager({
    'oa-1': [{ ...successCmd }],
    'oa-2': [{ ...timeoutCmd }],
  })
  const result = await compareTargets(
    manager,
    () => ({}),
    { command: 'cat /etc/hosts', targets: ['oa-1', 'oa-2'] },
  )
  const oa2 = result.results.find((t) => t.target === 'oa-2')
  assert.equal(oa2.ok, false)
  assert.equal(oa2.exitCode, null)
  // V0.4.5 locks the CODE: a timeout is a timeout, not a fake non-zero exit.
  assert.equal(oa2.error?.code, 'COMMAND_TIMEOUT')
  assert.match(String(oa2.error?.message ?? ''), /timed out/)
})

test('compare: a CONNECTION_LOST target is reported as ok=false with its own code', async () => {
  const manager = makeFakeManager({
    'oa-1': [{ ...successCmd }],
    'oa-2': [{ ...lostCmd }],
  })
  const result = await compareTargets(
    manager,
    () => ({}),
    { command: 'ls /', targets: ['oa-1', 'oa-2'] },
  )
  const oa2 = result.results.find((t) => t.target === 'oa-2')
  assert.equal(oa2.ok, false)
  assert.equal(oa2.error?.code, 'CONNECTION_LOST', 'a lost transport must not masquerade as EXIT_NONZERO')
})

test('compare: an EXIT_NONZERO target keeps COMMAND_EXIT_NONZERO', async () => {
  const manager = makeFakeManager({
    'oa-1': [{ ...successCmd }],
    'oa-2': [{ ...exitNonZeroCmd }],
  })
  const result = await compareTargets(
    manager,
    () => ({}),
    { command: 'jps -lv', targets: ['oa-1', 'oa-2'] },
  )
  const oa2 = result.results.find((t) => t.target === 'oa-2')
  assert.equal(oa2.error?.code, 'COMMAND_EXIT_NONZERO')
  assert.match(String(oa2.error?.message ?? ''), /127/)
})
