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
import { evaluateExpect, planRunbook, resolveRunbook } from '../../lib/jumpserver/runbook.js'
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

/* ------------------------------------------------------------------ V0.4.2 */
/* evaluateExpect: turn collected output into a PASS/FAIL judgement. */

const OK = { output: 'up\nnginx 1\nLISTEN 0 128\n', exitCode: 0, error: null }

test('evaluateExpect: null expect means nothing is judged', () => {
  assert.equal(evaluateExpect(undefined, OK), null)
})

test('evaluateExpect: contains / notContains are case-insensitive', () => {
  assert.equal(evaluateExpect({ contains: 'LISTEN' }, OK).verdict, 'pass')
  assert.equal(evaluateExpect({ contains: 'listen' }, OK).verdict, 'pass')
  const miss = evaluateExpect({ contains: 'nginx' }, { ...OK, output: 'nothing here' })
  assert.equal(miss.verdict, 'fail')
  assert.match(miss.failures[0], /missing "nginx"/)
  assert.equal(evaluateExpect({ notContains: 'ERROR' }, OK).verdict, 'pass')
  assert.equal(evaluateExpect({ notContains: 'listen' }, OK).verdict, 'fail')
})

test('evaluateExpect: regex matching, and a bad regex is a failure not a throw', () => {
  assert.equal(evaluateExpect({ matches: 'listen[ ]+0' }, OK).verdict, 'pass')
  const bad = evaluateExpect({ matches: '([' }, OK)
  assert.equal(bad.verdict, 'fail')
  assert.match(bad.failures[0], /invalid regex/)
})

test('evaluateExpect: exitCode is compared exactly', () => {
  assert.equal(evaluateExpect({ exitCode: 0 }, OK).verdict, 'pass')
  assert.equal(evaluateExpect({ exitCode: 1 }, OK).verdict, 'fail')
  // exitCode null (timed out / unknown) never equals a number
  assert.equal(evaluateExpect({ exitCode: 0 }, { ...OK, exitCode: null }).verdict, 'fail')
})

test('evaluateExpect: notEmpty and minLines count non-blank lines', () => {
  assert.equal(evaluateExpect({ notEmpty: true }, OK).verdict, 'pass')
  assert.equal(evaluateExpect({ notEmpty: true }, { ...OK, output: '   \n\n' }).verdict, 'fail')
  assert.equal(evaluateExpect({ minLines: 3 }, OK).verdict, 'pass')
  assert.equal(evaluateExpect({ minLines: 4 }, OK).verdict, 'fail')
})

test('evaluateExpect: a step that could not run always fails its assertions', () => {
  const check = evaluateExpect({ contains: 'anything' }, { output: '', exitCode: null, error: { code: 'TIMEOUT', message: 'took too long' } })
  assert.equal(check.verdict, 'fail')
  assert.match(check.failures[0], /did not run/)
})

test('evaluateExpect: all rules must hold (AND), and every failure is reported', () => {
  const check = evaluateExpect({ contains: 'nginx', notContains: 'ERROR', exitCode: 0 }, { ...OK, output: 'ERROR nginx down', exitCode: 2 })
  assert.equal(check.verdict, 'fail')
  assert.equal(check.failures.length, 2)
})

test('evaluateExpect: the message note is appended to each failure', () => {
  const check = evaluateExpect({ contains: 'nginx', message: 'nginx 未运行' }, { ...OK, output: 'nothing' })
  assert.match(check.failures[0], /nginx 未运行/)
})

test('planRunbook: asserted counts only runnable steps carrying expect', () => {
  const plan = planRunbook('rb', {
    steps: [
      { id: 'a', profile: 'basic', expect: { notEmpty: true } },
      { id: 'b', command: 'uptime' },
      { id: 'c', command: 'rm -rf /', expect: { exitCode: 0 } },
    ],
  })
  assert.equal(plan.runnable, 2)
  assert.equal(plan.skipped, 1)
  assert.equal(plan.asserted, 1)
  assert.equal(plan.steps[0].expect.notEmpty, true)
  assert.equal(plan.steps[1].expect, null)
})

/* ------------------------------------------------------------------ V0.4.3 */
/*
 * runRunbook integration tests.
 *
 * These drive the REAL runRunbook over a fake SessionManager, so the
 * flatten/regroup logic and the assertion semantics are exercised end to end
 * without a bastion. The regression they guard is the V0.4.2 bug where a
 * profile step's `expect` was evaluated once per probe, so
 * `profile: network, expect: { contains: 'LISTEN' }` reported FAIL on a
 * perfectly healthy host (only the `ss -lntp` probe contains LISTEN).
 */

/** Minimal stand-in for SessionManager.runTargetBatch. */
function fakeManager(outputFor) {
  const seen = []
  return {
    seen,
    async runTargetBatch(request) {
      seen.push(request)
      const commands = request.commands.map((c, index) => {
        const scripted = outputFor(c.command, index)
        return {
          command: c.command,
          executionState: 'COMPLETED',
          exitCode: scripted.exitCode ?? 0,
          output: scripted.output ?? '',
          truncated: false,
          durationMs: 1,
          error: scripted.error ?? null,
        }
      })
      return { target: request.target, hostname: 'host-' + request.target, error: null, commands }
    },
  }
}

const ALLOW_ALL = () => ({})

test('runRunbook: a profile step is reported ONCE, not once per probe', async () => {
  const manager = fakeManager(() => ({ output: 'ok', exitCode: 0 }))
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')
  const result = await runRunbook(manager, ALLOW_ALL, 'rb', { steps: [{ id: 'net', profile: 'network' }] }, { targets: ['10.0.0.1'] })

  assert.equal(result.results.length, 1)
  const steps = result.results[0].steps
  assert.equal(steps.length, 1, 'one logical step must produce exactly one result row')
  assert.equal(steps[0].id, 'net')
  assert.equal(steps[0].kind, 'profile')
  // Detail is preserved even though the row is folded.
  assert.ok(steps[0].commands.length > 1, 'per-probe detail must survive in commands[]')
  assert.equal(steps[0].commands.length, steps[0].probes.length)
  assert.deepEqual(
    steps[0].commands.map((c) => c.probe),
    steps[0].probes,
  )
})

test('runRunbook: profile expect without probe aggregates ALL probe output (no false FAIL)', async () => {
  // Reproduces the exact config.example.json shape: only ONE probe prints
  // LISTEN, the rest print unrelated text. Pre-V0.4.3 this was a false FAIL.
  const manager = fakeManager((command) => ({
    output: command.startsWith('ss -lntp') ? 'State  Local Address:Port\nLISTEN 0 128 0.0.0.0:22\n' : 'irrelevant output',
    exitCode: 0,
  }))
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')
  const result = await runRunbook(
    manager,
    ALLOW_ALL,
    'oa-health',
    { steps: [{ id: 'net', profile: 'network', expect: { contains: 'LISTEN' } }] },
    { targets: ['10.0.0.1'] },
  )

  assert.equal(result.verdict, 'pass', 'aggregate assertion must not false-FAIL a healthy host')
  const step = result.results[0].steps[0]
  assert.equal(step.check.verdict, 'pass')
  // The judged text is the aggregate of every probe.
  assert.ok(step.output.includes('LISTEN'))
  assert.ok(step.output.includes('irrelevant output'))
})

test('runRunbook: expect.probe narrows the assertion to that one probe', async () => {
  const manager = fakeManager((command) => ({
    output: command.startsWith('ss -lntp') ? 'LISTEN 0 128 0.0.0.0:22\n' : 'plain hosts file content',
    exitCode: 0,
  }))
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')

  // Targeting the probe that DOES contain LISTEN -> pass.
  const hit = await runRunbook(
    manager,
    ALLOW_ALL,
    'rb',
    { steps: [{ id: 'net', profile: 'network', expect: { probe: 'listen', contains: 'LISTEN' } }] },
    { targets: ['10.0.0.1'] },
  )
  assert.equal(hit.verdict, 'pass')
  assert.equal(hit.results[0].steps[0].output.includes('plain hosts file content'), false)

  // Targeting a probe that does NOT -> fail, proving the narrowing is real.
  const miss = await runRunbook(
    manager,
    ALLOW_ALL,
    'rb',
    { steps: [{ id: 'net', profile: 'network', expect: { probe: 'hosts', contains: 'LISTEN' } }] },
    { targets: ['10.0.0.1'] },
  )
  assert.equal(miss.verdict, 'fail')
})

test('runRunbook: expect.probe naming an unknown probe is skipped at plan time', () => {
  const plan = planRunbook('rb', { steps: [{ id: 'net', profile: 'network', expect: { probe: 'nope', contains: 'x' } }] })
  assert.equal(plan.runnable, 0)
  assert.equal(plan.skipped, 1)
  assert.equal(plan.steps[0].skipped.ruleId, 'runbook.unknown-probe')
})

test('runRunbook: a command step still judges its own single output', async () => {
  const manager = fakeManager(() => ({ output: 'uptime says fine', exitCode: 0 }))
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')
  const result = await runRunbook(
    manager,
    ALLOW_ALL,
    'rb',
    { steps: [{ id: 'up', command: 'uptime', expect: { contains: 'uptime' } }] },
    { targets: ['10.0.0.1'] },
  )
  assert.equal(result.verdict, 'pass')
  const step = result.results[0].steps[0]
  assert.equal(step.kind, 'command')
  assert.equal(step.commands.length, 1)
  assert.equal(step.commands[0].probe, null)
})

test('runRunbook: a non-zero probe exit makes the aggregated step exitCode non-zero', async () => {
  const manager = fakeManager((command) => (command.startsWith('ip neigh') ? { output: '', exitCode: 127 } : { output: 'ok', exitCode: 0 }))
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')
  const result = await runRunbook(manager, ALLOW_ALL, 'rb', { steps: [{ id: 'net', profile: 'network' }] }, { targets: ['10.0.0.1'] })
  const step = result.results[0].steps[0]
  assert.equal(step.exitCode, 127, 'aggregate exit code must surface a failing probe')
})

test('runRunbook: an unreachable target fails its assertions and does not run steps', async () => {
  const manager = {
    async runTargetBatch(request) {
      return { target: request.target, hostname: null, error: { code: 'ASSET_NOT_FOUND', message: 'no such asset' }, commands: [] }
    },
  }
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')
  const result = await runRunbook(
    manager,
    ALLOW_ALL,
    'rb',
    { steps: [{ id: 'net', profile: 'network', expect: { contains: 'LISTEN' } }] },
    { targets: ['10.0.0.1'] },
  )
  assert.equal(result.verdict, 'fail')
  assert.equal(result.results[0].steps.length, 0)
  assert.equal(result.results[0].error.code, 'ASSET_NOT_FOUND')
})

test('runRunbook: denied targets never reach the manager', async () => {
  const manager = fakeManager(() => ({ output: 'ok', exitCode: 0 }))
  const { runRunbook } = await import('../../lib/jumpserver/runbook.js')
  await assert.rejects(
    runRunbook(
      manager,
      () => ({ deniedTargets: ['10.0.0.1'] }),
      'rb',
      { steps: [{ id: 'net', profile: 'network' }] },
      { targets: ['10.0.0.1'] },
    ),
    /TARGET_DENIED|denied/i,
  )
  assert.equal(manager.seen.length, 0, 'a denied target must produce zero execution')
})
