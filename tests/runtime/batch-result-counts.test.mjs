/**
 * V0.6.0 (A-4): a batch result must say what ACTUALLY happened.
 *
 * Before, a batch whose every target failed to be entered and a batch that
 * ran three commands successfully produced the same shape: a list of targets,
 * each with `commands=0` or `commands=1`. The model had to read every line
 * to work out whether anything ran at all — and "nothing was executed" is
 * the single most important fact in a batch result.
 *
 * These tests pin:
 *   1. the counters (executedCount / rejectedCount / failedTargets);
 *   2. that the counters REACH THE MODEL TEXT — renderResult() is a
 *      whitelist, so a field that is not rendered there is invisible.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { renderBatchResult, renderResult } from '../../lib/runtime/tools-common.js'

/** One target whose commands all succeeded. */
function okTask(target) {
  return {
    target,
    hostname: 'host-' + target,
    error: null,
    commands: [
      { command: 'uptime', executionState: 'COMPLETED', commandStatus: 'SUCCESS', exitCode: 0, output: 'ok', truncated: false, durationMs: 10, error: null },
    ],
  }
}

/** One target that could not be entered at all. */
function failedTask(target, code) {
  return { target, hostname: null, error: { code, message: 'could not enter ' + target }, commands: [] }
}

test('a fully successful batch reports the executed count and no failures', () => {
  const value = renderBatchResult([okTask('10.0.0.1'), okTask('10.0.0.2')])
  assert.equal(value.executedCount, 2)
  assert.equal(value.rejectedCount, 0)
  assert.deepEqual(value.failedTargets, [])
  assert.equal(value.ok, true)
})

test('a batch where every target failed reports ZERO executed commands', () => {
  const value = renderBatchResult([
    failedTask('10.0.0.1', 'ASSET_UNREACHABLE'),
    failedTask('10.0.0.2', 'ASSET_NOT_AUTHORIZED'),
  ])
  assert.equal(value.executedCount, 0)
  assert.deepEqual(value.failedTargets, ['10.0.0.1', '10.0.0.2'])
  assert.equal(value.ok, false)
  assert.ok(String(value.message).includes('0 command(s) executed'), value.message)
})

test('a mixed batch separates executed, rejected and failed targets', () => {
  const refused = {
    target: '10.0.0.3',
    hostname: 'host-10.0.0.3',
    error: null,
    commands: [
      { command: 'rm -rf /tmp/x', executionState: 'ERROR', commandStatus: 'UNKNOWN', exitCode: null, output: '', truncated: false, durationMs: 0, error: { code: 'COMMAND_APPROVAL_REQUIRED', message: 'denied by the human' } },
    ],
  }
  const value = renderBatchResult([okTask('10.0.0.1'), refused, failedTask('10.0.0.2', 'ASSET_UNREACHABLE')])
  assert.equal(value.executedCount, 1)
  assert.equal(value.rejectedCount, 1)
  assert.deepEqual(value.failedTargets, ['10.0.0.2'])
})

test('the counters reach the model text (renderResult is a whitelist)', () => {
  const value = renderBatchResult([okTask('10.0.0.1'), failedTask('10.0.0.2', 'ASSET_UNREACHABLE')])
  const text = renderResult(value)
  assert.ok(text.includes('executedCount: 1'), text)
  assert.ok(text.includes('rejectedCount: 0'), text)
  assert.ok(text.includes('failedTargets: 10.0.0.2'), text)
})

test('an empty batch renders without throwing and reports zero counts', () => {
  const value = renderBatchResult([])
  assert.equal(value.executedCount, 0)
  assert.equal(value.rejectedCount, 0)
  assert.deepEqual(value.failedTargets, [])
  const text = renderResult(value)
  assert.ok(text.includes('failedTargets: none'), text)
})
