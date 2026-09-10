/**
 * V0.4.3: commandStatus — separate "did the exchange complete" from "did the
 * command succeed".
 *
 * Regression guard: `jps -lv` on a host without a JDK exits 127. Pre-V0.4.3
 * the connector reported ok=true / executionState=COMPLETED, so the model saw
 * a healthy read and the console counted it as a success. The audit trail
 * claimed READ / COMPLETED for a command that plainly failed.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { execOutcomeToValue } from '../../lib/runtime/tools-common.js'
import { renderBatchResult } from '../../lib/runtime/tools-common.js'

const STATUS = {
  configured: true,
  permissionMode: 'AUTO',
  state: 'ASSET_SHELL',
  gateway: 'bastion:2222',
  target: '10.0.0.1',
  hostname: 'oa-app-01',
  user: 'ops',
  pwd: null,
  connectedAt: 1,
  lastActivityAt: 2,
  reconnectCount: 0,
}

test('execOutcomeToValue: exit 0 => ok true, commandStatus SUCCESS', () => {
  const value = execOutcomeToValue(STATUS, {
    kind: 'completed',
    exitCode: 0,
    commandStatus: 'SUCCESS',
    output: 'java 1.8\n',
    truncated: false,
    durationMs: 12,
    executionState: 'COMPLETED',
  })
  assert.equal(value.ok, true)
  assert.equal(value.commandStatus, 'SUCCESS')
  assert.equal(value.exitCode, 0)
  assert.equal(value.completed, true)
})

test('execOutcomeToValue: exit 127 => ok FALSE (the jps -lv regression)', () => {
  const value = execOutcomeToValue(STATUS, {
    kind: 'completed',
    exitCode: 127,
    commandStatus: 'EXIT_NONZERO',
    output: 'jps: command not found\n',
    truncated: false,
    durationMs: 9,
    executionState: 'COMPLETED',
  })
  assert.equal(value.ok, false, 'a non-zero exit must never be reported as ok')
  assert.equal(value.commandStatus, 'EXIT_NONZERO')
  assert.equal(value.exitCode, 127)
  // The exchange still completed — that fact is preserved for diagnostics.
  assert.equal(value.completed, true)
  assert.equal(value.executionState, 'COMPLETED')
  assert.equal(value.code, 'COMMAND_EXIT_NONZERO')
  assert.match(String(value.message), /127/)
})

test('execOutcomeToValue: timeout carries TIMEOUT and is not ok', () => {
  const value = execOutcomeToValue(STATUS, {
    kind: 'timeout',
    commandStatus: 'TIMEOUT',
    output: 'partial',
    truncated: false,
    durationMs: 30000,
    executionState: 'TIMEOUT',
  })
  assert.equal(value.ok, false)
  assert.equal(value.commandStatus, 'TIMEOUT')
  assert.equal(value.code, 'COMMAND_TIMEOUT')
})

test('execOutcomeToValue: lost connection carries CONNECTION_LOST', () => {
  const value = execOutcomeToValue(STATUS, {
    kind: 'signal-lost',
    commandStatus: 'CONNECTION_LOST',
    output: '',
    durationMs: 5,
    executionState: 'UNKNOWN',
  })
  assert.equal(value.ok, false)
  assert.equal(value.commandStatus, 'CONNECTION_LOST')
  assert.equal(value.code, 'CONNECTION_LOST')
})

test('renderBatchResult: a non-zero exit makes the batch report ok=false', () => {
  const value = renderBatchResult([
    {
      target: '10.0.0.1',
      hostname: 'oa-app-01',
      error: null,
      commands: [
        { command: 'jps -lv', executionState: 'COMPLETED', commandStatus: 'EXIT_NONZERO', exitCode: 127, output: 'not found', truncated: false, durationMs: 3, error: null },
      ],
    },
  ])
  assert.equal(value.ok, false, 'one failing command must fail the batch')
  assert.match(String(value.message), /1 error/)
})

test('renderBatchResult: all-zero exits report ok=true', () => {
  const value = renderBatchResult([
    {
      target: '10.0.0.1',
      hostname: 'oa-app-01',
      error: null,
      commands: [
        { command: 'uptime', executionState: 'COMPLETED', commandStatus: 'SUCCESS', exitCode: 0, output: 'up 1 day', truncated: false, durationMs: 3, error: null },
      ],
    },
  ])
  assert.equal(value.ok, true)
})
