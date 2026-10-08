/**
 * V0.5.12: every failure renderer must carry JumpServerError.detail.
 *
 * Regression guard for a real, observed failure mode: a profile whose password
 * was wrong surfaced to the model as
 *
 *     code: AUTH_FAILED
 *     JumpServer authentication failed
 *
 * with no `detail`, so the only available next step was to guess. The cause
 * was not guardValue() (it attaches detail correctly) but THREE hand-written
 * renderers that projected a narrower shape:
 *   - renderAssetsResult()      -> tools/common.ts
 *   - the ops text tools' local render()  -> tools-ops.ts (now delegates)
 *   - renderBatchResult() nested errors   -> blocked further upstream by
 *     BatchCommandResult.error / TargetBatchResult.error being declared
 *     `{ code, message }` while errorDetail() actually returned a `detail`.
 *
 * These tests pin the projection, not the transport: they assert that a
 * `detail` which reached a ResultValue is visible in the rendered text.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { renderAssetsResult, renderBatchResult, renderResult } from '../../lib/runtime/tools-common.js'

const AUTH_DETAIL = 'All configured authentication methods failed'

test('renderAssetsResult: AUTH_FAILED detail reaches the model', () => {
  const text = renderAssetsResult({
    ok: false,
    code: 'AUTH_FAILED',
    message: 'JumpServer authentication failed',
    detail: AUTH_DETAIL,
  })
  assert.match(text, /code: AUTH_FAILED/)
  assert.match(text, /JumpServer authentication failed/)
  assert.ok(text.includes('detail: ' + AUTH_DETAIL), 'the server reason must be rendered, got:\n' + text)
  // A failure must never masquerade as a listing.
  assert.doesNotMatch(text, /^ok/m)
})

test('renderAssetsResult: missing config fields are listed, not just "incomplete"', () => {
  const text = renderAssetsResult({
    ok: false,
    code: 'CONFIG_INCOMPLETE',
    message: 'connection settings are incomplete',
    connectionComplete: false,
    connectionMissing: ['host', 'username'],
  })
  assert.ok(text.includes('connection: INCOMPLETE — missing host, username'), 'got:\n' + text)
})

test('renderAssetsResult: ASSET_UNREACHABLE keeps its STOP line', () => {
  const text = renderAssetsResult({
    ok: false,
    code: 'ASSET_UNREACHABLE',
    message: 'JumpServer could not reach the asset',
    detail: '网络不通（连接超时）',
  })
  assert.match(text, /STOP — the bastion cannot reach this asset/)
  assert.ok(text.includes('detail: 网络不通（连接超时）'))
})

test('renderAssetsResult: the success path is unchanged', () => {
  const text = renderAssetsResult({
    ok: true,
    code: undefined,
    filter: undefined,
    group: undefined,
    assets: [{ ip: '10.0.0.1' }, { ip: '10.0.0.2' }],
    reportedTotal: 2,
    parsedRows: 2,
    complete: true,
  })
  assert.match(text, /^ok count=2/)
  assert.match(text, /KoKo footer: reportedTotal=2 \(capture complete\)/)
  assert.doesNotMatch(text, /detail:/)
})

test('renderBatchResult: a target-level failure keeps its detail', () => {
  const value = renderBatchResult([
    {
      target: 'app-01',
      hostname: null,
      error: { code: 'ACCOUNT_SELECTION_REQUIRED', message: 'multiple accounts', detail: 'accounts=1:root | 2:手动输入' },
      commands: [],
    },
  ])
  assert.ok(value.output.includes('accounts=1:root | 2:手动输入'), 'got:\n' + value.output)
})

test('renderBatchResult: a command-level failure keeps its detail', () => {
  const value = renderBatchResult([
    {
      target: 'app-01',
      hostname: 'ahl-c148036',
      error: null,
      commands: [
        {
          command: 'pwd',
          executionState: 'FAILED',
          commandStatus: 'ERROR',
          exitCode: null,
          output: '',
          truncated: false,
          durationMs: 5,
          error: { code: 'COMMAND_TIMEOUT', message: 'no prompt within 30s', detail: 'tail: [Host]>' },
        },
      ],
    },
  ])
  assert.ok(value.output.includes('tail: [Host]>'), 'got:\n' + value.output)
  // A command failure must still count as a failure overall.
  assert.equal(value.ok, false)
})

test('renderBatchResult: failures without detail render exactly as before (no empty line)', () => {
  const value = renderBatchResult([
    { target: 'app-01', hostname: null, error: { code: 'MENU_RETURN_FAILED', message: 'cannot return to menu' }, commands: [] },
  ])
  assert.ok(value.output.includes('error=MENU_RETURN_FAILED: cannot return to menu'))
  assert.doesNotMatch(value.output, /detail:/)
})

test('renderResult: detail is never dropped for a JumpServerError value', () => {
  const text = renderResult({ ok: false, code: 'ACCOUNT_SELECTION_EXPIRED', message: 'the ID> prompt is gone', detail: 'accounts=1:root' })
  assert.ok(text.includes('detail: accounts=1:root'), 'got:\n' + text)
})
