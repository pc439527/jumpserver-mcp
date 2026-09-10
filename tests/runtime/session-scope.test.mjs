/**
 * V0.4.5: `jumpserver_status.sessionScope` must describe the scope the caller
 * is REALLY on.
 *
 * V0.4.4 derived it from `sessionIdOf(exec).length > 0`, but sessionIdOf()
 * falls back to JUMPSERVER_MCP_SESSION and then to ANONYMOUS_SESSION — both
 * non-empty — so a plain WorkBuddy stdio conversation (no transport id at all)
 * was reported as `transport`. That is the very case the fix was supposed to
 * disambiguate, so this test drives the projection used by the status tool
 * with real exec contexts, not sessionIdOf() alone.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { projectSessionScope, hasTransportSession } from '../../lib/runtime/session-scope.js'
import { sessionIdOf } from '../../lib/runtime/tools-common.js'
import { ANONYMOUS_SESSION } from '../../lib/jumpserver/session-registry.js'
import { describeSessionScope } from '../../lib/runtime/runtime.js'

/** A ToolRunContext as the stdio transport builds it (no transport sessionId). */
function stdioExec() {
  return { name: 'jumpserver_status', callId: 1, signal: new AbortController().signal, confirm: false }
}

/** A ToolRunContext from a multiplexing host that DID assign a session id. */
function transportExec(sessionId) {
  return { ...stdioExec(), sessionId }
}

test('stdio conversation (no transport id) is reported as the runtime mode, never transport', () => {
  assert.equal(hasTransportSession(stdioExec()), false)
  assert.equal(projectSessionScope(stdioExec(), 'process'), 'process')
  assert.equal(describeSessionScope(projectSessionScope(stdioExec(), 'process')), 'process isolation (one MCP server per conversation)')
})

test('regression: the ANONYMOUS_SESSION fallback is not mistaken for a transport session', () => {
  const exec = stdioExec()
  // sessionIdOf() is non-empty even here — that is exactly what V0.4.4 read.
  assert.equal(sessionIdOf(exec), ANONYMOUS_SESSION)
  assert.equal(projectSessionScope(exec, 'process'), 'process', 'ANONYMOUS_SESSION must not become transport')
})

test('regression: JUMPSERVER_MCP_SESSION pins the env scope, still not transport', () => {
  const previous = process.env['JUMPSERVER_MCP_SESSION']
  process.env['JUMPSERVER_MCP_SESSION'] = 'pinned-scope'
  try {
    const exec = stdioExec()
    assert.equal(sessionIdOf(exec), 'pinned-scope')
    assert.equal(projectSessionScope(exec, 'env'), 'env')
  } finally {
    if (previous === undefined) delete process.env['JUMPSERVER_MCP_SESSION']
    else process.env['JUMPSERVER_MCP_SESSION'] = previous
  }
})

test('a host-assigned transport sessionId IS transport-scoped', () => {
  const exec = transportExec('conv-42')
  assert.equal(hasTransportSession(exec), true)
  assert.equal(projectSessionScope(exec, 'process'), 'transport')
  // sessionIdOf() and the projection must agree on WHICH id is used.
  assert.equal(sessionIdOf(exec), 'conv-42')
})

test('an empty-string sessionId is treated as absent', () => {
  assert.equal(hasTransportSession({ sessionId: '' }), false)
  assert.equal(projectSessionScope({ sessionId: '' }, 'process'), 'process')
})
