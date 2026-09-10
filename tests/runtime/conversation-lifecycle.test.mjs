/**
 * V0.4.3: WorkBuddy conversation lifecycle isolation.
 *
 * WorkBuddy spawns ONE MCP stdio server process per conversation, so process
 * isolation is the conversation boundary. These tests verify the properties
 * that assumption depends on:
 *
 *   - two conversations never share a SessionBundle / manager / observer
 *   - jobs, grants and terminal streams stay inside their own conversation
 *   - a transport sessionId (multiplexing host) is honoured when present
 *   - a shared process WITHOUT a scope id is reported honestly, not silently
 *     treated as multi-conversation
 *
 * The gate here is real code, not a mock: SessionRegistry + SessionGrant +
 * sessionIdOf are driven directly.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionRegistry, ANONYMOUS_SESSION } from '../../lib/jumpserver/session-registry.js'
import { SessionGrant } from '../../lib/security/grant.js'
import { sessionIdOf } from '../../lib/runtime/tools-common.js'
import { describeSessionScope } from '../../lib/runtime/runtime.js'

/** A registry whose bundles are distinguishable stand-ins. */
function makeRegistry() {
  let created = 0
  const registry = new SessionRegistry({
    create: (sessionId) => {
      created += 1
      const id = created
      return {
        manager: { id, sessionId, status: () => ({ state: 'DISCONNECTED', target: null }), tickIdle: () => {}, dispose: () => {} },
        observer: { id, sessionId, snapshot: () => [], snapshotSince: () => [], cursorSeq: 0 },
        lastUsedAt: 0,
      }
    },
  })
  return registry
}

const exec = (sessionId) => ({ name: 'jumpserver_exec', callId: 1, signal: new AbortController().signal, confirm: false, sessionId })

test('two transport sessions get two distinct bundles (no sharing)', () => {
  const registry = makeRegistry()
  const a = registry.getOrCreate(sessionIdOf(exec('conv-A')))
  const b = registry.getOrCreate(sessionIdOf(exec('conv-B')))
  assert.notEqual(a, b)
  assert.notEqual(a.manager, b.manager)
  assert.notEqual(a.observer, b.observer)
  assert.equal(registry.size, 2)
})

test('the same transport session always maps back to the same bundle', () => {
  const registry = makeRegistry()
  const first = registry.getOrCreate(sessionIdOf(exec('conv-A')))
  const again = registry.getOrCreate(sessionIdOf(exec('conv-A')))
  assert.equal(first, again, 'a conversation must resume its own session')
  assert.equal(registry.size, 1)
})

test('a conversation cannot read another conversation bundle by id', () => {
  const registry = makeRegistry()
  registry.getOrCreate('conv-A')
  assert.equal(registry.get('conv-B'), undefined)
  assert.equal(registry.has('conv-B'), false)
})

test('grants are per conversation: arming A does not arm B', () => {
  const grants = new SessionGrant()
  grants.arm('conv-A', 'turn', 60_000)
  assert.equal(grants.isGranted('conv-A'), true)
  assert.equal(grants.isGranted('conv-B'), false, 'one conversation must not unlock another')
})

test('revoking a grant affects only that conversation', () => {
  const grants = new SessionGrant()
  grants.arm('conv-A', 'persistent', 60_000)
  grants.arm('conv-B', 'persistent', 60_000)
  grants.revoke('conv-A')
  assert.equal(grants.isGranted('conv-A'), false)
  assert.equal(grants.isGranted('conv-B'), true)
})

test('without a transport sessionId, every call collapses to the anonymous scope', () => {
  // This is the stdio reality: ONE process = ONE conversation. The fallback is
  // correct BECAUSE the host spawns a process per conversation.
  assert.equal(sessionIdOf(exec(undefined)), ANONYMOUS_SESSION)
  assert.equal(sessionIdOf(exec('')), ANONYMOUS_SESSION)
})

test('a transport sessionId overrides the anonymous fallback', () => {
  assert.equal(sessionIdOf(exec('conv-A')), 'conv-A')
})

test('JUMPSERVER_MCP_SESSION is honoured when no transport id is present', () => {
  const previous = process.env['JUMPSERVER_MCP_SESSION']
  process.env['JUMPSERVER_MCP_SESSION'] = 'pinned-scope'
  try {
    assert.equal(sessionIdOf(exec(undefined)), 'pinned-scope')
    // A transport id still wins: it is more specific than the process default.
    assert.equal(sessionIdOf(exec('conv-A')), 'conv-A')
  } finally {
    if (previous === undefined) delete process.env['JUMPSERVER_MCP_SESSION']
    else process.env['JUMPSERVER_MCP_SESSION'] = previous
  }
})

test('a shared process without a scope id is reported honestly', () => {
  // The self-check must not claim multi-conversation support it cannot provide.
  assert.match(describeSessionScope('shared-unsafe'), /SHARED/)
  assert.match(describeSessionScope('process'), /process isolation/)
  assert.match(describeSessionScope('transport'), /transport/)
})

test('detach reaps only the idle conversation', () => {
  let now = 1000
  const registry = new SessionRegistry({
    create: (sessionId) => ({
      manager: { status: () => ({ state: 'DISCONNECTED' }), tickIdle: () => {}, dispose: () => {} },
      observer: { snapshot: () => [] },
      lastUsedAt: now,
      sessionId,
    }),
    now: () => now,
    detachGraceMs: 500,
  })
  registry.getOrCreate('conv-A')
  now += 200
  registry.getOrCreate('conv-B') // B is fresh
  now += 400 // A is now 600ms idle, B is 400ms
  registry.tickIdle()
  assert.equal(registry.get('conv-A'), undefined, 'the idle conversation is reaped')
  assert.notEqual(registry.get('conv-B'), undefined, 'the active conversation survives')
})
