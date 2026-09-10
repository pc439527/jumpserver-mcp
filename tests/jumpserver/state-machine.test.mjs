/**
 * Session state machine: every legal transition must round-trip; every
 * illegal one must collapse to UNKNOWN.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionState, LEGAL_TRANSITIONS, canTransition, nextState } from '../../lib/jumpserver/state-machine.js'

test('legal transitions are complete and unambiguous', () => {
  for (const from of Object.values(SessionState)) {
    const set = LEGAL_TRANSITIONS[from]
    assert.ok(set instanceof Set, 'transitions from ' + from + ' must be a Set')
    for (const to of set) {
      assert.ok(canTransition(from, to), from + ' -> ' + to + ' is in LEGAL_TRANSITIONS but canTransition disagrees')
    }
  }
})

test('every state has a recovery path (UNKNOWN / DISCONNECTED / forward to a recoverable state)', () => {
  for (const from of Object.values(SessionState)) {
    if (from === SessionState.DISCONNECTED) continue
    const set = LEGAL_TRANSITIONS[from]
    // DISCONNECTED is the natural rest; every other state must either reach
    // it directly, collapse to UNKNOWN, or move forward into a state that
    // can (CONNECTING transitions only into JUMPSERVER_MENU / ERROR, which
    // are themselves recoverable).
    const can =
      set.has(SessionState.UNKNOWN) ||
      set.has(SessionState.DISCONNECTED) ||
      set.has(SessionState.JUMPSERVER_MENU) ||
      set.has(SessionState.ERROR)
    assert.ok(can, from + ' has no way out of a stuck state')
  }
})

test('illegal self-transitions collapse to UNKNOWN (the state machine never silently no-ops)', () => {
  for (const s of Object.values(SessionState)) {
    assert.equal(nextState(s, s), SessionState.UNKNOWN, 'self-transition from ' + s + ' must collapse to UNKNOWN')
  }
})

test('UNKNOWN reconnects; ERROR must be closed before reconnecting', () => {
  // UNKNOWN: both CONNECTING (in-session re-probe) and DISCONNECTED (full reset) are legal.
  assert.ok(LEGAL_TRANSITIONS[SessionState.UNKNOWN].has(SessionState.CONNECTING))
  assert.ok(LEGAL_TRANSITIONS[SessionState.UNKNOWN].has(SessionState.DISCONNECTED))
  // ERROR is unrecoverable until the user explicitly closes the session.
  assert.ok(LEGAL_TRANSITIONS[SessionState.ERROR].has(SessionState.DISCONNECTED))
  assert.equal(LEGAL_TRANSITIONS[SessionState.ERROR].has(SessionState.CONNECTING), false)
})
