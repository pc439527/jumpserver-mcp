/**
 * V0.4.3: the live terminal view must hide the connector's own bookkeeping.
 *
 * The done-script wrapper (`__dsh_rc=$?`, the printf line, the
 * __DSH_JS_DONE_/PROBE_ markers) is protocol noise a user should never see in
 * the terminal mirror. It must be filtered from the VIEW only — the raw events
 * stay in the ring buffer and the audit JSONL, so the evidence is intact.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { stripInternalMarkers } from '../../lib/runtime/audit-viewer.js'

const out = (seq, data) => ({ seq, type: 'output', data, visibility: 'terminal' })

test('strips the done marker line and the __dsh_rc capture line', () => {
  const raw = out(1, 'total 4\ndrwxr-xr-x 2 root root 4096 .\n__dsh_rc=0\n__DSH_JS_DONE_ab12cd34:0\n')
  const clean = stripInternalMarkers(raw)
  assert.equal(clean.data.includes('__dsh_rc'), false)
  assert.equal(clean.data.includes('__DSH_JS_DONE_'), false)
  // Real command output survives untouched.
  assert.ok(clean.data.includes('total 4'))
  assert.ok(clean.data.includes('drwxr-xr-x'))
})

test('strips the probe markers and the printf wrapper', () => {
  const raw = out(2, "printf '\\n__DSH_JS_PROBE_ff00\\n'\nH=oa-app-01\nU=root\nP=/root\n__DSH_JS_PROBE_END_ff00\n")
  const clean = stripInternalMarkers(raw)
  assert.equal(clean.data.includes('__DSH_JS_PROBE_'), false)
  assert.equal(clean.data.includes('printf'), false)
  assert.ok(clean.data.includes('H=oa-app-01'))
  assert.ok(clean.data.includes('P=/root'))
})

test('leaves an event with no markers byte-identical (no needless copy)', () => {
  const raw = out(3, 'plain output\n')
  assert.equal(stripInternalMarkers(raw), raw)
})

test('non-output events pass through untouched', () => {
  const state = { seq: 4, type: 'state', state: 'ASSET_SHELL', prev: 'CONNECTING' }
  assert.equal(stripInternalMarkers(state), state)
})

test('a marker embedded mid-line is still removed', () => {
  const raw = out(5, 'before __DSH_JS_DONE_x:1 after\n')
  const clean = stripInternalMarkers(raw)
  assert.equal(clean.data.includes('__DSH_JS_DONE_'), false)
})
