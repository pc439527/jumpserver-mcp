/**
 * E-4 · the console address must not BREAK when a process dies.
 *
 * The failure this guards (N-15): the handover URL was
 * `http://127.0.0.1:8765/?inst=<pid>`, and the owner of port 8765 changed
 * THREE times inside 25 minutes on this workspace (every MCP process restart
 * takes the address over). A URL pinned to the old pid then named an instance
 * that no longer existed, and the preview panel said 「暂无数据」 — which
 * looked like a rendering bug and was actually a dead pointer.
 *
 * The contract:
 *   1. The pin STAYS — it is the V0.5.8 identity fix (an operator must not
 *      land in a stranger's terminal), and it is derived from THIS process's
 *      own pid, never from the live instance list (that would be a race).
 *   2. A pin that no longer resolves HEALS: redirect to the live console and
 *      carry the dead pid along, so the page can explain itself.
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  consoleAddressFor,
  isPinLive,
  stalePinFallback,
} from '../../lib/runtime/console-address.js'

const URL = 'http://127.0.0.1:8765/'

test('E-4: stable mode pins the address to this process', () => {
  const address = consoleAddressFor(URL, 100, true)
  assert.equal(address.url, 'http://127.0.0.1:8765/?inst=100')
  assert.equal(address.pinned, true)
  assert.equal(address.pinnedPid, 100)
  assert.equal(address.reason, 'stable-pinned')
})

test('E-4: the pin is derived from THIS process, never from the instance list', () => {
  // The address must not depend on who else is alive: a second conversation
  // starting a millisecond later must not change the URL already handed out.
  const address = consoleAddressFor(URL, 100, true)
  assert.equal(address.pinnedPid, 100)
})

test('E-4: legacy mode never pins (the token is the identity)', () => {
  const address = consoleAddressFor('http://127.0.0.1:52490/?token=abc', 100, false)
  assert.equal(address.url, 'http://127.0.0.1:52490/?token=abc')
  assert.equal(address.pinned, false)
  assert.equal(address.reason, 'legacy')
})

test('E-4: no console ⇒ no address', () => {
  const address = consoleAddressFor(null, 100, true)
  assert.equal(address.url, null)
  assert.equal(address.pinned, false)
})

test('E-4: an address that already has a query keeps a single ?', () => {
  const address = consoleAddressFor('http://127.0.0.1:8765/?token=abc', 100, true)
  assert.equal(address.url, 'http://127.0.0.1:8765/?token=abc&inst=100')
  assert.equal((address.url.match(/\?/g) ?? []).length, 1)
})

test('E-4: a pin naming THIS process is live', () => {
  assert.equal(isPinLive(100, 100, [{ pid: 100, port: 8765, role: 'owner' }]), true)
})

test('E-4: a pin naming another live instance is live', () => {
  const instances = [
    { pid: 100, port: 8765, role: 'owner' },
    { pid: 200, port: 53124, role: 'follower' },
  ]
  assert.equal(isPinLive(200, 100, instances), true)
})

test('E-4: a pin naming a DEAD instance is not live', () => {
  // The pid the URL was minted with is gone — the process restarted.
  const instances = [{ pid: 300, port: 8765, role: 'owner' }]
  assert.equal(isPinLive(200, 300, instances), false)
})

test('E-4: no pin at all is not "live" (there is nothing to resolve)', () => {
  assert.equal(isPinLive(null, 100, []), false)
  assert.equal(isPinLive(0, 100, []), false)
  assert.equal(isPinLive(-1, 100, []), false)
  assert.equal(isPinLive(Number.NaN, 100, []), false)
})

test('E-4: a stale pin falls back to the live address and says which pid died', () => {
  const fallback = stalePinFallback(URL, 200)
  assert.equal(fallback, 'http://127.0.0.1:8765/?gone=200')
})

test('E-4: the fallback of a pin-less request is the plain address', () => {
  assert.equal(stalePinFallback(URL, null), URL)
})

test('E-4: no console ⇒ no fallback', () => {
  assert.equal(stalePinFallback(null, 200), null)
})

test('E-4: the fallback never carries a stale ?inst= (that is what killed it)', () => {
  const fallback = stalePinFallback(URL, 200)
  assert.equal(fallback.includes('inst='), false)
})
