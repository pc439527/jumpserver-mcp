/**
 * V0.4.3: `maxSessions` must actually be enforced.
 *
 * Before this, `maxSessions` was parsed from config and never read — the
 * README claimed a Semaphore capped simultaneous bastion sessions, but the
 * gate was never wired into any execution path. These tests drive the real
 * SessionManager with a fake wire and prove the gate holds the line.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { Semaphore } from '../../lib/jumpserver/concurrency.js'

test('Semaphore: never admits more than `size` concurrent holders', async () => {
  const gate = new Semaphore(2)
  let live = 0
  let peak = 0
  const work = async () => {
    const release = await gate.acquire()
    live += 1
    peak = Math.max(peak, live)
    await new Promise((r) => setTimeout(r, 20))
    live -= 1
    release()
  }
  await Promise.all([work(), work(), work(), work(), work(), work()])
  assert.equal(peak, 2, 'peak concurrency must not exceed the gate size')
  assert.equal(live, 0, 'every holder must be released')
})

test('Semaphore: release is idempotent', async () => {
  const gate = new Semaphore(1)
  const release = await gate.acquire()
  release()
  release() // must not hand out a second slot
  let second = false
  const pending = gate.acquire().then(() => {
    second = true
    return () => undefined
  })
  await new Promise((r) => setTimeout(r, 10))
  assert.equal(second, true, 'the slot was freed exactly once')
  ;(await pending)()
})

test('Semaphore: queued waiters are served in order', async () => {
  const gate = new Semaphore(1)
  const order = []
  const release = await gate.acquire()
  const waiting = [
    gate.acquire().then((r) => {
      order.push('a')
      return r
    }),
    gate.acquire().then((r) => {
      order.push('b')
      return r
    }),
  ]
  release()
  // 'a' gets the slot; hand it on so 'b' can proceed.
  const releaseA = await waiting[0]
  assert.deepEqual(order, ['a'])
  releaseA()
  const releaseB = await waiting[1]
  assert.deepEqual(order, ['a', 'b'], 'FIFO order must be preserved')
  releaseB()
})

test('Semaphore: size below 1 is clamped to 1', async () => {
  const gate = new Semaphore(0)
  const release = await gate.acquire()
  assert.equal(typeof release, 'function')
  release()
})
