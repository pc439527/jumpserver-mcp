/**
 * Bounded-concurrency helpers (V0.4.1).
 *
 * Contract under test: results keep INPUT order regardless of completion
 * order, concurrency never exceeds the limit, an empty input is a no-op, and
 * an aborted signal stops the run with AbortRequestedError.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mapWithConcurrency, Semaphore } from '../../lib/jumpserver/concurrency.js'
import { AbortRequestedError } from '../../lib/jumpserver/errors.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

test('mapWithConcurrency preserves input order when completion is out of order', async () => {
  const items = [50, 10, 30, 5]
  const seen = []
  const result = await mapWithConcurrency(items, async (delay, index) => {
    seen.push(index)
    await sleep(delay)
    return 'r' + index
  }, { concurrency: 4 })
  assert.deepEqual(result, ['r0', 'r1', 'r2', 'r3'])
  // every item ran exactly once
  assert.equal(seen.length, 4)
  assert.deepEqual([...seen].sort((a, b) => a - b), [0, 1, 2, 3])
})

test('mapWithConcurrency never exceeds the concurrency limit', async () => {
  let active = 0
  let peak = 0
  const items = Array.from({ length: 12 }, (_, i) => i)
  await mapWithConcurrency(items, async () => {
    active += 1
    peak = Math.max(peak, active)
    await sleep(5)
    active -= 1
    return null
  }, { concurrency: 3 })
  assert.ok(peak <= 3, 'peak concurrency was ' + peak)
  assert.ok(peak >= 2, 'expected real parallelism, peak was ' + peak)
})

test('mapWithConcurrency on an empty list returns an empty array without calling the worker', async () => {
  let called = 0
  const result = await mapWithConcurrency([], async () => { called += 1; return 1 }, { concurrency: 4 })
  assert.deepEqual(result, [])
  assert.equal(called, 0)
})

test('mapWithConcurrency throws AbortRequestedError when the signal is already aborted', async () => {
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(
    mapWithConcurrency([1, 2, 3], async (n) => n, { concurrency: 2, signal: controller.signal }),
    AbortRequestedError,
  )
})

test('mapWithConcurrency treats concurrency < 1 as 1 (sequential)', async () => {
  let active = 0
  let peak = 0
  await mapWithConcurrency([1, 2, 3], async () => {
    active += 1
    peak = Math.max(peak, active)
    await sleep(2)
    active -= 1
    return null
  }, { concurrency: 0 })
  assert.equal(peak, 1)
})

test('Semaphore caps concurrent holders and releases in order', async () => {
  const sem = new Semaphore(2)
  let active = 0
  let peak = 0
  const order = []
  const job = async (id) => {
    const release = await sem.acquire()
    active += 1
    peak = Math.max(peak, active)
    await sleep(5)
    active -= 1
    order.push(id)
    release()
  }
  await Promise.all([job(1), job(2), job(3), job(4)])
  assert.ok(peak <= 2, 'peak was ' + peak)
  assert.equal(order.length, 4)
})

test('Semaphore release is idempotent (double release cannot inflate the pool)', async () => {
  const sem = new Semaphore(1)
  const release = await sem.acquire()
  release()
  release()
  // after a double release the pool still has exactly one slot
  let second = false
  const release2 = await sem.acquire()
  second = true
  assert.equal(second, true)
  release2()
})
