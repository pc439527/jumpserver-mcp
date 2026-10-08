/**
 * AuditStore paging + archive rotation (V0.5.10).
 *
 * Field failure this covers: the console fetched the WHOLE ring every second
 * and only re-rendered when the array length changed — once the ring hit its
 * cap the length never changed again, so new records stopped appearing and the
 * page paid a 5000-row innerHTML cost per tick. Paging by ABSOLUTE index is the
 * contract that fixes both: only new bytes/records cross the wire, and the
 * cursor stays valid while the ring evicts old records.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AuditStore } from '../../lib/runtime/audit-store.js'

async function withStore(fn, ringSize = 100) {
  const dir = await mkdtemp(join(tmpdir(), 'js-audit-paging-'))
  const file = join(dir, 'audit.jsonl')
  try {
    await fn(new AuditStore(file, { ringSize, log: () => undefined }), file, dir)
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined)
  }
}

test('page advances the cursor and never overlaps', async () => {
  await withStore(async (store) => {
    for (let i = 0; i < 10; i++) store.append({ i })
    await store.flush()

    const first = store.page(-1, 4)
    assert.deepEqual(first.items.map((e) => e['i']), [0, 1, 2, 3])
    assert.equal(first.nextIndex, 3)
    assert.equal(first.total, 10)
    assert.equal(first.windowed, false)
    assert.equal(first.firstIndex, 0, 'a ring that never overflowed starts at 0')

    const second = store.page(first.nextIndex, 4)
    assert.deepEqual(second.items.map((e) => e['i']), [4, 5, 6, 7])
    assert.equal(second.nextIndex, 7)

    const third = store.page(second.nextIndex, 4)
    assert.deepEqual(third.items.map((e) => e['i']), [8, 9])

    // No new records: nextIndex stays put, items is empty.
    const idle = store.page(third.nextIndex, 4)
    assert.equal(idle.items.length, 0)
    assert.equal(idle.nextIndex, 9, 'with no new records nextIndex equals sinceIndex')
  })
})

test('walking page() to exhaustion is neither lossy nor duplicating', async () => {
  await withStore(async (store) => {
    for (let i = 0; i < 250; i++) store.append({ i })
    await store.flush()
    let cursor = -1
    const seen = []
    for (;;) {
      const page = store.page(cursor, 7)
      if (page.items.length === 0) break
      for (const e of page.items) seen.push(e['i'])
      cursor = page.nextIndex
    }
    // Ring is 100, so absolute 150..249 survive; the walk must return exactly them.
    assert.deepEqual(seen, Array.from({ length: 100 }, (_, k) => 150 + k))
  })
})

test('after a ring overflow, firstIndex > 0 and evicted records are not served', async () => {
  await withStore(async (store) => {
    for (let i = 0; i < 250; i++) store.append({ i })
    await store.flush()

    const page = store.page(-1, 10)
    assert.equal(page.windowed, true)
    assert.equal(page.firstIndex, 150)
    assert.equal(page.total, 250)
    // A fresh cursor still cannot reach below firstIndex.
    assert.deepEqual(page.items.map((e) => e['i']), [150, 151, 152, 153, 154, 155, 156, 157, 158, 159])

    // The "caller missed records" signal: cursor older than firstIndex - 1.
    const stale = store.page(10, 5)
    assert.equal(stale.firstIndex, 150)
    assert.ok(stale.firstIndex > 10 + 1, 'records 11..149 were evicted before this cursor')
    assert.equal(stale.items[0]['i'], 150, 'only the oldest SURVIVING record is served')
  })
})

test('window()/list() keep returning the whole ring', async () => {
  await withStore(async (store) => {
    for (let i = 0; i < 250; i++) store.append({ i })
    await store.flush()

    const win = store.window()
    assert.equal(win.items.length, 100)
    assert.equal(win.total, 250)
    assert.equal(win.windowed, true)
    assert.equal(win.items[0]['i'], 150)

    const list = store.list()
    assert.equal(list.length, 100)
    assert.equal(list[99]['i'], 249)
  })
})

test('archive rotates the file, resets counters and keeps writing to a fresh file', async () => {
  await withStore(async (store, file, dir) => {
    for (let i = 0; i < 5; i++) store.append({ i })
    await store.flush()
    const before = store.list()
    assert.equal(before.length, 5)

    const result = await store.archive()
    assert.ok(result.archivedPath !== null, 'archive must report where the file went')
    assert.equal(result.records, 5)
    assert.ok(result.bytes > 0, 'bytes is the pre-rotation file size')

    // Rotated name: <base>.<UTC stamp>.jsonl, inside the same directory.
    assert.match(result.archivedPath, /audit\.\d{4}-\d{2}-\d{2}T[\d-]+Z\.jsonl$/)
    assert.equal(result.archivedPath.startsWith(dir), true, 'rotation stays in the same directory')
    assert.equal(existsSync(result.archivedPath), true)
    assert.equal(existsSync(file), false, 'the live file was renamed away')

    const archivedLines = readFileSync(result.archivedPath, 'utf8').trim().split('\n')
    assert.equal(archivedLines.length, 5, 'every flushed record is in the archive')

    // Counters and ring are reset; the new file is empty.
    const empty = store.page(-1, 10)
    assert.equal(empty.total, 0)
    assert.equal(empty.items.length, 0)
    assert.equal(empty.windowed, false)

    // Appending again is read back from the NEW file (offset was reset).
    store.append({ i: 99 })
    await store.flush()
    const after = store.page(-1, 10)
    assert.equal(after.total, 1)
    assert.deepEqual(after.items.map((e) => e['i']), [99])
    assert.equal(store.list().length, 1)
  })
})

test('archive on a missing file reports zero instead of throwing', async () => {
  await withStore(async (store, file) => {
    assert.equal(existsSync(file), false, 'no append happened, so no file exists yet')
    const result = await store.archive()
    assert.equal(result.archivedPath, null)
    assert.equal(result.records, 0)
    assert.equal(result.bytes, 0)
  })
})
