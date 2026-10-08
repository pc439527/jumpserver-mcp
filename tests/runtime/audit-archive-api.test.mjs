/**
 * Console API: paged audit reads + archive rotation (V0.5.10).
 *
 * The wire contract that matters here:
 *   - `/api/entries` with NO query keeps returning a plain ARRAY (older callers
 *     and existing tests depend on it);
 *   - `/api/entries?since=&limit=` returns the paged envelope;
 *   - `POST /api/audit/archive` sits behind the same console-token gate as every
 *     other /api/* route and only ever echoes the archived file NAME.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'
import { AuditStore } from '../../lib/runtime/audit-store.js'

/** Pick a free port, then give it back so startAuditViewer can take it. */
async function freePort() {
  return await new Promise((resolve) => {
    const probe = http.createServer()
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolve(port))
    })
  })
}

function boot(dir, port, audit) {
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: true, portFallback: true, stableUrl: true },
    null,
    { audit, timeZone: 'Asia/Shanghai' },
  )
}

const base = (port) => `http://127.0.0.1:${port}`

function tokenOf(html) {
  const match = html.match(/\|\| "([0-9a-f]{16,})";/)
  assert.ok(match !== null, 'the page should embed the access token')
  return match[1]
}

/** The listener may still be binding right after boot(); retry briefly. */
async function fetchOk(url, init) {
  const deadline = Date.now() + 5000
  for (;;) {
    try {
      return await fetch(url, init)
    } catch (error) {
      if (Date.now() > deadline) throw error
      await new Promise((r) => setTimeout(r, 50))
    }
  }
}

test.afterEach(() => {
  stopAuditViewer()
})

test('/api/entries paginates with since/limit and stays an array without params', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-audit-api-'))
  const store = new AuditStore(join(dir, 'audit.jsonl'), { ringSize: 100, log: () => undefined })
  for (let i = 0; i < 3; i++) store.append({ operation: 'exec', i })
  await store.flush()
  boot(dir, port, store)
  try {
    const token = tokenOf(await (await fetchOk(base(port) + '/')).text())

    const paged = await (await fetchOk(base(port) + `/api/entries?since=-1&limit=2&token=${token}`)).json()
    assert.equal(Array.isArray(paged), false, 'a paged read returns an envelope')
    assert.equal(paged.items.length, 2)
    assert.equal(paged.items[0].i, 0)
    assert.equal(paged.total, 3)
    assert.equal(paged.nextIndex, 1)
    assert.equal(paged.windowed, false)
    assert.equal(paged.firstIndex, 0)

    const next = await (await fetchOk(base(port) + `/api/entries?since=${paged.nextIndex}&limit=2&token=${token}`)).json()
    assert.deepEqual(next.items.map((e) => e.i), [2])
    assert.equal(next.nextIndex, 2)

    // No since/limit => the historical whole-array response is preserved.
    const all = await (await fetchOk(base(port) + '/api/entries?token=' + token)).json()
    assert.equal(Array.isArray(all), true)
    assert.equal(all.length, 3)
  } finally {
    stopAuditViewer()
  }
})

test('/api/entries falls back to positional paging when no AuditStore is wired', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-audit-api-fallback-'))
  // The no-store path reads the file directly, so seed it on disk.
  const lines = [0, 1, 2].map((i) => JSON.stringify({ operation: 'exec', i })).join('\n') + '\n'
  writeFileSync(join(dir, 'audit.jsonl'), lines, 'utf8')
  boot(dir, port, null)
  try {
    const token = tokenOf(await (await fetchOk(base(port) + '/')).text())
    const paged = await (await fetchOk(base(port) + `/api/entries?since=-1&limit=2&token=${token}`)).json()
    assert.equal(Array.isArray(paged), false)
    assert.equal(paged.items.length, 2)
    assert.equal(paged.total, 3)
    assert.equal(paged.nextIndex, 1)
    assert.equal(paged.windowed, false)
  } finally {
    stopAuditViewer()
  }
})

test('POST /api/audit/archive without a token is rejected and rotates nothing', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-audit-archive-auth-'))
  const store = new AuditStore(join(dir, 'audit.jsonl'), { ringSize: 100, log: () => undefined })
  store.append({ i: 1 })
  await store.flush()
  boot(dir, port, store)
  try {
    const res = await fetchOk(base(port) + '/api/audit/archive', { method: 'POST' })
    assert.equal(res.status, 403)
    assert.equal(existsSync(join(dir, 'audit.jsonl')), true, 'a rejected archive must not rotate')
  } finally {
    stopAuditViewer()
  }
})

test('POST /api/audit/archive with a token rotates the file and reports the new name', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-audit-archive-'))
  const store = new AuditStore(join(dir, 'audit.jsonl'), { ringSize: 100, log: () => undefined })
  for (let i = 0; i < 3; i++) store.append({ i })
  await store.flush()
  boot(dir, port, store)
  try {
    const token = tokenOf(await (await fetchOk(base(port) + '/')).text())
    const res = await fetchOk(base(port) + '/api/audit/archive?token=' + token, { method: 'POST' })
    assert.equal(res.status, 200)
    const body = await res.json()
    assert.equal(body.archived, true)
    assert.equal(body.records, 3)
    assert.ok(body.bytes > 0)
    // Only the file NAME crosses the wire — no full disk path.
    assert.match(body.file, /^audit\.\d{4}-\d{2}-\d{2}T[\d-]+Z\.jsonl$/)
    assert.equal(existsSync(join(dir, body.file)), true)
    assert.equal(existsSync(join(dir, 'audit.jsonl')), false)

    // The server-side stream is reset, so the next read starts empty.
    const after = await (await fetchOk(base(port) + `/api/entries?since=-1&limit=10&token=${token}`)).json()
    assert.equal(after.total, 0)
    assert.equal(after.items.length, 0)
  } finally {
    stopAuditViewer()
  }
})

test('POST /api/audit/archive reports not-archived when no AuditStore is configured', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-audit-archive-none-'))
  boot(dir, port, null)
  try {
    const token = tokenOf(await (await fetchOk(base(port) + '/')).text())
    const res = await fetchOk(base(port) + '/api/audit/archive?token=' + token, { method: 'POST' })
    assert.equal(res.status, 200)
    const body = await res.json()
    assert.equal(body.archived, false)
    assert.equal(body.file, null)
    assert.equal(body.records, 0)
    assert.equal(body.bytes, 0)
  } finally {
    stopAuditViewer()
  }
})
