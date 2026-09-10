/**
 * Stable console address (V0.5.1).
 *
 * Field failure this covers: with two MCP processes alive (the custom
 * `~/.workbuddy/mcp.json` entry plus the installed connector) the second one
 * hit EADDRINUSE, fell back to an ephemeral port and handed the model
 * `http://127.0.0.1:52490/?token=…`. That process was then replaced by a
 * config reload, so the URL the user finally clicked was dead and the page
 * showed 工作台已失效.
 *
 * The fix: one fixed address per workspace, token injected into the page
 * instead of the URL, and whichever process survives re-binds that address.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  auditViewerUrl,
  consoleHintForModel,
  consoleHintPending,
  startAuditViewer,
  stopAuditViewer,
} from '../../lib/runtime/audit-viewer.js'

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

/**
 * Boot a stable-mode console on a specific port and wait until it serves.
 * `stableUrl` is the default; passing it explicitly documents the intent.
 */
async function boot(port) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-stable-'))
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: true, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai' },
  )
  await waitFor(async () => {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`)
      return res.status === 200
    } catch {
      return false
    }
  })
  return `http://127.0.0.1:${port}/`
}

async function waitFor(check, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    if (await check()) return true
    if (Date.now() > deadline) return false
    await new Promise((r) => setTimeout(r, 100))
  }
}

test.afterEach(() => {
  stopAuditViewer()
})

test('stable mode hands over a token-free, fixed address', async () => {
  const port = await freePort()
  const url = await boot(port)
  assert.equal(url, `http://127.0.0.1:${port}/`)
  assert.equal(auditViewerUrl(), url)
  assert.equal(url.includes('token'), false)
})

test('GET / works without a token but still embeds the access token in the page', async () => {
  const port = await freePort()
  await boot(port)
  const res = await fetch(`http://127.0.0.1:${port}/`)
  assert.equal(res.status, 200)
  const html = await res.text()
  assert.match(html, /<title>JumpServer MCP 控制台<\/title>/)
  // The page must carry a usable token or /api/* would be unreachable.
  const injected = html.match(/var TOKEN = .*\|\| "([0-9a-f]{16,})";/)
  assert.ok(injected !== null, 'the page should embed the current access token')
})

test('/api/* is still gated: no token => 403, embedded token => 200', async () => {
  const port = await freePort()
  await boot(port)
  const base = `http://127.0.0.1:${port}/`

  const anonymous = await fetch(base + 'api/entries')
  assert.equal(anonymous.status, 403)

  const html = await (await fetch(base)).text()
  const token = html.match(/\|\| "([0-9a-f]{16,})";/)[1]
  const authorized = await fetch(base + 'api/entries', { headers: { 'x-console-token': token } })
  assert.equal(authorized.status, 200)
})

test('a cross-origin page cannot reach the console even at the token-free address', async () => {
  const port = await freePort()
  await boot(port)
  // fetch() silently drops forbidden headers such as Origin, so drive the raw
  // http client: a browser page's cross-origin request DOES reach the socket,
  // and that is exactly what has to be refused.
  const probe = (headers) =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/', method: 'GET', headers }, (res) => {
        res.resume()
        resolve(res.statusCode)
      })
      req.on('error', reject)
      req.end()
    })
  assert.equal(await probe({ origin: 'http://evil.example' }), 403)
  assert.equal(await probe({}), 200)
})

test('EADDRINUSE adopts the occupied address instead of inventing a random port', async () => {
  const port = await freePort()
  const blocker = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('BLOCKER')
  })
  await new Promise((resolve) => blocker.listen(port, '127.0.0.1', resolve))

  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-adopt-'))
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: true, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai' },
  )

  // The handover URL must be the SAME address the owner serves — not a 52xxx.
  await waitFor(async () => auditViewerUrl() !== null)
  assert.equal(auditViewerUrl(), `http://127.0.0.1:${port}/`)

  // And it must really be the other process answering right now.
  const during = await (await fetch(`http://127.0.0.1:${port}/`)).text()
  assert.equal(during, 'BLOCKER')

  // When the owner exits, this process takes the address over and the
  // already-open page recovers by itself (this is the 工作台已失效 fix).
  await new Promise((resolve) => blocker.close(resolve))
  const tookOver = await waitFor(async () => {
    try {
      const body = await (await fetch(`http://127.0.0.1:${port}/`)).text()
      return body.includes('<title>JumpServer MCP 控制台</title>')
    } catch {
      return false
    }
  }, 12000)
  assert.equal(tookOver, true, 'the surviving process should re-bind the address within one heartbeat')
})

test('the hint nags until the page has actually been fetched', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-hint-'))
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: true, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai' },
  )
  // Wait for the LISTENER without fetching the page (an /api/* 403 proves the
  // gate is answering; GET / would mark the console as opened).
  await waitFor(async () => {
    try {
      return (await fetch(`http://127.0.0.1:${port}/api/entries`)).status === 403
    } catch {
      return false
    }
  })

  // Bound but never opened: the handover must keep repeating. A single
  // first-response hint is what the model parked until the task was over.
  assert.equal(consoleHintPending(), true)
  const hint = consoleHintForModel()
  assert.ok(hint !== null && hint.includes(`http://127.0.0.1:${port}/`))
  assert.match(hint, /启动阶段/)

  // Opening the page settles it — no more nagging.
  await fetch(`http://127.0.0.1:${port}/`)
  assert.equal(consoleHintPending(), false)
})
