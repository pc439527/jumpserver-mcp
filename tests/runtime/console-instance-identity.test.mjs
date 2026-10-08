/**
 * Console instance IDENTITY (V0.5.8).
 *
 * Field failure this covers: the handover URL is the SHARED stable address
 * (`http://127.0.0.1:8765/`) plus `?inst=<pid>`. Whoever owns that port answers
 * the request — and with two WorkBuddy conversations open that is very often
 * NOT the conversation that asked for the console. A fresh conversation (its
 * MCP process a follower on a private loopback port) opened its own link and
 * got: 「正在查看另一个实例（pid <自己的 pid>）… 该实例属于另一个对话」 over its
 * OWN terminal, with a 「切回本实例」 button pointing at somebody else's session.
 * Content was right; identity was inverted.
 *
 * Tested here: the pure handover decision, and the fact that the served page
 * carries the requesting pid (so the client can land on the right instance) and
 * no longer hardcodes the page-serving process as 「本实例」.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { resolveConsoleHandover, startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'

async function freePort() {
  return await new Promise((resolve) => {
    const probe = http.createServer()
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolve(port))
    })
  })
}

function boot(dir, port) {
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: true, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai' },
  )
}

/** Resolve with the first truthy value the check returns, else null on timeout. */
async function waitFor(check, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = check()
    if (value) return value
    if (Date.now() > deadline) return null
    await new Promise((r) => setTimeout(r, 100))
  }
}

/** This process's own discovery file, once it has been written. */
function ownHeartbeat(dir) {
  try {
    return JSON.parse(readFileSync(join(dir, 'consoles', String(process.pid) + '.json'), 'utf8'))
  } catch {
    return null
  }
}

function writeHeartbeat(dir, entry) {
  writeFileSync(join(dir, 'consoles', String(entry.pid) + '.json'), JSON.stringify(entry) + '\n', 'utf8')
}

function tokenOf(html) {
  const match = html.match(/\|\| "([0-9a-f]{16,})";/)
  assert.ok(match !== null, 'the page should embed the access token')
  return match[1]
}

const live = (pid, port, target = null) => ({
  pid,
  port,
  role: 'follower',
  startedAt: new Date().toISOString(),
  ageMs: 0,
  self: false,
  state: target === null ? 'none' : 'ASSET_SHELL',
  target,
  sessions: target === null ? 0 : 1,
  url: 'http://127.0.0.1:' + String(port) + '/',
})

test.afterEach(() => {
  stopAuditViewer()
})

test('resolveConsoleHandover: hands the browser to the asking conversation', () => {
  const instances = [live(34886, 18765, '192.168.78.82'), live(10960, 8765)]
  // The page is served by 10960 (owner of the shared address); 34886 asked for it.
  assert.equal(resolveConsoleHandover(34886, 10960, 8765, instances), 'http://127.0.0.1:18765/?inst=34886')
})

test('resolveConsoleHandover: stays put when there is nothing to move to', () => {
  const instances = [live(34886, 18765), live(10960, 8765)]
  // No ?inst= — a plain bookmark keeps the address it always had.
  assert.equal(resolveConsoleHandover(null, 10960, 8765, instances), null)
  // ?inst= names this very process: the page IS the right console.
  assert.equal(resolveConsoleHandover(10960, 10960, 8765, instances), null)
  // An unknown / already-dead id must not redirect into a void.
  assert.equal(resolveConsoleHandover(4242, 10960, 8765, instances), null)
  // Same listener published twice (an owner that has not rebound yet).
  assert.equal(resolveConsoleHandover(34886, 10960, 18765, [live(34886, 18765)]), null)
  // Garbage parameters.
  assert.equal(resolveConsoleHandover(0, 10960, 8765, instances), null)
  assert.equal(resolveConsoleHandover(Number.NaN, 10960, 8765, instances), null)
})

test('resolveConsoleHandover: legacy token URL keeps a valid query string', () => {
  const legacy = { ...live(34886, 18765), url: 'http://127.0.0.1:18765/?token=abc' }
  assert.equal(resolveConsoleHandover(34886, 10960, 8765, [legacy]), 'http://127.0.0.1:18765/?token=abc&inst=34886')
})

test('the served page knows which conversation asked for it', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-ident-'))
  boot(dir, port)
  const other = 99999988
  const otherPort = await freePort()
  await waitFor(() => ownHeartbeat(dir))
  writeHeartbeat(dir, {
    pid: other,
    port: otherPort,
    role: 'follower',
    startedAt: new Date().toISOString(),
    heartbeatAt: new Date().toISOString(),
    tokenExpiresAt: null,
    summary: { state: 'ASSET_SHELL', target: '192.168.78.82', sessions: 1 },
  })

  const html = await (await fetch(`http://127.0.0.1:${port}/?inst=${other}`)).text()
  assert.ok(html.includes('var SELFPID = ' + process.pid + ';'), 'the page still knows who serves it')
  assert.ok(html.includes('var OPENPID = ' + other + ';'), 'the page must know who ASKED for it')
  assert.ok(
    html.includes('var HANDOVER = "http://127.0.0.1:' + otherPort + '/?inst=' + other + '";'),
    'the page must be told where the asking conversation really lives',
  )
  // 🔒 The inversion fix: the ASKING conversation is 「本实例」; the process that
  // happened to answer the shared port is named for what it is.
  assert.ok(html.includes("if (pid === HOME) return '本实例';"), 'the asking conversation is 本实例')
  assert.ok(html.includes("if (pid === SELFPID) return '本页服务进程';"), 'the serving process is named honestly')
  assert.ok(html.includes('切换到本页服务进程'), 'the button must describe where it actually goes')
  assert.ok(html.includes('本对话实例'), 'the fallback notice names the conversation, not a stranger')

  // Self-reference (a process opening its own link) and a plain bookmark must
  // not move the browser at all.
  const self = await (await fetch(`http://127.0.0.1:${port}/?inst=${process.pid}`)).text()
  assert.ok(self.includes('var HANDOVER = null;'))
  const plain = await (await fetch(`http://127.0.0.1:${port}/`)).text()
  assert.ok(plain.includes('var OPENPID = null;'))
  assert.ok(plain.includes('var HANDOVER = null;'))

  // An embedded page never re-locates: it IS the target.
  const embedded = await (await fetch(`http://127.0.0.1:${port}/?inst=${other}&embed=1`)).text()
  assert.ok(embedded.includes('var OPENPID = null;'), 'embed mode must not inherit a redirect')

  // The probe the page uses before leaving is token-free and carries nothing.
  const ping = await fetch(`http://127.0.0.1:${port}/ping`)
  assert.equal(ping.status, 204)
  assert.equal(await ping.text(), '')
})

test('/api/instances keeps reporting who serves the page', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-ident-pick-'))
  boot(dir, port)
  await waitFor(() => ownHeartbeat(dir))
  const html = await (await fetch(`http://127.0.0.1:${port}/`)).text()
  const list = await (await fetch(`http://127.0.0.1:${port}/api/instances?token=${tokenOf(html)}`)).json()
  assert.equal(list.selfPid, process.pid)
  // `self` still means "the process serving this page" — the human-facing label
  // now comes from HOME (= OPENPID) instead.
  assert.equal(list.instances.find((i) => i.pid === process.pid).self, true)
})
