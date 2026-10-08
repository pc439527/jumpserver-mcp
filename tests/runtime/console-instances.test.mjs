/**
 * Multi-instance console (V0.5.4).
 *
 * Field failure this covers: with two WorkBuddy conversations open, each one
 * spawns its own MCP process. Only the process that won the stable port served
 * a console; the loser adopted the SAME address and served nothing — so both
 * preview panels showed ONE terminal, and the page's 中断当前命令 button acted
 * on the port owner's sessions rather than the caller's. A real
 * cross-conversation side effect, not just a cosmetic confusion.
 *
 * The fix: a process that loses the race still binds its OWN loopback port and
 * publishes { role, port, summary } in its discovery file. Every page lists the
 * live instances and embeds the selected one — the embedded page injects its
 * own token, so no shared secret is introduced and the token model is unchanged.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { consoleHintForModel, startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'

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

function boot(dir, port) {
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: true, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai' },
  )
}

/** Resolve with the first truthy value the check returns, else null on timeout. */
async function waitForValue(check, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = check()
    if (value) return value
    if (Date.now() > deadline) return null
    await new Promise((r) => setTimeout(r, 100))
  }
}

function heartbeatOf(dir, pid = process.pid) {
  const file = join(dir, 'consoles', String(pid) + '.json')
  if (!existsSync(file)) return null
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
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

test.afterEach(() => {
  stopAuditViewer()
})

test('a process that loses the port race still serves its own console', async () => {
  const port = await freePort()
  const blocker = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('BLOCKER')
  })
  await new Promise((resolve) => blocker.listen(port, '127.0.0.1', resolve))

  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-inst-'))
  boot(dir, port)

  try {
    // Before V0.5.4 the loser published NOTHING (writeConsoleFile only ran once
    // this process owned a port), which is why a second conversation was invisible.
    const hb = await waitForValue(() => {
      const entry = heartbeatOf(dir)
      return entry !== null && Number(entry.port) > 0 ? entry : null
    })
    assert.ok(hb !== null, 'the follower must publish a discovery file')
    assert.equal(hb.role, 'follower')
    assert.notEqual(hb.port, port, 'the follower must not claim the shared address')

    // Its private port serves the real console — this is what the picker embeds.
    const page = await fetch(`http://127.0.0.1:${hb.port}/`)
    assert.equal(page.status, 200)
    const html = await page.text()
    assert.match(html, /<title>JumpServer MCP 控制台<\/title>/)
    assert.ok(html.includes('var SELFPID = ' + process.pid + ';'), 'the page must know its own instance')
    assert.ok(html.includes('id="instsel"'), 'the page needs the instance picker')
    assert.ok(html.includes('id="fwframe"'), 'the page needs the embed target')
    // The old label read 「当前对话」 for a PTY session id — that is what made an
    // operator read another conversation's terminal as their own.
    assert.equal(html.includes('当前对话'), false)
  } finally {
    // Always release the blocker: a lingering listener keeps the test runner's
    // event loop alive and hangs the whole suite instead of failing one test.
    await new Promise((resolve) => blocker.close(resolve))
  }
})

test('/api/instances lists every live instance and marks this one', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-inst-list-'))
  boot(dir, port)
  const hb = await waitForValue(() => heartbeatOf(dir))
  assert.ok(hb !== null)
  assert.equal(hb.role, 'owner')

  // Another conversation's MCP process, as it appears on disk to this one.
  const other = 99999999
  writeHeartbeat(dir, {
    pid: other,
    port: 45678,
    role: 'follower',
    startedAt: new Date().toISOString(),
    heartbeatAt: new Date().toISOString(),
    tokenExpiresAt: null,
    summary: { state: 'ASSET_SHELL', target: '10.0.0.9', sessions: 1 },
  })

  const html = await (await fetch(`http://127.0.0.1:${port}/`)).text()
  const res = await fetch(`http://127.0.0.1:${port}/api/instances?token=${tokenOf(html)}`)
  assert.equal(res.status, 200)
  const list = await res.json()

  assert.equal(list.selfPid, process.pid)
  assert.equal(list.selfRole, 'owner')
  assert.deepEqual(
    list.instances.map((i) => i.pid).sort((a, b) => a - b),
    [process.pid, other].sort((a, b) => a - b),
  )
  const self = list.instances.find((i) => i.pid === process.pid)
  assert.equal(self.self, true)
  assert.equal(self.url, `http://127.0.0.1:${port}/`)
  const foreign = list.instances.find((i) => i.pid === other)
  assert.equal(foreign.self, false)
  assert.equal(foreign.role, 'follower')
  assert.equal(foreign.target, '10.0.0.9')
  assert.equal(foreign.sessions, 1)
  assert.equal(foreign.url, 'http://127.0.0.1:45678/')
  // The picker defaults to YOUR own console: self sorts first.
  assert.equal(list.instances[0].self, true)
})

test('a stale discovery file is not offered as a live instance', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-inst-stale-'))
  boot(dir, port)
  await waitForValue(() => heartbeatOf(dir))

  const dead = 88888888
  writeHeartbeat(dir, {
    pid: dead,
    port: 45679,
    role: 'follower',
    startedAt: new Date(Date.now() - 600_000).toISOString(),
    heartbeatAt: new Date(Date.now() - 60_000).toISOString(),
    tokenExpiresAt: null,
    summary: { state: 'DISCONNECTED', target: null, sessions: 0 },
  })

  const html = await (await fetch(`http://127.0.0.1:${port}/`)).text()
  const list = await (await fetch(`http://127.0.0.1:${port}/api/instances?token=${tokenOf(html)}`)).json()
  assert.equal(list.instances.some((i) => i.pid === dead), false)
})

test('/api/instances is gated by the console token like every other endpoint', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-inst-auth-'))
  boot(dir, port)
  const res = await fetch(`http://127.0.0.1:${port}/api/instances`)
  assert.equal(res.status, 403)
})

test('the handover URL pins the instance that asked for the console', async () => {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-inst-hint-'))
  boot(dir, port)
  await waitForValue(() => heartbeatOf(dir))

  const hint = consoleHintForModel()
  assert.ok(hint !== null)
  // Two conversations hand out the same stable address but different ?inst=,
  // so each one's preview panel lands on its own sessions.
  assert.ok(hint.includes(`http://127.0.0.1:${port}/?inst=${process.pid}`), hint)
})
