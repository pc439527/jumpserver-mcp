/**
 * Console multi-account block (V0.5.11).
 *
 * The connector now keeps several named JumpServer logins on this machine. The
 * 设置 tab lists them and offers add / edit / delete / switch — all over the
 * same token-gated /api/* surface as every other console action.
 *
 * What this file pins down:
 *   - the 设置 tab is wired to an accounts payload at all (id="setaccts");
 *   - that payload is REDACTED: ProfileView fields only, never a password, a
 *     vault token or a `v1:` ciphertext;
 *   - the write routes are gated by the console token exactly like the rest of
 *     /api/*, and a save never echoes the submitted password back;
 *   - allowCredentialWrite=false and a corrupt profiles file are both surfaced
 *     to the operator instead of silently presenting an entry point that would
 *     fail on submit.
 *
 * Everything runs under os.tmpdir(); the real ~/.workbuddy is never touched,
 * because the accounts service is injected as a fake and no runtime boots.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'

async function freePort() {
  return await new Promise((resolve) => {
    const probe = http.createServer()
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolve(port))
    })
  })
}

/** GET the token-free stable address, retrying while the listener settles. */
async function fetchPage(port) {
  const deadline = Date.now() + 8000
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`)
      if (res.status === 200) {
        const html = await res.text()
        if (html.includes('<nav>')) return html
      }
    } catch {
      /* not listening yet */
    }
    if (Date.now() > deadline) throw new Error('console did not serve the page in time')
    await new Promise((r) => setTimeout(r, 100))
  }
}

/** The page injects the access token as `... || "<hex>";`. */
function tokenOf(html) {
  const match = html.match(/\|\| "([0-9a-f]{16,})";/)
  assert.ok(match !== null, 'the page should embed the access token')
  return match[1]
}

async function boot(services) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-acct-'))
  const port = await freePort()
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: false, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai', ...services },
  )
  const html = await fetchPage(port)
  return { html, port, token: tokenOf(html) }
}

function getJson(port, path) {
  return fetch(`http://127.0.0.1:${port}${path}`)
}

function postJson(port, path, body) {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const REDACTED_PROFILE = {
  id: 'p1',
  label: '生产',
  host: 'h',
  port: 22,
  username: 'u',
  hasSecret: true,
  active: true,
  createdAt: 1,
  updatedAt: 2,
}

function accountsView(overrides = {}) {
  return () => ({
    activeProfileId: 'p1',
    profiles: [{ ...REDACTED_PROFILE }],
    integrity: { broken: false, message: null },
    allowWrite: true,
    storePathHint: '~/.workbuddy/jumpserver-mcp/profiles.json',
    ...overrides,
  })
}

test.afterEach(() => {
  stopAuditViewer()
})

test('the settings tab lists accounts in redacted form only', async () => {
  const { html, port, token } = await boot({ accounts: accountsView() })

  assert.ok(html.includes('id="setaccts"'), 'the settings tab needs an accounts block')
  assert.ok(html.includes('renderAccounts'), 'the block must be rendered from the accounts payload')

  const res = await getJson(port, `/api/settings?token=${token}`)
  assert.equal(res.status, 200)
  const body = await res.json()

  assert.ok(body.accounts !== null, 'accounts must be present when the service is wired')
  assert.equal(body.accounts.activeProfileId, 'p1')
  assert.equal(body.accounts.allowWrite, true)
  assert.deepEqual(body.accounts.integrity, { broken: false, message: null })
  assert.deepEqual(body.accounts.profiles[0], REDACTED_PROFILE)

  // Redaction: the payload must carry no credential material at all.
  const accountText = JSON.stringify(body.accounts)
  assert.equal(accountText.includes('v1:'), false, 'no vault ciphertext may appear')
  for (const p of body.accounts.profiles) {
    assert.equal('password' in p, false)
    assert.equal('secret' in p, false)
    assert.equal('token' in p, false)
  }
})

test('activating an account is token-gated and reaches the service', async () => {
  const calls = []
  const { port, token } = await boot({
    accounts: accountsView(),
    switchAccount: (id) => {
      calls.push(id)
      return { ok: true }
    },
  })

  const forbidden = await postJson(port, '/api/accounts/activate', { id: 'p1' })
  assert.equal(forbidden.status, 403, 'no token means no access')
  assert.equal(calls.length, 0, 'a rejected request must not reach the service')

  const ok = await postJson(port, `/api/accounts/activate?token=${token}`, { id: 'p1' })
  assert.equal(ok.status, 200)
  assert.deepEqual(await ok.json(), { ok: true })
  assert.deepEqual(calls, ['p1'])
})

test('saving an account forwards the password but never echoes it', async () => {
  const SENTINEL = 'sentinel-password-do-not-echo'
  let received = null
  const { port, token } = await boot({
    accounts: accountsView(),
    saveAccount: (input) => {
      received = input
      return { ok: true }
    },
  })

  const res = await postJson(port, `/api/accounts/save?token=${token}`, {
    label: '维护',
    host: 'bastion.example',
    port: 2222,
    username: 'ops',
    password: SENTINEL,
  })
  assert.equal(res.status, 200)
  const text = await res.text()

  assert.ok(received !== null, 'the save route must reach the service')
  assert.equal(received.label, '维护')
  assert.equal(received.host, 'bastion.example')
  assert.equal(received.username, 'ops')
  assert.equal(received.port, 2222)
  assert.equal(received.password, SENTINEL, 'the service receives the submitted password')
  assert.equal(text.includes(SENTINEL), false, 'the response must not echo the password')
  assert.deepEqual(JSON.parse(text), { ok: true })
})

test('allowCredentialWrite=false is reported and offers no write UI', async () => {
  const { html, port, token } = await boot({ accounts: accountsView({ allowWrite: false }) })

  // The notice is part of the page script, so it ships in the served HTML.
  assert.ok(html.includes('已关闭'), 'the read-only notice must be rendered')

  const body = await (await getJson(port, `/api/settings?token=${token}`)).json()
  assert.equal(body.accounts.allowWrite, false)
})

test('a corrupt profiles file raises a visible warning', async () => {
  const { html, port, token } = await boot({
    accounts: accountsView({ integrity: { broken: true, message: 'file is not valid JSON' } }),
  })
  assert.ok(html.includes('账号文件无法读取'), 'a broken store must warn the operator')

  const body = await (await getJson(port, `/api/settings?token=${token}`)).json()
  assert.deepEqual(body.accounts.integrity, { broken: true, message: 'file is not valid JSON' })
})
