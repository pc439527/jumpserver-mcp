/**
 * Console /api/* same-origin gate + structured delete errors (V0.5.12).
 *
 * Field finding: the console's own comment promised "cross-origin callers are
 * still refused outright", but only the token-free `GET /` shortcut actually
 * consulted the Origin header. Every /api/* route — including the account write
 * routes and the side-effecting interrupt / close / stop POSTs — was gated by
 * the token ALONE, so a page on another origin that learned a valid token could
 * drive them (reproduced with `POST /api/accounts/activate` + a foreign Origin).
 *
 * What this file pins down:
 *   - a cross-origin /api/* request is refused with 403 EVEN with a valid token,
 *     and the injected service is never called (zero side effect);
 *   - the normal path is untouched: a token-bearing request WITHOUT Origin still
 *     reaches the service;
 *   - an anonymous cross-origin request is still 403;
 *   - the stable-address `GET /` token-free shortcut still serves the page;
 *   - /api/accounts/remove passes the service's structured {ok,error} straight
 *     through, and the body never carries a password or a `v1:` ciphertext.
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

/**
 * Raw http client. fetch() silently drops forbidden headers such as Origin, so
 * a browser-style cross-origin request has to be driven by hand — which is
 * exactly the request a foreign page makes and the one that must be refused.
 */
function rawRequest(port, { method = 'GET', path = '/', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === null ? null : Buffer.from(body)
    const outgoing = { ...headers }
    if (payload !== null && outgoing['content-length'] === undefined) outgoing['content-length'] = payload.length
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: outgoing }, (res) => {
      let text = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        text += chunk
      })
      res.on('end', () => resolve({ status: res.statusCode, body: text, headers: res.headers }))
    })
    req.on('error', reject)
    if (payload !== null) req.write(payload)
    req.end()
  })
}

/** GET the token-free stable address, retrying while the listener settles. */
async function fetchPage(port) {
  const deadline = Date.now() + 8000
  for (;;) {
    try {
      const res = await rawRequest(port, { path: '/' })
      if (res.status === 200 && res.body.includes('<nav>')) return res.body
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
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-origin-'))
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

const EVIL = 'http://evil.example'

test.afterEach(() => {
  stopAuditViewer()
})

test('a cross-origin write with a VALID token is refused with no side effect', async () => {
  let calls = 0
  const { port, token } = await boot({
    switchAccount: () => {
      calls += 1
      return { ok: true }
    },
  })

  const res = await rawRequest(port, {
    method: 'POST',
    path: '/api/accounts/activate',
    headers: {
      'content-type': 'application/json',
      'x-console-token': token,
      origin: EVIL,
    },
    body: JSON.stringify({ id: 'p1' }),
  })

  assert.equal(res.status, 403, 'a cross-origin request must not be accepted even with a valid token')
  assert.equal(calls, 0, 'the service must never be reached — no side effect')
  assert.equal(res.body.includes('"ok":true'), false)
})

test('the same write WITHOUT Origin still reaches the service exactly once', async () => {
  let calls = 0
  const { port, token } = await boot({
    switchAccount: () => {
      calls += 1
      return { ok: true }
    },
  })

  const res = await rawRequest(port, {
    method: 'POST',
    path: '/api/accounts/activate',
    headers: {
      'content-type': 'application/json',
      'x-console-token': token,
    },
    body: JSON.stringify({ id: 'p1' }),
  })

  assert.equal(res.status, 200, 'a local token-bearing call must keep working')
  assert.deepEqual(JSON.parse(res.body), { ok: true })
  assert.equal(calls, 1)
})

test('an anonymous cross-origin request is still 403', async () => {
  let calls = 0
  const { port } = await boot({
    switchAccount: () => {
      calls += 1
      return { ok: true }
    },
  })

  const res = await rawRequest(port, {
    method: 'POST',
    path: '/api/accounts/activate',
    headers: { 'content-type': 'application/json', origin: EVIL },
    body: JSON.stringify({ id: 'p1' }),
  })

  assert.equal(res.status, 403)
  assert.equal(calls, 0)
})

test('the stable-address GET / shortcut stays token-free', async () => {
  const { html } = await boot({ accounts: () => ({ profiles: [] }) })
  assert.ok(html.includes('<nav>'), 'the page must be served without a token')
  assert.ok(html.includes('id="setaccts"'))
})

test('removeAccount errors pass through and no credential material is echoed', async () => {
  const SENTINEL = 'sentinel-password-do-not-echo'
  const seen = []
  const { port, token } = await boot({
    removeAccount: (id) => {
      seen.push(id)
      return { ok: false, error: 'PROFILE_NOT_FOUND' }
    },
  })

  const res = await rawRequest(port, {
    method: 'POST',
    path: '/api/accounts/remove',
    headers: {
      'content-type': 'application/json',
      'x-console-token': token,
    },
    body: JSON.stringify({ id: 'ghost', password: SENTINEL }),
  })

  assert.equal(res.status, 200)
  assert.deepEqual(JSON.parse(res.body), { ok: false, error: 'PROFILE_NOT_FOUND' })
  assert.deepEqual(seen, ['ghost'], 'the route must forward the requested id')
  assert.equal(res.body.includes(SENTINEL), false, 'the request password must never be echoed')
  assert.equal(res.body.includes('v1:'), false, 'no vault ciphertext may appear in the response')
})
