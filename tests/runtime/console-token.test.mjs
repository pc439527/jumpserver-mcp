/**
 * Console access token (V0.4.1 / V0.4.2).
 *
 * The console binds to 127.0.0.1, but any local process could otherwise read
 * the audit trail and drive /api/interrupt. Every request must present the
 * per-process token, which is handed over in the URL only. V0.4.2 adds an
 * expiry (a stale token is rejected with an explicit marker) and rotation.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  auditViewerUrl,
  consoleTokenInfo,
  rotateConsoleAccessToken,
  startAuditViewer,
} from '../../lib/runtime/audit-viewer.js'

let portCursor = 18901
async function boot(opts = {}) {
  // Try successive ports: earlier consoles in this file stay bound until the
  // process exits, and an unrelated process may hold one of them.
  let lastError = null
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const port = portCursor++
    startAuditViewer(
      'C:/Users/114976/WorkBuddy/jumpserver-mcp/data/_token_test.jsonl',
      { enabled: true, port, autoOpen: false, portFallback: false, ...opts },
      null,
      { audit: null, timeZone: 'Asia/Shanghai' },
    )
    // The real URL is only known once the socket is listening.
    for (let i = 0; i < 40; i += 1) {
      const url = auditViewerUrl()
      if (url !== null && url.includes(':' + port + '/')) return url
      await new Promise((r) => setTimeout(r, 25))
    }
    lastError = new Error('console did not start on port ' + port)
  }
  throw lastError
}

/** The console URL is http://host:port/?token=…; split it into base + token. */
function parts(url) {
  const [base, query] = url.split('?')
  const token = new URLSearchParams(query).get('token')
  return { base: base.endsWith('/') ? base : base + '/', token }
}

test('console URL carries a token query parameter', async () => {
  const url = await boot()
  assert.ok(url.includes('token='), 'url was ' + url)
  assert.match(url, /\?token=[0-9a-f]{16,}/)
})

test('a request WITHOUT the token is rejected with 403', async () => {
  const { base } = parts(await boot())
  const res = await fetch(base + 'api/entries')
  assert.equal(res.status, 403)
})

test('a request WITH the correct token succeeds', async () => {
  const { base, token } = parts(await boot())
  const res = await fetch(base + 'api/assets?token=' + token)
  assert.equal(res.status, 200)
  const body = await res.json()
  assert.ok(body !== null && typeof body === 'object')
})

test('a request with a WRONG token is rejected with 403', async () => {
  const { base } = parts(await boot())
  const res = await fetch(base + 'api/entries?token=deadbeefdeadbeef')
  assert.equal(res.status, 403)
})

test('the X-Console-Token header is accepted as an alternative to the query', async () => {
  const { base, token } = parts(await boot())
  const res = await fetch(base + 'api/entries', { headers: { 'x-console-token': token } })
  assert.equal(res.status, 200)
})

/* ------------------------------------------------------------ V0.4.2 expiry */

test('token TTL defaults to 12h and is reported by consoleTokenInfo', async () => {
  await boot()
  const info = consoleTokenInfo()
  assert.equal(info.ttlMinutes, 720)
  assert.equal(info.expired, false)
  assert.ok(typeof info.expiresAt === 'string' && info.expiresAt.length > 0)
})

test('tokenTtlMinutes=0 disables expiry entirely', async () => {
  await boot({ tokenTtlMinutes: 0 })
  const info = consoleTokenInfo()
  assert.equal(info.ttlMinutes, 0)
  assert.equal(info.expiresAt, null)
  assert.equal(info.expired, false)
})

test('an already-expired token is rejected with the expiry marker', async () => {
  // A 1-minute TTL, then rewind the expiry by rotating and forcing it past.
  const { base, token } = parts(await boot({ tokenTtlMinutes: 1 }))
  const fresh = await fetch(base + 'api/assets?token=' + token)
  assert.equal(fresh.status, 200)
  assert.equal(fresh.headers.get('x-console-token-expired'), null)
  // Expire the token deterministically rather than sleeping a minute.
  const info = consoleTokenInfo()
  assert.equal(info.expired, false)
  const { forceExpireConsoleToken } = await import('../../lib/runtime/audit-viewer.js')
  forceExpireConsoleToken()
  const stale = await fetch(base + 'api/assets?token=' + token)
  assert.equal(stale.status, 403)
  assert.equal(stale.headers.get('x-console-token-expired'), '1')
})

test('rotation invalidates the old token and issues a working new one', async () => {
  const { base, token: oldToken } = parts(await boot())
  const next = rotateConsoleAccessToken()
  assert.ok(next !== null && next.includes('token='))
  const { token: newToken } = parts(next)
  assert.notEqual(newToken, oldToken)

  const withOld = await fetch(base + 'api/assets?token=' + oldToken)
  assert.equal(withOld.status, 403)
  const withNew = await fetch(base + 'api/assets?token=' + newToken)
  assert.equal(withNew.status, 200)
})

test('rotation is reflected in auditViewerUrl so the next handover is correct', async () => {
  const before = await boot()
  const next = rotateConsoleAccessToken()
  assert.equal(auditViewerUrl(), next)
  assert.notEqual(auditViewerUrl(), before)
})

/* ------------------------------------------------- V0.4.3 on-disk secrecy */

test('the discovery file NEVER contains the token or a tokenized URL', async () => {
  const { token } = parts(await boot())
  // The heartbeat file is written on boot and refreshed every 5s.
  const { readFileSync, existsSync } = await import('node:fs')
  const { join } = await import('node:path')
  const file = join('data', 'consoles', String(process.pid) + '.json')
  assert.ok(existsSync(file), 'expected a discovery file at ' + file)
  const raw = readFileSync(file, 'utf8')
  const parsed = JSON.parse(raw)

  assert.equal(raw.includes(token), false, 'the token must not be readable from disk')
  assert.equal('url' in parsed, false, 'the tokenized URL must not be persisted')
  assert.equal(typeof parsed.port, 'number')
  assert.equal(typeof parsed.pid, 'number')
  assert.ok('startedAt' in parsed && 'heartbeatAt' in parsed)
})
