/**
 * Console access token (V0.4.1).
 *
 * The console binds to 127.0.0.1, but any local process could otherwise read
 * the audit trail and drive /api/interrupt. Every request must present the
 * per-process token, which is handed over in the URL only.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { startAuditViewer, auditViewerUrl } from '../../lib/runtime/audit-viewer.js'

let portCursor = 18901
async function boot() {
  const port = portCursor++
  startAuditViewer(
    'C:/Users/114976/WorkBuddy/jumpserver-mcp/data/_token_test.jsonl',
    { enabled: true, port, autoOpen: false, portFallback: false },
    null,
    { audit: null, timeZone: 'Asia/Shanghai' },
  )
  // The real URL is only known once the socket is listening.
  for (let i = 0; i < 40; i += 1) {
    const url = auditViewerUrl()
    if (url !== null && url.includes(':' + port + '/')) return url
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('console did not start on port ' + port)
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
