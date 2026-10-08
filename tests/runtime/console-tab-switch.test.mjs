/**
 * Console tab switches, end to end (V0.5.13).
 *
 * The field request was "can the tabs be switched off IN THE SETTINGS TAB".
 * V0.5.10 answered it with a read-only report pointing at
 * `config.json → auditViewer.tabs` — a file the connector form rewrites and the
 * operator has to edit by hand. The request was a control, so this file drives
 * the real thing: real HTTP routes, a REAL ConsolePrefsStore on a temp file, and
 * the page HTML that the switches are rendered into.
 *
 * Contracts pinned here:
 *   - a switch write persists, and a FRESH page load reflects it (no reliance on
 *     client state, which is what makes it survive a reload or another tab);
 *   - the write response carries the AUTHORITATIVE new state, not an echo of the
 *     request — so a write that config.json overrides still reports the tab as
 *     visible instead of letting the UI believe a lie;
 *   - `settings` is refused by the STORE, not merely hidden by the UI;
 *   - a config-pinned row and the always-on row are rendered disabled, because a
 *     switch that cannot win is worse than no switch;
 *   - the route is behind both the console token and the same-origin gate, and
 *     a refused request performs zero writes.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'
import { ConsolePrefsStore } from '../../lib/runtime/console-prefs.js'
import { consoleTabSources, resolveConsoleTabs } from '../../lib/runtime/console-tabs.js'

const ALL_TABS = ['terminal', 'assets', 'topology', 'jobs', 'audit', 'stats', 'sessions', 'settings']

async function freePort() {
  return await new Promise((resolve) => {
    const probe = http.createServer()
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolve(port))
    })
  })
}

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
      res.on('end', () => resolve({ status: res.statusCode, body: text }))
    })
    req.on('error', reject)
    if (payload !== null) req.write(payload)
    req.end()
  })
}

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

function tokenOf(html) {
  const match = html.match(/\|\| "([0-9a-f]{16,})";/)
  assert.ok(match !== null, 'the page should embed the access token')
  return match[1]
}

function navTabsOf(html) {
  const nav = html.match(/<nav>([\s\S]*?)<\/nav>/)
  assert.ok(nav !== null, 'the page should render a nav block')
  return [...nav[1].matchAll(/data-tab="([a-z]+)"/g)].map((m) => m[1])
}

function visibleOf(html) {
  const match = html.match(/var VISIBLE = (\[[^\]]*\]);/)
  assert.ok(match !== null, 'the page should inject the VISIBLE tab list')
  return JSON.parse(match[1])
}

function sourcesOf(html) {
  const match = html.match(/var TAB_SOURCES = (\{[^}]*\});/)
  assert.ok(match !== null, 'the page should inject TAB_SOURCES')
  return JSON.parse(match[1])
}

/**
 * Boot a console wired to a REAL prefs store on a temp file and a `configured`
 * object that stands in for config.json's auditViewer.tabs.
 */
async function boot({ configured = {}, corrupt = null, extra = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-tabswitch-'))
  const filePath = join(dir, 'console-prefs.json')
  if (corrupt !== null) writeFileSync(filePath, corrupt, 'utf8')
  const prefs = new ConsolePrefsStore({ filePath })
  const port = await freePort()
  const report = () => ({
    visible: resolveConsoleTabs(configured, prefs.visibility()),
    sources: consoleTabSources(configured, prefs.visibility()),
    hidden: prefs.hidden(),
    integrity: prefs.integrity(),
    storePathHint: '~/.workbuddy/jumpserver-mcp/console-prefs.json',
  })
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: false, portFallback: true, stableUrl: true },
    null,
    {
      audit: null,
      timeZone: 'Asia/Shanghai',
      consoleTabs: () => configured,
      consoleTabLocal: () => prefs.visibility(),
      consoleTabReport: report,
      setConsoleTab: (id, hidden) => prefs.setHidden(id, hidden),
      ...extra,
    },
  )
  const html = await fetchPage(port)
  return {
    port,
    token: tokenOf(html),
    html,
    filePath,
    reload: () => fetchPage(port),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}

/** The hidden list on disk, tolerating "refused, so no file was ever created". */
function hiddenOnDisk(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8')).hiddenTabs
  } catch {
    return []
  }
}

function toggle(port, token, id, hidden, origin) {
  const headers = { 'content-type': 'application/json', 'x-console-token': token }
  if (origin !== undefined) headers['origin'] = origin
  return rawRequest(port, {
    method: 'POST',
    path: '/api/console/tabs',
    headers,
    body: JSON.stringify({ id, hidden }),
  })
}

test.afterEach(() => {
  stopAuditViewer()
})

/**
 * The switch markup is built CLIENT-side by renderVisibleTabs() (one renderer,
 * re-used after every write), so the served HTML carries the renderer and the
 * data it draws from — not a pre-baked checkbox list. These assertions therefore
 * pin the renderer contract; the real behavioural coverage is the HTTP route
 * tests below, which exercise a real store on a real file.
 */
test('the settings tab renders operable switches and locks the ones that cannot win', async () => {
  const ctx = await boot()
  try {
    assert.ok(ctx.html.includes('function renderVisibleTabs('), 'the switch renderer must exist')
    assert.ok(ctx.html.includes('function wireVisibleTabs('), 'the switches must be wired to a write')
    // A checkbox per tab, fed by the id in a loop rather than a literal list.
    assert.match(ctx.html, /data-tab-toggle="'\+esc\(id\)\+'"/)
    // Locked = config-pinned or always-on; a locked row is disabled.
    assert.match(ctx.html, /locked = \(src === 'config' \|\| src === 'always'\)/)
    assert.match(ctx.html, /\(locked \? ' disabled' : ''\)/)
    // The reason has to be on screen, not only in a comment.
    assert.ok(ctx.html.includes('「设置」不可隐藏'), 'the always-on reason must be shown')
    assert.ok(ctx.html.includes('已被 config.json 的 auditViewer.tabs 固定'), 'the pinned reason must be shown')
    // The old read-only copy ("当前显示（8/8）… 全部 Tab 均显示") was the actual
    // field complaint: it named the rule without offering a control.
    assert.ok(!ctx.html.includes('全部 Tab 均显示'), 'the read-only report must be gone')
    assert.ok(ctx.html.includes('取消勾选即从导航栏移除该 Tab'), 'the switches must say what they do')
  } finally {
    ctx.cleanup()
  }
})

test('a config-pinned tab is reported as locked, and its source is injected', async () => {
  const ctx = await boot({ configured: { stats: false } })
  try {
    assert.ok(!visibleOf(ctx.html).includes('stats'), 'a config-hidden tab must not be in VISIBLE')
    assert.equal(sourcesOf(ctx.html)['stats'], 'config')
    assert.equal(sourcesOf(ctx.html)['settings'], 'always')
    assert.equal(sourcesOf(ctx.html)['terminal'], 'default')
  } finally {
    ctx.cleanup()
  }
})

test('toggling a tab persists, is reflected on a fresh page load, and never touched config.json', async () => {
  const ctx = await boot()
  try {
    const res = await toggle(ctx.port, ctx.token, 'stats', true)
    assert.equal(res.status, 200)
    const body = JSON.parse(res.body)
    assert.equal(body.ok, true)
    assert.ok(!body.visible.includes('stats'), 'the response must carry the new authoritative list')
    assert.equal(body.sources['stats'], 'local', 'the tab is now hidden by the LOCAL layer')

    // The store on disk is the source of truth, not the client's memory.
    assert.deepEqual(hiddenOnDisk(ctx.filePath), ['stats'])

    const reloaded = await ctx.reload()
    assert.ok(!navTabsOf(reloaded).includes('stats'), 'a reload must lose the stats nav button')
    assert.deepEqual(navTabsOf(reloaded), visibleOf(reloaded), 'nav and VISIBLE must still agree')
    // The section stays in the DOM: the page script binds handlers inside it.
    assert.ok(reloaded.includes('id="tab-stats"'))
  } finally {
    ctx.cleanup()
  }
})

test('showing a tab again puts it back', async () => {
  const ctx = await boot()
  try {
    await toggle(ctx.port, ctx.token, 'jobs', true)
    assert.ok(!navTabsOf(await ctx.reload()).includes('jobs'))

    const res = await toggle(ctx.port, ctx.token, 'jobs', false)
    assert.equal(JSON.parse(res.body).ok, true)
    assert.ok(navTabsOf(await ctx.reload()).includes('jobs'))
    assert.deepEqual(hiddenOnDisk(ctx.filePath), [])
  } finally {
    ctx.cleanup()
  }
})

test('the response is authoritative: a write config.json overrides is reported as still visible', async () => {
  const ctx = await boot({ configured: { assets: true } })
  try {
    const res = await toggle(ctx.port, ctx.token, 'assets', true)
    const body = JSON.parse(res.body)
    assert.equal(body.ok, true, 'the store accepted the write')
    // ...but config.json pins the tab visible, so the page must NOT be told it
    // disappeared. Otherwise the switch would visibly lie until the next reload.
    assert.ok(body.visible.includes('assets'), 'config.json must still win in the reported state')
    assert.equal(body.sources['assets'], 'config')
  } finally {
    ctx.cleanup()
  }
})

test('settings cannot be hidden even by a direct API call', async () => {
  const ctx = await boot()
  try {
    const res = await toggle(ctx.port, ctx.token, 'settings', true)
    assert.deepEqual(JSON.parse(res.body), { ok: false, error: 'TAB_ALWAYS_VISIBLE' })
    assert.deepEqual(hiddenOnDisk(ctx.filePath), [])
  } finally {
    ctx.cleanup()
  }
})

test('an unknown tab id is refused without writing anything', async () => {
  const ctx = await boot()
  try {
    const res = await toggle(ctx.port, ctx.token, 'retired-tab', true)
    assert.deepEqual(JSON.parse(res.body), { ok: false, error: 'INVALID_ARGUMENT' })
    assert.deepEqual(hiddenOnDisk(ctx.filePath), [])
  } finally {
    ctx.cleanup()
  }
})

test('a corrupt preference file is reported AND refuses the write', async () => {
  const ctx = await boot({ corrupt: '{ not json' })
  try {
    assert.ok(ctx.html.includes('偏好文件无法读取'), 'the page must say the store is unreadable')
    assert.deepEqual(visibleOf(ctx.html), ALL_TABS, 'a broken file degrades to defaults')
    const res = await toggle(ctx.port, ctx.token, 'stats', true)
    assert.deepEqual(JSON.parse(res.body), { ok: false, error: 'PREFS_FILE_UNREADABLE' })
    assert.equal(readFileSync(ctx.filePath, 'utf8'), '{ not json', 'the file must not be replaced')
  } finally {
    ctx.cleanup()
  }
})

test('the toggle route is behind the same-origin gate and the token', async () => {
  const ctx = await boot()
  try {
    const crossOrigin = await toggle(ctx.port, ctx.token, 'stats', true, 'http://evil.example')
    assert.equal(crossOrigin.status, 403, 'a cross-origin write must be refused even with a valid token')
    assert.deepEqual(hiddenOnDisk(ctx.filePath), [], 'no side effect')

    const anonymous = await rawRequest(ctx.port, {
      method: 'POST',
      path: '/api/console/tabs',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'stats', hidden: true }),
    })
    assert.notEqual(anonymous.status, 200, 'a token-free write must not be accepted')
    assert.deepEqual(hiddenOnDisk(ctx.filePath), [])
  } finally {
    ctx.cleanup()
  }
})

test('/api/settings carries the same tab block the write route returns', async () => {  const ctx = await boot()
  try {
    await toggle(ctx.port, ctx.token, 'topology', true)
    const res = await rawRequest(ctx.port, {
      path: '/api/settings?token=' + ctx.token,
    })
    const body = JSON.parse(res.body)
    assert.ok(body.consoleTabs !== null && body.consoleTabs !== undefined, 'settings must expose the tab block')
    assert.deepEqual(body.consoleTabs.hidden, ['topology'])
    assert.ok(!body.consoleTabs.visible.includes('topology'))
    assert.equal(body.consoleTabs.storePathHint, '~/.workbuddy/jumpserver-mcp/console-prefs.json')
  } finally {
    ctx.cleanup()
  }
})

/**
 * The whole console is ONE template literal, so a stray backtick or a broken
 * interpolation ships as a runtime SyntaxError that only appears in the
 * operator's browser — the type checker sees a perfectly good string. Compiling
 * the served script covers that gap without a DOM: new Function() parses
 * without running, so `document` being absent does not matter.
 */
test('the served page script is valid JavaScript', async () => {
  const ctx = await boot()
  try {
    const start = ctx.html.indexOf('<script>')
    const end = ctx.html.lastIndexOf('</script>')
    assert.ok(start >= 0 && end > start, 'the page must contain its script block')
    const script = ctx.html.slice(start + '<script>'.length, end)
    assert.ok(script.length > 20000, 'the console script is large; a truncated block means a broken template')
    assert.doesNotThrow(() => new Function(script), 'the page script must parse')
    // The switch feature must actually be in there.
    assert.ok(script.includes('/api/console/tabs'), 'the switch must post to the tab route')
  } finally {
    ctx.cleanup()
  }
})
