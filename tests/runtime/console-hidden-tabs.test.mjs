/**
 * Console tab visibility (V0.5.10).
 *
 * Field request this covers: the console shows eight tabs at once and the
 * operator wanted to switch off the ones they never use. `auditViewer.tabs`
 * now decides which nav buttons exist.
 *
 * What must NOT happen, and is asserted here:
 *   - hiding a tab must not remove its <section>, because the page script binds
 *     handlers to nodes inside every section ($('rows'), $('cards'), …) and a
 *     missing section would throw on load;
 *   - hiding a tab must not be reachable another way — the router guard is what
 *     makes the state unreachable, so the injected VISIBLE list has to agree
 *     with the nav that was rendered;
 *   - `settings` must survive any configuration, including `{settings:false}`:
 *     it is the console's only diagnostics page (and documents this very
 *     switch), so a console without it is a console with no way back.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'

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

function request(port, path) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path }, (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
        })
        res.on('end', () => resolve({ status: res.statusCode, body }))
      })
      .on('error', reject)
  })
}

/** The page is served asynchronously; retry briefly while the listener settles. */
async function fetchPage(port) {
  const deadline = Date.now() + 8000
  for (;;) {
    try {
      const res = await request(port, '/')
      if (res.status === 200 && res.body.includes('<nav>')) return res.body
    } catch {
      /* not listening yet */
    }
    if (Date.now() > deadline) throw new Error('console did not serve the page in time')
    await new Promise((r) => setTimeout(r, 100))
  }
}

async function boot(services) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-tabs-'))
  const port = await freePort()
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port, autoOpen: false, portFallback: true, stableUrl: true },
    null,
    { audit: null, timeZone: 'Asia/Shanghai', ...services },
  )
  const html = await fetchPage(port)
  return { html, port }
}

function visibleOf(html) {
  const match = html.match(/var VISIBLE = (\[[^\]]*\]);/)
  assert.ok(match !== null, 'the page should inject the VISIBLE tab list')
  return JSON.parse(match[1])
}

function navTabsOf(html) {
  const nav = html.match(/<nav>([\s\S]*?)<\/nav>/)
  assert.ok(nav !== null, 'the page should render a nav block')
  return [...nav[1].matchAll(/data-tab="([a-z]+)"/g)].map((m) => m[1])
}

test.afterEach(() => {
  stopAuditViewer()
})

test('a hidden tab loses its nav button, keeps its section, and leaves VISIBLE', async () => {
  const { html } = await boot({ consoleTabs: () => ({ stats: false }) })
  const nav = navTabsOf(html)

  assert.ok(!nav.includes('stats'), 'the stats nav button must not be rendered')
  assert.equal(nav.length, ALL_TABS.length - 1)
  // The section must stay: the script binds to nodes inside it.
  assert.ok(html.includes('id="tab-stats"'), 'the stats section must remain in the DOM')

  const visible = visibleOf(html)
  assert.ok(!visible.includes('stats'))
  assert.ok(visible.includes('settings'))
  assert.deepEqual(visible, nav, 'the injected VISIBLE list and the rendered nav must agree')
})

test('settings survives an explicit attempt to hide it', async () => {
  const { html } = await boot({ consoleTabs: () => ({ settings: false }) })
  assert.ok(navTabsOf(html).includes('settings'), 'settings is always-on')
  assert.ok(visibleOf(html).includes('settings'))
})

test('without consoleTabs every tab is rendered', async () => {
  const { html } = await boot({})
  assert.deepEqual(navTabsOf(html), ALL_TABS)
  assert.deepEqual(visibleOf(html), ALL_TABS)
})

test('the router guard derives from VISIBLE rather than a second list', async () => {
  const { html } = await boot({ consoleTabs: () => ({ topology: false, jobs: false }) })
  // A hardcoded allowlist in the client would drift from the config; the guard
  // must ask VISIBLE, and the old literal eight-tab array must be gone.
  assert.ok(html.includes('function landingTab('), 'the landing-tab guard must exist')
  assert.ok(!html.includes("['terminal','assets','topology','jobs','audit','stats','sessions','settings']"))
  assert.deepEqual(navTabsOf(html), ['terminal', 'assets', 'audit', 'stats', 'sessions', 'settings'])
})

test('the settings tab reports which tabs are hidden', async () => {
  const { html } = await boot({ consoleTabs: () => ({ assets: false }) })
  assert.ok(html.includes('id="settabs"'), 'the settings tab needs a tab-summary block')
  assert.ok(html.includes('renderVisibleTabs'), 'the summary must be rendered from VISIBLE')
})
