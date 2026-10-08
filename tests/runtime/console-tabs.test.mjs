/**
 * V0.5.9 console tab visibility: the pure resolver + the config schema layer.
 *
 * Two contracts are pinned here:
 *   1. resolveConsoleTabs() / isConsoleTabVisible() / pickLandingTab() are the
 *      single judge of "what is shown", including the rule that `settings` can
 *      never be hidden (it is the console's only way back to the explanation of
 *      this very switch).
 *   2. The config schema only enforces TYPES: a non-boolean tab value is a
 *      config error, while the visibility policy stays out of the schema.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  ALWAYS_ON_CONSOLE_TABS,
  CONSOLE_TAB_IDS,
  DEFAULT_CONSOLE_TABS,
} from '../../lib/config/types.js'
import { parseConfig } from '../../lib/config/schema.js'
import { consoleTabSource, consoleTabSources, isConsoleTabVisible, pickLandingTab, resolveConsoleTabs } from '../../lib/runtime/console-tabs.js'

const ALL_TABS = ['terminal', 'assets', 'topology', 'jobs', 'audit', 'stats', 'sessions', 'settings']

/* ---------------------------------------------- V0.5.13: two layers, one rule */

test('the local layer (the 设置 switches) hides a tab', () => {
  assert.deepEqual(resolveConsoleTabs(undefined, { stats: false }), [
    'terminal', 'assets', 'topology', 'jobs', 'audit', 'sessions', 'settings',
  ])
})

test('config.json outranks the local layer in BOTH directions', () => {
  // Pinned visible in the file => a stale local `false` must not win.
  assert.ok(resolveConsoleTabs({ stats: true }, { stats: false }).includes('stats'))
  // Pinned hidden in the file => a local `true` (or absence) must not win.
  assert.ok(!resolveConsoleTabs({ stats: false }, { stats: true }).includes('stats'))
  // And the two layers are independent per tab.
  const visible = resolveConsoleTabs({ audit: false }, { stats: false })
  assert.ok(!visible.includes('audit'))
  assert.ok(!visible.includes('stats'))
  assert.ok(visible.includes('topology'))
})

test('the local layer can never hide settings either', () => {
  assert.ok(resolveConsoleTabs(undefined, { settings: false }).includes('settings'))
  assert.ok(resolveConsoleTabs({ settings: false }, { settings: false }).includes('settings'))
})

test('consoleTabSource names the layer that won, so the UI can lock the row', () => {
  assert.equal(consoleTabSource('stats', undefined, undefined), 'default')
  assert.equal(consoleTabSource('stats', undefined, { stats: false }), 'local')
  assert.equal(consoleTabSource('stats', { stats: true }, { stats: false }), 'config')
  assert.equal(consoleTabSource('stats', { stats: false }, undefined), 'config')
  // `settings` is locked by the always-on rule regardless of either layer.
  assert.equal(consoleTabSource('settings', { settings: false }, { settings: false }), 'always')

  const sources = consoleTabSources({ audit: false }, { stats: false })
  assert.deepEqual(Object.keys(sources), ALL_TABS)
  assert.equal(sources['audit'], 'config')
  assert.equal(sources['stats'], 'local')
  assert.equal(sources['settings'], 'always')
  assert.equal(sources['terminal'], 'default')
})

test('isConsoleTabVisible sees both layers, matching resolveConsoleTabs', () => {
  for (const id of CONSOLE_TAB_IDS) {
    assert.equal(
      isConsoleTabVisible(id, { audit: false }, { stats: false }),
      resolveConsoleTabs({ audit: false }, { stats: false }).includes(id),
      'the router guard and the nav must ask the same question about ' + id,
    )
  }
})

/* ------------------------------------------------------------ constants */

test('CONSOLE_TAB_IDS is the documented navigation order', () => {
  assert.deepEqual([...CONSOLE_TAB_IDS], ALL_TABS)
})

test('DEFAULT_CONSOLE_TABS turns every tab on', () => {
  assert.deepEqual(DEFAULT_CONSOLE_TABS, {
    terminal: true,
    assets: true,
    topology: true,
    jobs: true,
    audit: true,
    stats: true,
    sessions: true,
    settings: true,
  })
})

test('settings is the only always-on tab', () => {
  assert.deepEqual([...ALWAYS_ON_CONSOLE_TABS], ['settings'])
})

/* ------------------------------------------------------ resolveConsoleTabs */

test('nothing configured shows all eight tabs in order', () => {
  assert.deepEqual(resolveConsoleTabs(undefined), ALL_TABS)
  assert.deepEqual(resolveConsoleTabs({}), ALL_TABS)
})

test('an explicit false drops exactly that tab', () => {
  const visible = resolveConsoleTabs({ stats: false })
  assert.equal(visible.length, 7)
  assert.ok(!visible.includes('stats'))
  assert.deepEqual(visible, ['terminal', 'assets', 'topology', 'jobs', 'audit', 'sessions', 'settings'])
})

test('an explicit true keeps a tab (and is the default anyway)', () => {
  assert.deepEqual(resolveConsoleTabs({ stats: true }), ALL_TABS)
  assert.deepEqual(resolveConsoleTabs({ stats: false, audit: true }), [
    'terminal',
    'assets',
    'topology',
    'jobs',
    'audit',
    'sessions',
    'settings',
  ])
})

test('settings cannot be hidden, however it is configured', () => {
  assert.ok(resolveConsoleTabs({ settings: false }).includes('settings'))
  assert.ok(resolveConsoleTabs({ settings: false, stats: false }).includes('settings'))
  assert.ok(resolveConsoleTabs({ terminal: false, assets: false, topology: false, jobs: false,
    audit: false, stats: false, sessions: false, settings: false }).includes('settings'))
})

test('every tab may be hidden except settings, and the list stays ordered', () => {
  const visible = resolveConsoleTabs({
    terminal: false,
    assets: false,
    topology: false,
    jobs: false,
    audit: false,
    stats: false,
    sessions: false,
  })
  assert.deepEqual(visible, ['settings'], 'settings is the last and only survivor')
})

/* --------------------------------------------------- isConsoleTabVisible */

test('isConsoleTabVisible agrees with resolveConsoleTabs for every tab', () => {
  for (const configured of [undefined, {}, { stats: false }, { settings: false }, { terminal: false, audit: false }]) {
    const visible = resolveConsoleTabs(configured)
    for (const id of CONSOLE_TAB_IDS) {
      assert.equal(
        isConsoleTabVisible(id, configured),
        visible.includes(id),
        `disagreement for tab "${id}" with ${JSON.stringify(configured)}`,
      )
    }
  }
})

test('isConsoleTabVisible still reports settings as visible when disabled', () => {
  assert.equal(isConsoleTabVisible('settings', { settings: false }), true)
  assert.equal(isConsoleTabVisible('stats', { stats: false }), false)
})

/* ------------------------------------------------------- pickLandingTab */

test('a requested visible tab is used as the landing tab', () => {
  const visible = resolveConsoleTabs()
  assert.equal(pickLandingTab('audit', visible), 'audit')
  assert.equal(pickLandingTab('settings', visible), 'settings')
})

test('requesting a hidden tab falls back to the first visible tab', () => {
  const visible = resolveConsoleTabs({ stats: false })
  assert.equal(pickLandingTab('stats', visible), 'terminal')
})

test('an unknown hash falls back to the first visible tab', () => {
  assert.equal(pickLandingTab('nonsense', resolveConsoleTabs()), 'terminal')
  assert.equal(pickLandingTab('', resolveConsoleTabs()), 'terminal')
  assert.equal(pickLandingTab('#stats', resolveConsoleTabs()), 'terminal')
})

test('with stats hidden and terminal hidden the fallback is the new first tab', () => {
  const visible = resolveConsoleTabs({ terminal: false, stats: false })
  assert.equal(pickLandingTab('stats', visible), 'assets')
  assert.equal(pickLandingTab('nonsense', visible), 'assets')
})

test('an empty list falls back to terminal rather than returning undefined', () => {
  assert.equal(pickLandingTab('audit', []), 'terminal')
})

/* ---------------------------------------------------------- schema layer */

const BASE = { host: 'jump.example.com', username: 'IT00123' }

test('the schema accepts a valid tabs block and keeps only the written keys', () => {
  const cfg = parseConfig({ ...BASE, auditViewer: { tabs: { stats: false, terminal: true } } })
  assert.deepEqual(cfg.auditViewer.tabs, { terminal: true, stats: false })
})

test('a non-boolean tab value is refused', () => {
  assert.throws(() => parseConfig({ ...BASE, auditViewer: { tabs: { terminal: 'yes' } } }))
  assert.throws(() => parseConfig({ ...BASE, auditViewer: { tabs: { stats: 1 } } }))
})

test('an absent tabs block normalizes to an empty object (no defaults injected)', () => {
  const cfg = parseConfig(BASE)
  assert.deepEqual(cfg.auditViewer.tabs, {})
})

test('unknown tab names are dropped, not carried into the config object', () => {
  const cfg = parseConfig({ ...BASE, auditViewer: { tabs: { bogus: false, stats: false } } })
  assert.deepEqual(cfg.auditViewer.tabs, { stats: false })
})

test('settings:false survives parsing but resolveConsoleTabs still shows settings', () => {
  const cfg = parseConfig({ ...BASE, auditViewer: { tabs: { settings: false } } })
  assert.equal(cfg.auditViewer.tabs.settings, false, 'the file is echoed faithfully…')
  assert.ok(resolveConsoleTabs(cfg.auditViewer.tabs).includes('settings'), '…but the policy wins')
})
