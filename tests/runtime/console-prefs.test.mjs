/**
 * Console tab preferences store (V0.5.13).
 *
 * WHY THIS EXISTS. `auditViewer.tabs` in config.json can hide a tab, but that
 * is a FILE the operator owns and the connector form rewrites — it is not a
 * place a browser click can write. The field request was "a switch in the
 * settings tab", so the console got a store of its own.
 *
 * The two properties that matter, and are frozen here:
 *   - a corrupt file degrades to DEFAULTS and never throws (it is read while
 *     rendering a page — an exception would take the whole console down);
 *   - a corrupt file REFUSES writes, so an operator's recoverable data is not
 *     silently replaced by a fresh file. Same contract as ProfileStore.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ConsolePrefsStore } from '../../lib/runtime/console-prefs.js'

function tempStore(initial) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-prefs-'))
  const filePath = join(dir, 'console-prefs.json')
  if (initial !== undefined) writeFileSync(filePath, initial, 'utf8')
  return { filePath, dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

test('a missing file means "nothing hidden" and is not an error', () => {
  const store = tempStore()
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    assert.deepEqual(prefs.hidden(), [])
    assert.deepEqual(prefs.visibility(), {})
    assert.equal(prefs.integrity().broken, false)
  } finally {
    store.cleanup()
  }
})

test('hiding a tab persists and is reported back in CONSOLE_TAB_IDS order', () => {
  const store = tempStore()
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    assert.deepEqual(prefs.setHidden('stats', true), { ok: true })
    assert.deepEqual(prefs.setHidden('audit', true), { ok: true })
    // Order follows the canonical tab table, not the click order.
    assert.deepEqual(prefs.hidden(), ['audit', 'stats'])
    assert.deepEqual(prefs.visibility(), { audit: false, stats: false })
    // And it survives a fresh instance reading the same file.
    assert.deepEqual(new ConsolePrefsStore({ filePath: store.filePath }).hidden(), ['audit', 'stats'])
  } finally {
    store.cleanup()
  }
})

test('showing a tab again removes it from the file rather than storing true', () => {
  const store = tempStore()
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    prefs.setHidden('jobs', true)
    assert.deepEqual(prefs.setHidden('jobs', false), { ok: true })
    assert.deepEqual(prefs.hidden(), [])
    // "not hidden" must be an ABSENT key, not `false`: otherwise this layer
    // would start overriding config.json with a value nobody chose.
    const raw = JSON.parse(readFileSync(store.filePath, 'utf8'))
    assert.deepEqual(raw.hiddenTabs, [])
  } finally {
    store.cleanup()
  }
})

test('settings can never be hidden — refused, not silently ignored', () => {
  const store = tempStore()
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    assert.deepEqual(prefs.setHidden('settings', true), { ok: false, error: 'TAB_ALWAYS_VISIBLE' })
    assert.deepEqual(prefs.hidden(), [])
  } finally {
    store.cleanup()
  }
})

test('an unknown tab id is refused instead of written', () => {
  const store = tempStore()
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    assert.deepEqual(prefs.setHidden('nonsense', true), { ok: false, error: 'INVALID_ARGUMENT' })
    assert.deepEqual(prefs.hidden(), [])
  } finally {
    store.cleanup()
  }
})

test('a corrupt file reads as defaults and refuses to be overwritten', () => {
  const store = tempStore('{ not json')
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    assert.deepEqual(prefs.hidden(), [], 'a broken preference file must not throw during a page render')
    const integrity = prefs.integrity()
    assert.equal(integrity.broken, true)
    assert.match(integrity.message, /not valid JSON/)

    assert.deepEqual(prefs.setHidden('stats', true), { ok: false, error: 'PREFS_FILE_UNREADABLE' })
    // The original bytes must still be there for the operator to inspect.
    assert.equal(readFileSync(store.filePath, 'utf8'), '{ not json')
  } finally {
    store.cleanup()
  }
})

test('a structurally wrong file is broken, and an unknown id inside it is dropped', () => {
  const badStructure = tempStore('[1,2,3]')
  try {
    assert.equal(new ConsolePrefsStore({ filePath: badStructure.filePath }).integrity().broken, true)
  } finally {
    badStructure.cleanup()
  }

  const staleId = tempStore(JSON.stringify({ version: 1, hiddenTabs: ['stats', 'retired-tab'] }))
  try {
    const prefs = new ConsolePrefsStore({ filePath: staleId.filePath })
    // A tab the code no longer knows must not brick the console, and must not
    // be re-written as if it were valid either.
    assert.deepEqual(prefs.hidden(), ['stats'])
    assert.equal(prefs.integrity().broken, false)
  } finally {
    staleId.cleanup()
  }

  const wrongType = tempStore(JSON.stringify({ version: 1, hiddenTabs: 'stats' }))
  try {
    assert.equal(new ConsolePrefsStore({ filePath: wrongType.filePath }).integrity().broken, true)
  } finally {
    wrongType.cleanup()
  }
})

test('the write is atomic and leaves no .tmp behind', () => {
  const store = tempStore()
  try {
    const prefs = new ConsolePrefsStore({ filePath: store.filePath })
    prefs.setHidden('topology', true)
    const raw = readFileSync(store.filePath, 'utf8')
    assert.doesNotThrow(() => JSON.parse(raw), 'the target file must always be complete JSON')
    assert.deepEqual(JSON.parse(raw).hiddenTabs, ['topology'])
    assert.throws(() => readFileSync(store.filePath + '.tmp', 'utf8'), 'the temp file must be renamed away')
  } finally {
    store.cleanup()
  }
})

test('an unwritable target reports PREFS_WRITE_FAILED instead of throwing', () => {
  // A path whose parent is a FILE cannot be created as a directory.
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-prefs-'))
  writeFileSync(join(dir, 'blocker'), 'x', 'utf8')
  const filePath = join(dir, 'blocker', 'nested', 'console-prefs.json')
  try {
    const prefs = new ConsolePrefsStore({ filePath })
    assert.deepEqual(prefs.setHidden('stats', true), { ok: false, error: 'PREFS_WRITE_FAILED' })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
