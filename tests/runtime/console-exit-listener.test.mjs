/**
 * V0.5.0 — stopAuditViewer() must remove the 'exit' listener it registered.
 *
 * startHeartbeat() registers the console's exit handler with
 * `process.once('exit', onProcessExit)`. `once` wraps the handler afresh on
 * every call, so each start/stop cycle leaves another listener behind unless
 * the removal happens. The V0.4.4 comment in the source claimed the removal
 * was already implemented; it was not, and the only test that exercised the
 * teardown path asserted HTTP listeners, not process listeners.
 *
 * Node warns once the count passes 10, which is why the loop runs past it.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { auditViewerUrl, startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'

let portCursor = 19401

/**
 * Boot a console and wait until it is actually bound: startHeartbeat() runs
 * inside the listen callback, so stopping before the bind completes would test
 * nothing at all.
 */
async function bootAndWait() {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-exit-'))
  startAuditViewer(
    join(dir, 'audit.jsonl'),
    { enabled: true, port: portCursor++, autoOpen: false, portFallback: true, tokenTtlMinutes: 720 },
    null,
    {},
  )
  for (let i = 0; i < 60; i += 1) {
    if (auditViewerUrl() !== null) return
    await new Promise((r) => setTimeout(r, 25))
  }
  throw new Error('console did not start within 1.5s')
}

test.afterEach(() => {
  stopAuditViewer()
})

test('a running console registers exactly one exit listener', async () => {
  const before = process.listenerCount('exit')
  await bootAndWait()
  assert.equal(process.listenerCount('exit'), before + 1)
})

test('stopAuditViewer removes the exit listener again', async () => {
  const before = process.listenerCount('exit')
  await bootAndWait()
  stopAuditViewer()
  assert.equal(process.listenerCount('exit'), before)
})

test('repeated start/stop cycles never accumulate exit listeners', async () => {
  const before = process.listenerCount('exit')
  for (let i = 0; i < 12; i += 1) {
    await bootAndWait()
    stopAuditViewer()
  }
  assert.equal(
    process.listenerCount('exit'),
    before,
    'twelve cycles must not leave twelve listeners (Node warns past ten)',
  )
})
