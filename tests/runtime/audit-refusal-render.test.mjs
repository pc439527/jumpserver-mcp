/**
 * V0.5.9 — a refusal must be readable AFTER the fact, not just at the moment it
 * happened.
 *
 * Why it exists: the refusal is already thrown at the caller, so the model
 * knows why THAT call failed. The trail is different: `jumpserver_audit` is a
 * whitelisted projection, so a `refusalReason` that is stored but not rendered
 * makes the record useless for the one question it exists to answer — "who
 * tried to run what, and why were they stopped". A bare `BLOCKED` sends the
 * reader back to guessing.
 *
 * Driven through the real server over MCP stdio against a fabricated audit
 * sink, so what is asserted is the text the model actually receives — not a
 * unit-level helper that the projection could bypass.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { openServer } from '../helpers/mcp.mjs'

/** A config that points the audit sink at our fixture and starts no console. */
function auditFixture(records) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-audit-'))
  const auditPath = join(dir, 'audit.jsonl')
  writeFileSync(auditPath, records.map((record) => JSON.stringify(record)).join('\n') + '\n', 'utf8')
  const configPath = join(dir, 'config.json')
  writeFileSync(configPath, JSON.stringify({ auditPath, auditViewer: { enabled: false } }), 'utf8')
  return { configPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

const base = {
  timestamp: '2026-09-21T07:00:00.000Z',
  gateway: 'gw:2222',
  target: '192.168.148.36',
  hostname: 'app01',
  actor: 'AGENT',
  permissionMode: 'READ_ONLY',
  exitCode: null,
  durationMs: null,
}

const BLOCKED = {
  ...base,
  operation: 'exec',
  command: 'rm -rf /var',
  redactedCommand: 'rm -rf /var',
  risk: 'MODIFY',
  result: 'BLOCKED',
  approvalRequired: false,
  approvalResult: 'none',
  refusalReason: 'MUTATION_VERB: rm is not a read command',
}

const DENIED = {
  ...base,
  operation: 'run',
  command: 'some-vendor-cli --apply',
  redactedCommand: 'some-vendor-cli --apply',
  risk: 'UNKNOWN',
  result: 'DENIED',
  approvalRequired: true,
  approvalResult: 'denied',
  refusalReason: 'the user did not approve this command',
}

const RAN = {
  ...base,
  operation: 'exec',
  command: 'uptime',
  redactedCommand: 'uptime',
  risk: 'READ',
  result: 'SUCCESS',
  approvalRequired: false,
  approvalResult: 'none',
}

test('a blocked command is listed with the reason it was blocked', async () => {
  const fixture = auditFixture([BLOCKED, RAN])
  const server = await openServer({ configPath: fixture.configPath })
  try {
    const { text } = await server.call('jumpserver_audit')
    const line = text.split('\n').find((l) => l.includes('rm -rf /var'))
    assert.ok(line !== undefined, 'the refused command must appear in the trail: ' + text)
    assert.ok(line.includes('| BLOCKED |'), 'the outcome must be distinguishable from a failure: ' + line)
    assert.ok(line.includes('why=MUTATION_VERB'), 'the reason is the whole point of the record: ' + line)
    // …and the entry that DID run stays byte-identical to the pre-V0.5.9 shape,
    // so nothing downstream has to learn a new column for the common case.
    const ran = text.split('\n').find((l) => l.includes('uptime'))
    assert.equal(ran.includes('why='), false, 'an ordinary entry carries no refusal column: ' + ran)
  } finally {
    server.close()
    fixture.cleanup()
  }
})

test('a denied command is listed as denied, with its own reason', async () => {
  const fixture = auditFixture([DENIED])
  const server = await openServer({ configPath: fixture.configPath })
  try {
    const { text } = await server.call('jumpserver_audit')
    const line = text.split('\n').find((l) => l.includes('some-vendor-cli'))
    assert.ok(line !== undefined, text)
    assert.ok(line.includes('| DENIED |'), '"stopped by policy" must be distinct from "nothing happened": ' + line)
    assert.ok(line.includes('why=the user did not approve'), line)
    assert.ok(text.includes('entries=1'), text)
  } finally {
    server.close()
    fixture.cleanup()
  }
})
