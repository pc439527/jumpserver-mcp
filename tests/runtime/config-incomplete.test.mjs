/**
 * V0.5.2: an incomplete connection must not kill the process.
 *
 * The defect this freezes: `createRuntime` threw `ConfigIncompleteError`,
 * `main()` caught it and called `process.exit(1)`. The MCP handshake never
 * completed, so the host could only report "the server failed to start" — to a
 * user whose real problem was an unfilled connector form. A reviewer running
 * `npx -y jumpserver-mcp` for a sanity check saw a crash rather than a server.
 *
 * The fix has two halves, and BOTH are asserted here:
 *  1. boot always succeeds, and the refusal is deferred to the tools that
 *     actually need the bastion (`CONFIG_INCOMPLETE`, with the same wording the
 *     startup log uses);
 *  2. a MALFORMED config is still fatal. A missing value is recoverable at
 *     runtime; a broken file is an operator mistake, and silently ignoring it
 *     would hide it.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MISSING_CONFIG, openServer, parseResultText, spawnServer } from '../helpers/mcp.mjs'

function tempConfig(contents) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-cfg-'))
  const path = join(dir, 'config.json')
  writeFileSync(path, typeof contents === 'string' ? contents : JSON.stringify(contents), 'utf8')
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

/** The console is disabled in every fixture: these tests are about boot, not ports. */
const QUIET = { auditViewer: { enabled: false } }

test('boots and answers initialize + tools/list with no configuration at all', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG })
  try {
    assert.equal(server.initialized.serverInfo.name, 'jumpserver-mcp')
    assert.equal(server.tools.length, 23, 'the full tool table must be published even when unconfigured')
  } finally {
    server.close()
  }
})

test('jumpserver_status reports WHAT is missing instead of refusing', async () => {
  // Doubles as the harness-isolation guard. Once multi-account profiles exist,
  // a profile saved on the developer machine supplies host/username/credential
  // through effectiveConfig(), so "no configuration at all" silently becomes
  // "connection: complete" and this assertion fails on a machine while the
  // code is correct. spawnServer() pins HOME/USERPROFILE to a throwaway dir
  // for exactly this reason — do not remove that isolation.
  const server = await openServer({ configPath: MISSING_CONFIG })
  try {
    const { text } = await server.call('jumpserver_status')
    const parsed = parseResultText(text)
    assert.ok(parsed.ok, true, 'status must stay answerable — it is how a user diagnoses this')
    assert.match(text, /^connection: INCOMPLETE — missing host, username$/m, 'status should name every missing field')
  } finally {
    server.close()
  }
})

test('a connect-needing tool refuses with CONFIG_INCOMPLETE and actionable text', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG })
  try {
    for (const [tool, args] of [
      ['jumpserver_connect', {}],
      ['jumpserver_assets', {}],
      ['jumpserver_inspect', { targets: ['203.0.113.10'] }],
      ['jumpserver_exec', { command: 'hostname' }],
      ['jumpserver_batch', { tasks: [{ target: '203.0.113.10', commands: ['hostname'] }] }],
    ]) {
      const { text } = await server.call(tool, args)
      const parsed = parseResultText(text)
      assert.equal(parsed.code, 'CONFIG_INCOMPLETE', tool + ' should refuse with CONFIG_INCOMPLETE, got: ' + text.slice(0, 160))
      // The message a user sees in a tool call must be as actionable as the
      // one printed at startup — it names the env keys and both ways to fix it.
      assert.ok(text.includes('JUMPSERVER_HOST'), tool + ' should name the environment keys')
      assert.ok(text.includes('JUMPSERVER_USERNAME'), tool + ' should name the environment keys')
      assert.ok(text.includes('连接器'), tool + ' should point at the connector form')
    }
  } finally {
    server.close()
  }
})

test('local-only tools keep working while unconfigured', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG })
  try {
    const audit = await server.call('jumpserver_audit')
    assert.notEqual(parseResultText(audit.text).code, 'CONFIG_INCOMPLETE', 'jumpserver_audit must stay usable with no configuration')

    const rotate = await server.call('jumpserver_console_rotate_token')
    assert.notEqual(parseResultText(rotate.text).code, 'CONFIG_INCOMPLETE', 'rotate must not be gated on the connection')
  } finally {
    server.close()
  }
})

test('a partially configured connection names only the field that is still missing', async () => {
  const config = tempConfig({ host: '203.0.113.9', auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    const { text } = await server.call('jumpserver_status')
    assert.match(text, /^connection: INCOMPLETE — missing username$/m, 'only the still-missing field may be named')
  } finally {
    server.close()
    config.cleanup()
  }
})

test('a connection supplied through the environment is reported complete', async () => {
  const server = await openServer({
    configPath: MISSING_CONFIG,
    env: { JUMPSERVER_HOST: '203.0.113.9', JUMPSERVER_USERNAME: 'probe' },
  })
  try {
    const { text } = await server.call('jumpserver_status')
    assert.ok(text.includes('203.0.113.9'), 'the resolved host should be reported')
    assert.match(text, /^connection: complete$/m, 'an env-supplied connection must read as complete')
  } finally {
    server.close()
  }
})

test('a MALFORMED config is still fatal at boot (a missing value is not the same as a broken file)', async () => {
  const config = tempConfig('{"port":"not-a-port"}')
  const server = spawnServer({ configPath: config.path })
  try {
    const code = await Promise.race([
      server.exited,
      new Promise((resolve) => setTimeout(() => resolve('still-running'), 8000)),
    ])
    assert.notEqual(code, 'still-running', 'a schema-invalid config must not start a working server')
    assert.notEqual(code, 0, 'a schema-invalid config must exit non-zero')
  } finally {
    server.close()
    config.cleanup()
  }
})
