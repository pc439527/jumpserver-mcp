/**
 * Test helper: drive the real `lib/server.js` over MCP stdio.
 *
 * Used by the tests that must observe what the CONNECTOR actually advertises
 * (tools/list annotations, boot behaviour with no configuration) rather than
 * what a unit-level import would suggest. Boots the built server, so `npm test`
 * must have run `tsc` first — which `package.json` already does.
 *
 * Deliberately NOT named `*.test.mjs`: run-tests.mjs collects every test file
 * it walks past, and this is infrastructure.
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

/** A path that is guaranteed not to exist, for the "no config at all" cases. */
export const MISSING_CONFIG = join(repoRoot, 'tests', '.no-such-config.json')

/** The four connector-injected keys, blanked so a developer's own shell cannot leak in. */
export const BLANK_CONNECTION_ENV = {
  JUMPSERVER_HOST: '',
  JUMPSERVER_PORT: '',
  JUMPSERVER_USERNAME: '',
  JUMPSERVER_PASSWORD: '',
  JUMPSERVER_MCP_SESSION: '',
}

/**
 * Start the server process. Returns a handle with an MCP request() plus the
 * raw child, so a test can also assert on process EXIT (which is how the
 * "malformed config is fatal" contract is observed).
 *
 * Hermetic HOME by default. ProfileStore and CredentialVault both resolve
 * under the user's home (~/.workbuddy/jumpserver-mcp), so without this the
 * meaning of "no configuration at all" depends on the machine that runs the
 * suite: once a developer saves ONE bastion account, the saved profile starts
 * supplying host/username/credential and the CONFIG_INCOMPLETE tests fail
 * while the code is perfectly correct. A caller that needs a seeded store
 * passes its own USERPROFILE/HOME in `env`, which wins because `env` is spread
 * last.
 */
export function spawnServer({ configPath = MISSING_CONFIG, env = {} } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-home-'))
  const child = spawn(process.execPath, [join(repoRoot, 'lib', 'server.js')], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: repoRoot,
    env: {
      ...process.env,
      ...BLANK_CONNECTION_ENV,
      JUMPSERVER_MCP_CONFIG: configPath,
      USERPROFILE: home,
      HOME: home,
      ...env,
    },
  })
  child.on('exit', () => {
    try { rmSync(home, { recursive: true, force: true }) } catch { /* best effort */ }
  })

  let stderr = ''
  child.stderr.on('data', (d) => { stderr += d.toString() })

  const pending = new Map()
  let nextId = 1
  const exited = new Promise((resolve) => { child.on('exit', (code) => resolve(code)) })

  createInterface({ input: child.stdout }).on('line', (line) => {
    if (line.trim().length === 0) return
    let msg
    try { msg = JSON.parse(line) } catch { return }
    const entry = pending.get(msg.id)
    if (entry === undefined) return
    pending.delete(msg.id)
    if (msg.error !== undefined) entry.reject(new Error(JSON.stringify(msg.error)))
    else entry.resolve(msg.result)
  })

  const request = (method, params) => {
    const id = nextId++
    const promise = new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject })
      setTimeout(() => {
        if (pending.has(id)) { pending.delete(id); reject(new Error('timeout waiting for ' + method)) }
      }, 20000)
    })
    try {
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
    } catch {
      /* process already gone — the pending timeout reports it */
    }
    return promise
  }

  const notify = (method, params) => {
    try { child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n') } catch { /* gone */ }
  }

  return {
    child,
    request,
    notify,
    exited,
    stderr: () => stderr,
    close: () => { try { child.kill() } catch { /* already gone */ } },
  }
}

/** Spawn + handshake, returning the tool table and a call() helper. */
export async function openServer(options = {}) {
  const server = spawnServer(options)
  const initialized = await server.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'jumpserver-mcp-test', version: '0.0.1' },
  })
  server.notify('notifications/initialized', {})
  const listed = await server.request('tools/list', {})

  return {
    ...server,
    initialized,
    tools: listed.tools,
    /** Call a tool and return its first text content (the model-facing text). */
    call: async (name, args = {}) => {
      const result = await server.request('tools/call', { name, arguments: args })
      const text = result?.content?.[0]?.text ?? ''
      return { result, text }
    },
  }
}

/** Parse the `ok`/`code:` lines of a rendered tool result. */
export function parseResultText(text) {
  const out = { ok: null, code: null, lines: text.split('\n') }
  for (const line of out.lines) {
    if (line === 'ok') out.ok = true
    else if (line.startsWith('code: ')) out.code = line.slice(6).trim()
  }
  return out
}
