#!/usr/bin/env node
/**
 * Is the entry path frozen into the connector registry still a live server?
 *
 * Why this exists: the registry (~/.workbuddy/connectors/<account>/mcp.json)
 * hardcodes the absolute path of the checkout that was installed, and the host
 * caches it. Move the project folder, switch the managed node version, or
 * delete the old checkout, and the symptom is the same and misleading — the
 * connector still shows as enabled while the tool list stays EMPTY, because the
 * child process dies at startup and MCP reports nothing about why. Both have
 * happened here (node `22.22.2-2` → `-3`, and the checkout moving out of
 * `~/WorkBuddy`).
 *
 * This script answers the only question that matters — does that exact command
 * line boot and handshake — without touching the host, and tells you which line
 * of which file to fix when it does not.
 *
 * Read-only: it spawns the server, asks for the tool list, and exits. It never
 * writes the registry; fix the path yourself when it tells you what is wrong.
 *
 *   node scripts/verify-connector-entry.mjs                    # connector:jumpserver
 *   node scripts/verify-connector-entry.mjs --name github
 *   node scripts/verify-connector-entry.mjs --registry <mcp.json>
 */
import { spawn } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function parseArgs(argv) {
  const out = { name: 'jumpserver', registry: null, marketCache: null, localMarket: null }
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--name') out.name = argv[++i]
    else if (argv[i] === '--registry') out.registry = argv[++i]
    else if (argv[i] === '--market-cache') out.marketCache = argv[++i]
    else if (argv[i] === '--local-market') out.localMarket = argv[++i]
  }
  return out
}

/** Every registry this account has, newest first — the connector registry is per-account-id. */
function candidateRegistries() {
  const root = join(homedir(), '.workbuddy', 'connectors')
  if (!existsSync(root)) return []
  return readdirSync(root)
    .map((entry) => join(root, entry, 'mcp.json'))
    .filter((path) => existsSync(path))
}

function findEntry(registryPath, name) {
  const config = JSON.parse(readFileSync(registryPath, 'utf8'))
  const key = 'connector:' + name
  return config?.mcpServers?.[key] === undefined ? null : { key, entry: config.mcpServers[key] }
}

/**
 * The registry is not the only place the entry path gets frozen.
 *
 * "Re-bind from the marketplace" rewrites the registry from the connector
 * package, and a dev-mode package bakes the absolute checkout path in at BUILD
 * time. So a package built before the folder moved will push the old path back
 * and silently undo a manual registry fix — which is exactly what happened on
 * 2026-09-21, where the registry alone looked correct and kept reverting.
 *
 * Checking only the registry is therefore not enough; every install source the
 * host can copy from has to resolve too.
 */
/**
 * A connector package names its server plainly (`jumpserver`); the registry
 * prefixes it (`connector:jumpserver`). Accept both so one lookup works on
 * either side of the install.
 */
function frozenEntryArg(manifestPath, name) {
  const servers = JSON.parse(readFileSync(manifestPath, 'utf8'))?.mcpServers ?? {}
  const entry = servers['connector:' + name] ?? servers[name]
  return entry === undefined ? null : ((entry.args ?? [])[0] ?? null)
}

function installSources(name, overrides) {
  return [
    {
      label: 'market cache',
      path: join(overrides.marketCache ?? join(homedir(), '.workbuddy', 'connectors-marketplace'), 'connectors', name, 'mcp.json'),
      hint: 'reconnect from the connector centre re-copies this into the registry',
    },
    {
      label: 'built package',
      path: join(overrides.localMarket ?? join(ROOT, '.workbuddy', 'artifacts', 'local-market'), 'connectors', name, 'mcp.json'),
      hint: 'this is what a local-market rebuild would serve',
    },
  ]
}

/** Boot the frozen command line and complete an MCP handshake. */
function probe(entry, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const child = spawn(entry.command, entry.args ?? [], { stdio: ['pipe', 'pipe', 'pipe'], env: process.env })
    let out = ''
    let exited = null
    child.stdout.on('data', (d) => { out += d.toString() })
    child.stderr.on('data', (d) => { out += d.toString() })
    child.on('exit', (code) => { exited = code })
    child.on('error', (error) => { exited = String(error.message) })

    const send = (payload) => { try { child.stdin.write(JSON.stringify(payload) + '\n') } catch { /* gone */ } }
    send({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'verify-entry', version: '1' } },
    })
    setTimeout(() => send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }), 500)

    setTimeout(() => {
      try { child.kill() } catch { /* already gone */ }
      resolve({
        handshake: out.includes('"serverInfo"'),
        version: (out.match(/"version":"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"/) ?? [])[1] ?? null,
        tools: (out.match(/"name":"jumpserver_[a-z_]+"/g) ?? []).length,
        exited,
        raw: out,
      })
    }, timeoutMs)
  })
}

const args = parseArgs(process.argv.slice(2))
const registries = args.registry === null ? candidateRegistries() : [args.registry]

if (registries.length === 0) {
  console.log('no connector registry found under ~/.workbuddy/connectors/*/mcp.json')
  process.exit(1)
}

let found = false
let healthy = false

for (const registryPath of registries) {
  let match
  try {
    match = findEntry(registryPath, args.name)
  } catch (error) {
    console.log('registry does not parse: ' + registryPath + ' — ' + String(error.message))
    continue
  }
  if (match === null) continue
  found = true

  const { key, entry } = match
  const entryPath = (entry.args ?? [])[0] ?? null
  console.log('registry    : ' + registryPath)
  console.log('connector   : ' + key)
  console.log('command     : ' + String(entry.command))
  console.log('entry file  : ' + String(entryPath))
  console.log('entry exists: ' + String(entryPath !== null && existsSync(entryPath)))

  if (entryPath === null || !existsSync(entryPath)) {
    console.log('')
    console.log('FAILED — the frozen entry path does not exist, so the host spawns a process that')
    console.log('dies at startup. The connector can still look ENABLED while the tool list is EMPTY.')
    console.log('Fix: point args[0] of "' + key + '" in the registry above at this checkout,')
    console.log('     then reconnect the connector in WorkBuddy (a stale path is cached per session).')
    continue
  }

  const result = await probe(entry)
  console.log('handshake   : ' + (result.handshake ? 'OK' : 'FAILED'))
  console.log('server ver  : ' + String(result.version ?? '-'))
  console.log('tools       : ' + String(result.tools))
  if (result.exited !== null) console.log('child exit  : ' + String(result.exited))

  if (result.handshake && result.tools > 0) {
    healthy = true
  } else {
    console.log('')
    console.log('FAILED — the entry exists but no usable handshake came back.')
    console.log('Run `node lib/server.js --doctor` for the server-side reason.')
    if (result.raw.length > 0) console.log('raw output  : ' + result.raw.slice(0, 400).replace(/\n/g, ' | '))
  }
}

if (!found) {
  console.log('no "connector:' + args.name + '" entry in ' + registries.length + ' registry file(s)')
  process.exit(1)
}

// ---- install sources: the breakage a registry-only check cannot see --------
let sourcesHealthy = true
const stale = []
console.log('')
for (const source of installSources(args.name, args)) {
  if (!existsSync(source.path)) {
    console.log('source      : ' + source.label + ' — absent, cannot re-install')
    continue
  }
  let frozen = null
  try {
    frozen = frozenEntryArg(source.path, args.name)
  } catch (error) {
    console.log('source      : ' + source.label + ' — does not parse (' + String(error.message) + ')')
    sourcesHealthy = false
    continue
  }
  const ok = frozen !== null && existsSync(frozen)
  if (!ok) {
    sourcesHealthy = false
    stale.push(source.label)
  }
  console.log('source      : ' + source.label + (ok ? ' — OK' : ' — STALE'))
  console.log('  entry file: ' + String(frozen))
  if (!ok) console.log('  ' + source.hint)
}

if (stale.length > 0) {
  console.log('')
  console.log('LATENT FAILURE — the registry may work right now, but an install source still')
  console.log('carries a dead path, so the next re-bind or marketplace sync breaks it again.')
  console.log('Fix: `npm run build` then `npm run market:build` from the current checkout, so the')
  console.log('     package freezes the CURRENT path, then reconnect the connector.')
}

console.log('')
const usable = healthy && sourcesHealthy
console.log(
  usable
    ? 'Result: the registry entry boots and serves tools, and every install source resolves.'
    : healthy
      ? 'Result: usable now, but an install source is stale — see LATENT FAILURE above.'
      : 'Result: the registry entry is NOT usable.',
)
process.exit(usable ? 0 : 1)
