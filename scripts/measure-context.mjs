#!/usr/bin/env node
/**
 * Context-cost meter: how many bytes does `tools/list` push into EVERY
 * conversation of the host? An MCP client injects the whole tool table up
 * front, so this number is a permanent tax on every chat — including chats
 * that never touch JumpServer.
 *
 *   node scripts/measure-context.mjs            # report
 *   node scripts/measure-context.mjs --budget 18000   # exit 1 when over
 *   node scripts/measure-context.mjs --json     # machine-readable
 *
 * Exit codes: 0 = within budget, 1 = over budget (CI gate), 2 = boot failure.
 * No SSH connection is made — only `initialize` + `tools/list`.
 */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function argValue(flag) {
  const i = process.argv.indexOf(flag)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : null
}
const asJson = process.argv.includes('--json')
const budget = Number(argValue('--budget') ?? '0') || 0

/** ~4 characters per token is the usual English/JSON heuristic. */
const CHARS_PER_TOKEN = 4

async function listTools() {
  const child = spawn(process.execPath, [join(root, 'lib', 'server.js')], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, JUMPSERVER_MCP_CONFIG: join(root, 'config.example.json') },
  })

  let stderr = ''
  child.stderr.on('data', (d) => { stderr += d.toString() })

  const pending = new Map()
  let nextId = 1
  createInterface({ input: child.stdout }).on('line', (line) => {
    if (line.trim().length === 0) return
    let msg
    try { msg = JSON.parse(line) } catch { return }
    const entry = msg.id !== undefined ? pending.get(msg.id) : undefined
    if (entry === undefined) return
    pending.delete(msg.id)
    if (msg.error !== undefined) entry.reject(new Error(JSON.stringify(msg.error)))
    else entry.resolve(msg.result)
  })

  const send = (method, params) => {
    const id = nextId++
    const promise = new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject })
      setTimeout(() => {
        if (pending.has(id)) { pending.delete(id); reject(new Error('timeout waiting for ' + method)) }
      }, 15000)
    })
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
    return promise
  }

  try {
    await send('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'measure-context', version: '0.0.1' },
    })
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n')
    return { tools: (await send('tools/list', {})).tools, stderr }
  } finally {
    child.kill()
  }
}

let listed
try {
  listed = await listTools()
} catch (error) {
  console.error('measure-context: could not read tools/list — ' + (error instanceof Error ? error.message : String(error)))
  if (error !== null && typeof error === 'object') { /* stderr already surfaced by the caller below */ }
  process.exit(2)
}

const rows = listed.tools.map((t) => {
  const description = t.description ?? ''
  const inputSchema = JSON.stringify(t.inputSchema ?? {})
  return {
    name: t.name,
    descriptionBytes: Buffer.byteLength(description),
    schemaBytes: Buffer.byteLength(inputSchema),
    totalBytes: Buffer.byteLength(description) + Buffer.byteLength(inputSchema),
    hasAnnotations: t.annotations !== undefined && t.annotations !== null,
  }
}).sort((a, b) => b.totalBytes - a.totalBytes)

const totals = {
  tools: rows.length,
  serializedBytes: Buffer.byteLength(JSON.stringify(listed.tools)),
  descriptionBytes: rows.reduce((s, r) => s + r.descriptionBytes, 0),
  schemaBytes: rows.reduce((s, r) => s + r.schemaBytes, 0),
  annotated: rows.filter((r) => r.hasAnnotations).length,
}
totals.estimatedTokens = Math.round(totals.serializedBytes / CHARS_PER_TOKEN)

if (asJson) {
  console.log(JSON.stringify({ totals, tools: rows }, null, 2))
} else {
  console.log('tools: ' + totals.tools + '  |  annotated: ' + totals.annotated + '/' + totals.tools)
  console.log('tools/list payload: ' + totals.serializedBytes + ' B  (~' + totals.estimatedTokens + ' tokens every conversation)')
  console.log('  descriptions: ' + totals.descriptionBytes + ' B')
  console.log('  inputSchemas: ' + totals.schemaBytes + ' B')
  console.log('')
  console.log('  desc B  schema B  total  ann  tool')
  for (const r of rows) {
    console.log(
      String(r.descriptionBytes).padStart(7) + '  ' + String(r.schemaBytes).padStart(8) + '  ' +
      String(r.totalBytes).padStart(5) + '  ' + (r.hasAnnotations ? ' y ' : ' - ') + '  ' + r.name,
    )
  }
  console.log('')
  console.log('largest 5 hold ' +
    String(Math.round(rows.slice(0, 5).reduce((s, r) => s + r.totalBytes, 0) / totals.serializedBytes * 100)) +
    '% of the payload')
}

if (budget > 0 && totals.serializedBytes > budget) {
  console.error('')
  console.error('BUDGET EXCEEDED: ' + totals.serializedBytes + ' B > ' + budget + ' B')
  process.exit(1)
}
process.exit(0)
