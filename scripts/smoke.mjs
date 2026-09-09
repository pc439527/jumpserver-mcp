#!/usr/bin/env node
/**
 * MCP stdio smoke: initialize -> tools/list -> jumpserver_status.
 * Exits 0 when all three succeed; no real SSH connection is made.
 */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const child = spawn(process.execPath, [join(root, 'lib', 'server.js')], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, JUMPSERVER_MCP_CONFIG: join(root, 'config.example.json') },
})

let stderr = ''
child.stderr.on('data', (d) => { stderr += d.toString() })

const pending = new Map()
let nextId = 1

function send(method, params) {
  const id = nextId++
  const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params })
  const promise = new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); reject(new Error('timeout waiting for ' + method)) }
    }, 15000)
  })
  child.stdin.write(msg + '\n')
  return promise
}

function notify(method, params) {
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n')
}

const rl = createInterface({ input: child.stdout })
rl.on('line', (line) => {
  if (line.trim().length === 0) return
  let msg
  try { msg = JSON.parse(line) } catch { return }
  if (msg.id !== undefined && pending.has(msg.id)) {
    const entry = pending.get(msg.id)
    pending.delete(msg.id)
    if (msg.error !== undefined) entry.reject(new Error(methodName(msg) + ' error: ' + JSON.stringify(msg.error)))
    else entry.resolve(msg.result)
  }
})

function methodName(msg) { return msg?.method ?? 'call' }

try {
  const init = await send('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'jumpserver-mcp-smoke', version: '0.0.1' },
  })
  console.log('initialize ok: server=' + init.serverInfo.name + ' v' + init.serverInfo.version)
  notify('notifications/initialized', {})

  const list = await send('tools/list', {})
  const names = list.tools.map((t) => t.name).sort()
  console.log('tools/list ok: ' + names.join(', '))
  const expected = ['jumpserver_assets', 'jumpserver_batch', 'jumpserver_close', 'jumpserver_connect', 'jumpserver_enter', 'jumpserver_exec', 'jumpserver_leave', 'jumpserver_run', 'jumpserver_snapshot', 'jumpserver_status']
  const missing = expected.filter((n) => !names.includes(n))
  if (missing.length > 0) throw new Error('missing tools: ' + missing.join(', '))

  const status = await send('tools/call', { name: 'jumpserver_status', arguments: {} })
  const text = status.content?.[0]?.text ?? ''
  console.log('tools/call jumpserver_status ok:\n' + text)
  if (!text.includes('state: DISCONNECTED')) throw new Error('unexpected status output')

  console.log('SMOKE OK')
  process.exit(0)
} catch (error) {
  console.error('SMOKE FAILED: ' + (error instanceof Error ? error.message : String(error)))
  if (stderr.length > 0) console.error('--- server stderr ---\n' + stderr)
  child.kill()
  process.exit(1)
} finally {
  child.kill()
}
