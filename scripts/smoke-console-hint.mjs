/**
 * Smoke: prove the console URL is handed to the model through a real MCP
 * tool round-trip (no browser launch anywhere in the server process).
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Resolved from this file, never hardcoded: the repo path is machine-specific.
const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const NODE = process.execPath
const transport = new StdioClientTransport({
  command: NODE,
  args: [join(root, 'lib', 'server.js')],
  env: process.env,
  stderr: 'inherit',
})
const client = new Client({ name: 'smoke', version: '1.0.0' })
await client.connect(transport)

const tools = await client.listTools()
console.log('tools=' + tools.tools.length)

const first = await client.callTool({ name: 'jumpserver_status', arguments: {} })
const text = first.content[0].text
console.log('--- first tool text (head) ---')
console.log(text.slice(0, 400))
console.log('hint present: ' + text.includes('[jumpserver-console]'))
console.log('present_files instructed: ' + text.includes('present_files'))

const second = await client.callTool({ name: 'jumpserver_audit', arguments: { limit: 3 } })
console.log('hint repeat on 2nd call: ' + second.content[0].text.includes('[jumpserver-console]'))

await new Promise((r) => setTimeout(r, 1200))
const dir = join(root, 'data', 'consoles')
try {
  for (const f of readdirSync(dir)) console.log('registry ' + f + ' -> ' + readFileSync(join(dir, f), 'utf8').trim())
} catch (e) {
  console.log('registry MISSING: ' + e.message)
}

await client.close()
process.exit(0)
