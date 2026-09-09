#!/usr/bin/env node
/**
 * Debug: connect to the configured bastion, dump the raw KoKo screen after
 * login, then run one fresh 'p' capture and dump rawText + health metrics.
 * Never prints the password (passed via JUMPSERVER_PASSWORD env).
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { SessionManager } from '../lib/jumpserver/session-manager.js'
import { TerminalObserver } from '../lib/jumpserver/terminal-observer.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const raw = JSON.parse(readFileSync(join(root, 'config.json'), 'utf8'))

const config = {
  enabled: true,
  autoOpenTerminal: true,
  terminalScrollback: 4000,
  host: raw.host,
  port: raw.port ?? 2222,
  username: raw.username,
  passwordEnv: raw.passwordEnv ?? 'JUMPSERVER_PASSWORD',
  connectTimeout: 20,
  commandTimeout: 60,
  idleTimeout: 30,
  permissionMode: raw.permissionMode ?? 'READ_ONLY',
  autoReconnect: true,
  enableAudit: false,
}

const observer = new TerminalObserver(4000)
const manager = new SessionManager({
  getConfig: () => config,
  resolvePassword: async () => process.env.JUMPSERVER_PASSWORD,
  onLog: (m) => console.error('[core] ' + m),
  observer,
})

function dumpScreen(tag) {
  console.log('\n===== SCREEN ' + tag + ' =====')
  for (const e of observer.snapshot()) {
    if (e.type === 'output') process.stdout.write(e.data)
    else if (e.type === 'state') console.log('\n[state] ' + (e.prev ?? '?') + ' -> ' + e.state)
    else if (e.type === 'error') console.log('\n[error] ' + e.message)
  }
  console.log('\n===== END SCREEN =====')
}

try {
  const st = await manager.connect()
  console.log('CONNECT state=' + st.state + ' gateway=' + st.gateway)
  dumpScreen('after connect')

  const r = await manager.listAssets(undefined, undefined, true)
  console.log('\nLIST health=' + r.health + ' rawRows=' + r.rawRows + ' parsedRows=' + r.parsedRows +
    ' reportedTotal=' + r.reportedTotal + ' complete=' + r.complete + ' paged=' + r.paged)
  console.log('--- rawText (' + r.rawText.length + ' chars) ---')
  console.log(r.rawText)
  console.log('--- assets ---')
  console.log(JSON.stringify(r.assets.slice(0, 5), null, 2))

  const st2 = manager.status()
  console.log('\nFINAL state=' + st2.state + ' target=' + (st2.target ?? 'none'))
  process.exit(0)
} catch (error) {
  console.error('FAILED: ' + (error instanceof Error ? error.stack ?? error.message : String(error)))
  dumpScreen('on failure')
  process.exit(1)
}
