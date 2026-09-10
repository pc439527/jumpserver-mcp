/**
 * jumpserver-mcp runtime assembly — replaces dsh-jumpserver src/index.ts
 * (cordis context, DSH credential domain and storage domain are replaced by
 * env-var password resolution and a JSONL audit file).
 */
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseConfig, type McpConfig } from '../config/schema.js'
import { AuditStore, DEFAULT_AUDIT_RING_SIZE } from './audit-store.js'
import { JobStore } from './job-store.js'
import { TopologyStore } from './topology-store.js'
import { resolveTimeZone } from './time.js'
import { startAuditViewer, notifyAuditRecord } from './audit-viewer.js'
import { SessionManager } from '../jumpserver/session-manager.js'
import type { AuditRecord } from '../jumpserver/session-manager.js'
import { SessionRegistry, type SessionBundle } from '../jumpserver/session-registry.js'
import { TerminalObserver } from '../jumpserver/terminal-observer.js'
import { SessionGrant } from '../security/grant.js'

export interface Runtime {
  registry: SessionRegistry
  grants: SessionGrant
  getConfig: () => McpConfig
  resolvePassword: (env?: string) => string | undefined
  configPath: string
  auditPath: string
  /** V0.4.0: incremental audit sink (console + jumpserver_audit read it). */
  audit: AuditStore
  /** V0.4.0: streaming jobs (tail -f / journalctl -f / tcpdump …). */
  jobs: JobStore
  /** V0.4.0: last topology result, shared with the console's 拓扑 tab. */
  topology: TopologyStore
  /** V0.4.0: display timezone for audit timestamps (storage stays UTC). */
  timeZone: string
  dispose: () => void
}

/** Project root (two levels up from this file: lib/runtime -> lib -> root). */
function projectRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url))
  return join(here, '..', '..')
}

function log(message: string): void {
  // MCP stdio: stdout is protocol-only; diagnostics go to stderr.
  console.error('[jumpserver-mcp] ' + message)
}

export function createRuntime(): Runtime {
  const root = projectRoot()
  const configPath = process.env['JUMPSERVER_MCP_CONFIG'] ?? join(root, 'config.json')
  if (!existsSync(configPath)) {
    log('config not found at ' + configPath + ' — copy config.example.json to config.json and fill host/username; password comes from the ' + 'JUMPSERVER_PASSWORD' + ' env var')
    throw new Error('jumpserver-mcp: config not found at ' + configPath)
  }

  let config: McpConfig
  try {
    config = parseConfig(JSON.parse(readFileSync(configPath, 'utf8')))
  } catch (error) {
    log('invalid config at ' + configPath + ': ' + (error instanceof Error ? error.message : String(error)))
    throw error
  }

  const auditPath = config.auditPath ?? join(root, 'data', 'audit.jsonl')

  const getConfig = (): McpConfig => config

  /** Resolve password per connect; never cache, never log. */
  const resolvePassword = (env?: string): string | undefined => {
    const cfg = getConfig()
    const name = env !== undefined && env.length > 0 ? env : cfg.passwordEnv
    const hit = process.env[name]
    if (hit !== undefined && hit.length > 0) return hit
    const literal = cfg.password
    return literal !== undefined && literal.length > 0 ? literal : undefined
  }

  const audit = new AuditStore(auditPath, {
    ringSize: DEFAULT_AUDIT_RING_SIZE,
    log: (message) => log(message),
  })
  // The sink directory is created once at boot; appends are asynchronous and
  // never block the tool call that produced the record.
  try {
    mkdirSync(dirname(auditPath), { recursive: true })
  } catch (error) {
    log('audit dir create failed: ' + (error instanceof Error ? error.message : String(error)))
  }

  const onAudit = (record: AuditRecord): void => {
    if (getConfig().enableAudit !== true) return
    audit.append(record)
    notifyAuditRecord()
  }

  const grants = new SessionGrant()
  const registry = new SessionRegistry({
    create: (sessionId: string): SessionBundle => {
      const cfg = getConfig()
      const observer = new TerminalObserver(cfg.terminalScrollback)
      const manager = new SessionManager({
        getConfig,
        resolvePassword: async () => resolvePassword(),
        onAudit,
        onLog: (message: string) => log(sessionId + ': ' + message),
        observer,
      })
      return { manager, observer, lastUsedAt: Date.now() }
    },
  })

  // Embedded ops console (default on): audit mirror + live terminal + stats +
  // session control, served in-process. Browser auto-opens on the FIRST
  // audited command, not at boot.
  const jobs = new JobStore(registry)
  const topology = new TopologyStore()

  startAuditViewer(auditPath, config.auditViewer, registry, {
    audit,
    jobs,
    topology,
    timeZone: resolveTimeZone(config.timeZone),
  })

  // Reap idle disconnected bundles (same role as the DSH host fiber timer).
  const timer = setInterval(() => {
    try {
      registry.tickIdle()
    } catch {
      /* reap failures must never kill the server */
    }
  }, 60_000)
  timer.unref?.()

  return {
    registry,
    grants,
    getConfig,
    resolvePassword,
    configPath,
    auditPath,
    audit,
    jobs,
    topology,
    timeZone: resolveTimeZone(config.timeZone),
    dispose: () => {
      clearInterval(timer)
      jobs.dispose()
      registry.dispose()
    },
  }
}
