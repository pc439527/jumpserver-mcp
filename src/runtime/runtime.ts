/**
 * jumpserver-mcp runtime assembly — replaces dsh-jumpserver src/index.ts
 * (cordis context, DSH credential domain and storage domain are replaced by
 * env-var password resolution and a JSONL audit file).
 *
 * V0.5.0: the connection four-tuple (host / port / username / password) can
 * come from the WorkBuddy connector form through environment variables, so
 * config.json is optional. Resolution order is ENV > config.json > defaults.
 */
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseConfig, type McpConfig } from '../config/schema.js'
import {
  ENV_KEYS,
  LIFECYCLE_ENV_KEYS,
  readEnvConnection,
  sourceOf,
  type ConnectionView,
  type EnvConnection,
} from '../config/env.js'
import { AuditStore, DEFAULT_AUDIT_RING_SIZE } from './audit-store.js'
import { JobStore } from './job-store.js'
import { TopologyStore } from './topology-store.js'
import { BaselineStore } from './baseline-store.js'
import { AssetStore } from './asset-store.js'
import { resolveTimeZone } from './time.js'
import { startAuditViewer, notifyAuditRecord } from './audit-viewer.js'
import { SessionManager } from '../jumpserver/session-manager.js'
import type { AuditRecord } from '../jumpserver/session-manager.js'
import { SessionRegistry, type SessionBundle } from '../jumpserver/session-registry.js'
import { Semaphore } from '../jumpserver/concurrency.js'
import { DEFAULT_BATCH_CONCURRENCY, DEFAULT_MAX_SESSIONS } from '../config/types.js'
import { TerminalObserver } from '../jumpserver/terminal-observer.js'
import { KnownHostsStore } from '../jumpserver/host-key.js'
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
  /** V0.4.1: named baselines for drift detection (data/baselines/*.json). */
  baselines: BaselineStore
  /** V0.4.1: last asset listing, shared with the console's 资产 tab. */
  assets: AssetStore
  /** V0.4.0: display timezone for audit timestamps (storage stays UTC). */
  timeZone: string
  /**
   * V0.5.0: where each live connection value came from (ENV / config.json /
   * default). Read by the console's 设置 tab. Never carries the password value
   * — only the name of the layer that supplies it.
   */
  connection: () => ConnectionView
  /**
   * V0.4.3: whether this process can keep several conversations apart.
   *  - 'transport'  the host assigns a sessionId per request (HTTP/SSE)
   *  - 'env'        JUMPSERVER_MCP_SESSION pins one scope per process
   *  - 'process'    stdio process-per-conversation (the WorkBuddy default)
   * Anything else means one process is silently serving several conversations
   * with a single shared bastion session.
   */
  sessionScope: SessionScopeMode
  dispose: () => void
}

export type SessionScopeMode = 'transport' | 'env' | 'process' | 'shared-unsafe'

/** Project root (two levels up from this file: lib/runtime -> lib -> root). */
function projectRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url))
  return join(here, '..', '..')
}

function log(message: string): void {
  // MCP stdio: stdout is protocol-only; diagnostics go to stderr.
  console.error('[jumpserver-mcp] ' + message)
}

/**
 * Read config.json if it exists. V0.5.0: a missing file is NOT an error any
 * more — the connector form may supply everything the connection needs — so
 * this returns an empty object and lets `parseConfig` judge the merged view.
 */
function readConfigFile(configPath: string): Record<string, unknown> {
  if (!existsSync(configPath)) {
    log(
      'no config file at ' + configPath + ' — falling back to connector environment (' +
        ENV_KEYS.host + ' / ' + ENV_KEYS.username + ') and built-in defaults',
    )
    return {}
  }
  try {
    const parsed: unknown = JSON.parse(readFileSync(configPath, 'utf8'))
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('config root must be a JSON object')
    }
    return parsed as Record<string, unknown>
  } catch (error) {
    log('invalid config at ' + configPath + ': ' + (error instanceof Error ? error.message : String(error)))
    throw error
  }
}

export function createRuntime(): Runtime {
  const root = projectRoot()
  const configPath = process.env[LIFECYCLE_ENV_KEYS.configPath] ?? join(root, 'config.json')

  const configPresent = existsSync(configPath)
  const fileConfig = readConfigFile(configPath)

  const envConnection: EnvConnection = readEnvConnection()

  let config: McpConfig
  try {
    config = parseConfig(fileConfig, envConnection)
  } catch (error) {
    // ConfigIncompleteError already carries operator-facing instructions.
    log(error instanceof Error ? error.message : String(error))
    throw error
  }

  // V0.5.0: default the TOFU host-key store next to the audit sink. An
  // explicit knownHostsPath wins; an empty string counts as unset.
  if (config.knownHostsPath === undefined || config.knownHostsPath.length === 0) {
    config.knownHostsPath = join(root, 'data', 'known_hosts.json')
  }

  const auditPath = config.auditPath ?? join(root, 'data', 'audit.jsonl')

  const getConfig = (): McpConfig => config

  /**
   * Resolve the password per connect; never cache, never log.
   *
   * V0.5.0 precedence (highest first) — mirrors ConnectionView.password:
   *   1. the connector-injected credential (JUMPSERVER_PASSWORD)
   *   2. the env var named by the caller, else by config.passwordEnv
   *   3. a literal `password` in config.json
   */
  const resolvePassword = (env?: string): string | undefined => {
    const injected = process.env[ENV_KEYS.password]
    if (injected !== undefined && injected.length > 0) return injected

    const cfg = getConfig()
    const name = env !== undefined && env.length > 0 ? env : cfg.passwordEnv
    if (name !== ENV_KEYS.password) {
      const hit = process.env[name]
      if (hit !== undefined && hit.length > 0) return hit
    }

    const literal = cfg.password
    return literal !== undefined && literal.length > 0 ? literal : undefined
  }

  /** Describe — never reveal — the effective credential source. */
  const passwordView = (): ConnectionView['password'] => {
    const injected = process.env[ENV_KEYS.password]
    if (injected !== undefined && injected.length > 0) {
      return { source: 'env', present: true, via: ENV_KEYS.password }
    }
    const named = process.env[config.passwordEnv]
    if (named !== undefined && named.length > 0) {
      return { source: 'env', present: true, via: config.passwordEnv }
    }
    if (config.password !== undefined && config.password.length > 0) {
      return { source: 'config', present: true, via: 'password' }
    }
    return { source: 'default', present: false }
  }

  const connection = (): ConnectionView => ({
    host: { value: config.host, source: sourceOf(fileConfig['host'], envConnection.host) },
    port: { value: String(config.port), source: sourceOf(fileConfig['port'], envConnection.port) },
    username: { value: config.username, source: sourceOf(fileConfig['username'], envConnection.username) },
    password: passwordView(),
    configPath,
    configPresent,
    complete: config.host.length > 0 && config.username.length > 0,
  })

  /**
   * V0.5.0: the console's 设置 tab shows policy values that only config.json
   * can set — deliberately kept separate from the connection four-tuple, which
   * the WorkBuddy connector form owns.
   */
  const policyView = (): Record<string, unknown> => ({
    permissionMode: config.permissionMode,
    privilegedReadInReadOnly: config.privilegedReadInReadOnly ?? false,
    requireArm: config.requireArm,
    allowedTargets: config.allowedTargets ?? [],
    deniedTargets: config.deniedTargets ?? [],
    batchConcurrency: config.batchConcurrency ?? DEFAULT_BATCH_CONCURRENCY,
    maxSessions: config.maxSessions ?? DEFAULT_MAX_SESSIONS,
    timeZone: resolveTimeZone(config.timeZone),
    auditViewerPort: config.auditViewer.port,
    auditTokenTtlMinutes: config.auditViewer.tokenTtlMinutes,
    assetGroups: Object.keys(config.assetGroups ?? {}),
    runbooks: Object.keys(config.runbooks ?? {}),
    hostFingerprint: config.hostFingerprint ?? '（未固定，使用 TOFU）',
  })

  /** V0.5.0: known_hosts records, for visibility only — never edited here. */
  const knownHostsView = (): { path?: string; entries: Record<string, unknown> } => {
    const path = config.knownHostsPath
    if (path === undefined || path.length === 0) return { entries: {} }
    try {
      return { path, entries: new KnownHostsStore(path).entries() }
    } catch {
      return { path, entries: {} }
    }
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
  // V0.4.3: one gate for the whole process — `maxSessions` now really caps how
  // many targets are entered at once when batchConcurrency > 1.
  const sessionGate = new Semaphore(config.maxSessions ?? DEFAULT_MAX_SESSIONS)
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
        sessionGate,
      })
      return { manager, observer, lastUsedAt: Date.now() }
    },
  })

  // Embedded ops console (default on): audit mirror + live terminal + stats +
  // session control, served in-process. Browser auto-opens on the FIRST
  // audited command, not at boot.
  const jobs = new JobStore(registry)
  const topology = new TopologyStore()
  const baselines = new BaselineStore(join(root, 'data', 'baselines'))
  const assets = new AssetStore()

  startAuditViewer(auditPath, config.auditViewer, registry, {
    audit,
    jobs,
    topology,
    assets,
    baselines,
    timeZone: resolveTimeZone(config.timeZone),
    connection,
    policy: policyView,
    knownHosts: knownHostsView,
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

  const sessionScope = detectSessionScope()
  log(
    'session scope: ' + describeSessionScope(sessionScope) +
      ' — one bastion PTY per scope; a host that multiplexes conversations in one process must set a transport sessionId or JUMPSERVER_MCP_SESSION',
  )

  const view = connection()
  log(
    'connection: ' + String(view.host.value) + ':' + String(view.port.value) + ' as ' +
      String(view.username.value) + ' (host from ' + view.host.source +
      ', credential from ' + view.password.source + ')',
  )

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
    baselines,
    assets,
    timeZone: resolveTimeZone(config.timeZone),
    connection,
    sessionScope,
    dispose: () => {
      clearInterval(timer)
      jobs.dispose()
      registry.dispose()
    },
  }
}

/**
 * V0.4.3: decide — and WARN LOUDLY — whether this process can distinguish
 * conversations.
 *
 * WorkBuddy spawns one MCP stdio server per conversation, so the default is
 * safe: process isolation IS the conversation boundary. The dangerous case is
 * a host that multiplexes several conversations over ONE process without
 * supplying a transport sessionId — then every conversation shares
 * ANONYMOUS_SESSION, and one user's entered asset leaks into another's
 * terminal. We cannot detect that from inside, so we state the assumption and
 * tell the operator exactly how to fix it rather than pretending the registry
 * is multi-conversation when it is not.
 */
function detectSessionScope(): SessionScopeMode {
  const env = process.env[LIFECYCLE_ENV_KEYS.sessionScope]
  if (env !== undefined && env.length > 0) return 'env'
  return 'process'
}

export function describeSessionScope(mode: SessionScopeMode): string {
  switch (mode) {
    case 'transport':
      return 'per-request transport sessionId'
    case 'env':
      return 'JUMPSERVER_MCP_SESSION (one scope per process)'
    case 'process':
      return 'process isolation (one MCP server per conversation)'
    case 'shared-unsafe':
      return 'SHARED (several conversations, one session scope)'
  }
}
