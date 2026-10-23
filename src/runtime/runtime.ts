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
import { configProblems as missingConnectionFields, parseConfigLenient, type McpConfig } from '../config/schema.js'
import {
  ENV_KEYS,
  LIFECYCLE_ENV_KEYS,
  readEnvConnection,
  sourceOf,
  type ConnectionView,
  type EnvConnection,
} from '../config/env.js'
import { AuditStore, DEFAULT_AUDIT_RETAIN_DAYS, DEFAULT_AUDIT_RING_SIZE } from './audit-store.js'
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
import { DEFAULT_BATCH_CONCURRENCY, DEFAULT_MAX_SESSIONS, type ConsoleTabId } from '../config/types.js'
import { TerminalObserver } from '../jumpserver/terminal-observer.js'
import { KnownHostsStore } from '../jumpserver/host-key.js'
import { SessionGrant } from '../security/grant.js'
import { CredentialVault } from '../security/credential-vault.js'
import { ProfileStore, type ProfileView } from './profile-store.js'
import { ConsolePrefsStore, consolePrefsPathHint } from './console-prefs.js'
import { consoleTabSources, resolveConsoleTabs } from './console-tabs.js'

export interface Runtime {
  registry: SessionRegistry
  grants: SessionGrant
  getConfig: () => McpConfig
  /**
   * V0.5.2: required connection fields still missing — empty array when the
   * connection is usable. Connect-needing tools refuse with
   * `CONFIG_INCOMPLETE` while this is non-empty (see runtime/config-guard.ts);
   * `jumpserver_status` reports the list instead of refusing, so a user can
   * always find out WHAT to fill in.
   *
   * V0.5.11: judged against the EFFECTIVE connection, so a selected account
   * that supplies a host/username counts as complete even when config.json and
   * the environment carry neither.
   */
  configProblems: () => readonly string[]
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
   * V0.5.11: the locally stored multi-account profiles. Redacted views only —
   * the active profile id, the list of profiles (never a token or a password),
   * the file integrity flag, whether the console may write, and a path hint.
   */
  accounts: () => Record<string, unknown>
  /**
   * V0.5.11: point the connector at one stored account (`null` = none). This
   * DESTROYS every live session, because those PTYs were authenticated with the
   * previous credential; the next tool call reconnects with the new one.
   */
  switchAccount: (id: string | null) => { ok: boolean; error?: string }
  /** V0.5.11: create/update one account. Refused when credential writes are off. */
  saveAccount: (input: Record<string, unknown>) => { ok: boolean; error?: string }
  /** V0.5.11: delete one account. Structured so the console can tell a missing
   * id from a disabled write path and from a corrupt store. */
  removeAccount: (id: string) => { ok: boolean; error?: string }
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

/**
 * Project root (two levels up from this file: lib/runtime -> lib -> root).
 * Exported so `--doctor` resolves config.json and the data directory exactly
 * the way the real runtime does — a diagnostic that disagrees with the thing
 * it diagnoses is worse than none.
 */
export function projectRoot(): string {
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

  // V0.5.2: an incomplete connection no longer kills the process. The MCP
  // handshake must succeed so the host can show "fill in the connector form"
  // instead of "the server failed to start"; tools that actually need the
  // bastion answer with a structured CONFIG_INCOMPLETE. A MALFORMED config
  // still throws — a missing value is recoverable at runtime, a broken file
  // is not, and silently ignoring it would hide a real operator mistake.
  const parsed = parseConfigLenient(fileConfig, envConnection)
  const config: McpConfig = parsed.cfg
  const problems: readonly string[] = parsed.problems
  if (problems.length > 0) {
    log(
      'connection INCOMPLETE (' + problems.join(' / ') + ') — starting anyway so the host can report it; ' +
        'connect-needing tools answer CONFIG_INCOMPLETE',
    )
  }

  // V0.5.0: default the TOFU host-key store next to the audit sink. An
  // explicit knownHostsPath wins; an empty string counts as unset.
  if (config.knownHostsPath === undefined || config.knownHostsPath.length === 0) {
    config.knownHostsPath = join(root, 'data', 'known_hosts.json')
  }

  const auditPath = config.auditPath ?? join(root, 'data', 'audit.jsonl')

  /**
   * V0.5.11 — the EFFECTIVE connection tuple.
   *
   * An explicitly selected account outranks the host and username the connector
   * form injected: otherwise the multi-account store could only ever swap the
   * PASSWORD while the identity (host / port / username) stayed pinned to the
   * form, and a second account with a DIFFERENT login name would simply fail to
   * authenticate. The profile store is read lazily, per call, so switching
   * accounts takes effect on the very next connect.
   *
   * ONLY host / port / username are overlaid. Every other field (policy, target
   * scope, concurrency, timeouts, audit settings …) is returned exactly as
   * config.json produced it — `getConfig()` has other callers and must not
   * silently change their view of the world.
   */
  const effectiveConfig = (): McpConfig => {
    const active = profiles.getActive()
    if (active === null) return config
    // ProfileStore only ever accepts a port in 1..65535, so this guard is a
    // defensive fallback for a hand-edited file: a bogus port falls back to the
    // configured one instead of being handed to the SSH layer.
    const port = Number.isInteger(active.port) && active.port >= 1 && active.port <= 65535
      ? active.port
      : config.port
    return { ...config, host: active.host, port, username: active.username }
  }

  const getConfig = (): McpConfig => effectiveConfig()

  /**
   * Resolve the password per connect; never cache, never log.
   *
   * V0.5.11 precedence (highest first) — mirrors ConnectionView.password:
   *   0. the ACTIVE multi-account profile (an explicitly selected bastion
   *      account outranks the single credential injected by the connector form
   *      — that is exactly what the multi-account store exists for)
   *   1. the connector-injected credential (JUMPSERVER_PASSWORD)
   *   2. the env var named by the caller, else by config.passwordEnv
   *   3. a literal `password` in config.json
   *
   * Profile resolution is deliberately fail-open into the chain below: a
   * missing profile, no stored secret or a failed decrypt simply moves on, so
   * an account problem can never by itself make the connector unable to reach
   * the bastion.
   */
  const resolvePassword = (env?: string): string | undefined => {
    const active = profiles.getActive()
    if (active !== null) {
      const stored = profiles.resolvePassword(active.id)
      if (stored !== undefined && stored.length > 0) return stored
    }

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
    const active = profiles.getActive()
    if (active !== null) {
      const stored = profiles.resolvePassword(active.id)
      // The label is an operator-chosen display name; no credential value ever
      // reaches this view.
      if (stored !== undefined && stored.length > 0) {
        return { source: 'profile', present: true, via: active.label }
      }
    }
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

  const connection = (): ConnectionView => {
    const active = profiles.getActive()
    const cfg = effectiveConfig()
    // A selected account IS the identity this process will log in with, so the
    // three identity fields report `profile` as their source. Without a
    // selected account the original ENV > config.json > default layers stand.
    // The password branch keeps its own precedence (see passwordView()).
    return {
      host: active !== null
        ? { value: cfg.host, source: 'profile' }
        : { value: config.host, source: sourceOf(fileConfig['host'], envConnection.host) },
      port: active !== null
        ? { value: String(cfg.port), source: 'profile' }
        : { value: String(config.port), source: sourceOf(fileConfig['port'], envConnection.port) },
      username: active !== null
        ? { value: cfg.username, source: 'profile' }
        : { value: config.username, source: sourceOf(fileConfig['username'], envConnection.username) },
      password: passwordView(),
      configPath,
      configPresent,
      complete: cfg.host.length > 0 && cfg.username.length > 0,
    }
  }

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
    // V0.7.1 (D-7): keep 30 days of rotated daily files; older ones are swept.
    retainDays: DEFAULT_AUDIT_RETAIN_DAYS,
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
    rotateAuditIfDayChanged()
    audit.append(record)
    notifyAuditRecord()
  }

  // V0.7.1 (D-7): rotate the audit file on a DAY boundary.
  //
  // The check is cheap (one date string per record) and runs on the write
  // path, so no timer is needed and no rotation can be missed because the
  // process was idle across midnight. The rotation itself is asynchronous and
  // never blocks the tool call that produced the record.
  let auditDay = new Date().toISOString().slice(0, 10)
  let auditRotation: Promise<void> = Promise.resolve()
  const rotateAuditIfDayChanged = (): void => {
    const today = new Date().toISOString().slice(0, 10)
    if (today === auditDay) return
    const closedDay = auditDay
    auditDay = today
    auditRotation = auditRotation
      .then(() => audit.rotateForDay(closedDay))
      .then((result) => {
        if (result.rotated) {
          log(
            'audit rotated: ' + String(result.path) +
              (result.metricsPath !== null ? ' metrics=' + String(result.metricsPath) : '') +
              (result.pruned.length > 0 ? ' pruned=' + String(result.pruned.length) : ''),
          )
        }
      })
      .catch((error) => {
        log('audit rotation failed: ' + String(error))
      })
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

  // V0.5.11: the multi-account store. The vault holds the AES-256-GCM key (and
  // encrypts each profile's password); the profile store keeps the redacted
  // list and the active pointer under ~/.workbuddy/jumpserver-mcp/. Created
  // before the first connection() call below, since passwordView/resolvePassword
  // read the active profile.
  const vault = new CredentialVault()
  const profiles = new ProfileStore({ vault, log: (message) => log(message) })

  // V0.5.13: the console's own tab-visibility preferences, written by the
  // switches in the 设置 tab. Separate from config.json on purpose — the file
  // belongs to the operator and the connector form may rewrite it, so a click
  // in the browser needs a store the console actually owns. config.json still
  // wins when it pins a tab explicitly (resolveConsoleTabs).
  const consolePrefs = new ConsolePrefsStore({ log: (message) => log(message) })

  /**
   * V0.5.13: the ONE place the two preference layers are merged. The page
   * render, the settings payload and the write route all call this, so the nav
   * that was rendered can never disagree with what the switches report.
   */
  const resolveVisibleTabs = (): ConsoleTabId[] =>
    resolveConsoleTabs(getConfig().auditViewer.tabs ?? {}, consolePrefs.visibility())

  /**
   * V0.5.13: everything the 设置 tab needs to draw the tab switches — which
   * tabs are visible, which layer decided each one (so a config-pinned tab can
   * be rendered locked instead of silently ignoring the click), and whether the
   * local store is readable. `hidden` is the local layer alone, so the UI can
   * tell "you turned this off" from "config.json turned this off".
   */
  const consoleTabReport = (): Record<string, unknown> => ({
    visible: resolveVisibleTabs(),
    sources: consoleTabSources(getConfig().auditViewer.tabs ?? {}, consolePrefs.visibility()),
    hidden: consolePrefs.hidden(),
    integrity: consolePrefs.integrity(),
    storePathHint: consolePrefsPathHint(),
  })

  /**
   * V0.5.11: the 设置 tab's account payload. `profiles.list()` is already a
   * redacted view (id/label/host/port/username/hasSecret/active) — no token and
   * no plaintext is ever placed in here.
   */
  const accounts = (): Record<string, unknown> => ({
    activeProfileId: profiles.getActive()?.id ?? null,
    profiles: profiles.list(),
    integrity: profiles.integrity(),
    allowWrite: getConfig().auditViewer.allowCredentialWrite !== false,
    storePathHint: '~/.workbuddy/jumpserver-mcp/profiles.json',
  })

  /**
   * V0.5.11: switch the active account. The existing PTYs were authenticated
   * with the OLD credential and must not outlive the switch, so every session
   * bundle is disposed and the per-session asset cache is cleared. The
   * conversation grant is revoked as well: it is the user's standing
   * authorization for this conversation, but it was given while the process
   * pointed at the PREVIOUS login, and this process now connects as a different
   * identity — carrying that approval across would silently extend it to an
   * account the user never approved. The next tool call reconnects with the
   * newly selected account.
   */
  const switchAccount = (id: string | null): { ok: boolean; error?: string } => {
    let applied: ProfileView | null
    try {
      applied = profiles.setActive(id)
    } catch {
      // setActive refuses to write while the profiles file is corrupt.
      return { ok: false, error: 'PROFILES_FILE_UNREADABLE' }
    }
    if (id !== null && applied === null) return { ok: false, error: 'PROFILE_NOT_FOUND' }
    registry.dispose()
    assets.clear()
    grants.revokeAll()
    return { ok: true }
  }

  /**
   * V0.5.11: create/update one account. Validation lives here (the single write
   * path), and each refusal carries its OWN error category instead of collapsing
   * "unknown id" and "corrupt store" into one catch-all.
   */
  const saveAccount = (input: Record<string, unknown>): { ok: boolean; error?: string } => {
    if (getConfig().auditViewer.allowCredentialWrite === false) {
      return { ok: false, error: 'CREDENTIAL_WRITE_DISABLED' }
    }
    const label = typeof input['label'] === 'string' ? input['label'].trim() : ''
    const host = typeof input['host'] === 'string' ? input['host'].trim() : ''
    const username = typeof input['username'] === 'string' ? input['username'].trim() : ''
    const rawPort = input['port']
    const port = typeof rawPort === 'number' ? rawPort : Number(rawPort)
    if (label.length === 0 || host.length === 0 || username.length === 0) {
      return { ok: false, error: 'INVALID_ARGUMENT' }
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { ok: false, error: 'INVALID_ARGUMENT' }
    }
    const id = typeof input['id'] === 'string' && input['id'].length > 0 ? input['id'] : undefined
    // An update must name an existing profile: ProfileStore throws on an unknown
    // id, and a caller must never believe it updated something it did not. An
    // unreadable store makes the list empty, so report that cause first rather
    // than mislabelling every id as "not found".
    if (id !== undefined && !profiles.list().some((p) => p.id === id)) {
      return profiles.integrity().broken
        ? { ok: false, error: 'PROFILES_FILE_UNREADABLE' }
        : { ok: false, error: 'PROFILE_NOT_FOUND' }
    }
    // password: a non-empty string stores it; null forgets it; an absent or
    // empty value keeps whatever is already stored.
    const rawPassword = input['password']
    let password: string | null | undefined
    if (rawPassword === null) password = null
    else if (typeof rawPassword === 'string' && rawPassword.length > 0) password = rawPassword
    else password = undefined
    try {
      profiles.upsert({ id, label, host, port, username, password })
      return { ok: true }
    } catch {
      // A CORRUPT store is the one case the operator must fix by hand
      // (ProfileStore refuses to overwrite it); anything else is a plain write
      // failure. Category only — never the underlying message, which could
      // echo file contents.
      return profiles.integrity().broken
        ? { ok: false, error: 'PROFILES_FILE_UNREADABLE' }
        : { ok: false, error: 'ACCOUNT_WRITE_FAILED' }
    }
  }

  /**
   * V0.5.11: delete one account. The three refusal causes are kept apart so the
   * console can say "no such account", "writes are off" or "the store is
   * unreadable" instead of a single bare `false`.
   */
  const removeAccount = (id: string): { ok: boolean; error?: string } => {
    if (getConfig().auditViewer.allowCredentialWrite === false) {
      return { ok: false, error: 'CREDENTIAL_WRITE_DISABLED' }
    }
    let removed: boolean
    try {
      removed = profiles.remove(id)
    } catch {
      // ProfileStore refuses to touch a corrupt file.
      return profiles.integrity().broken
        ? { ok: false, error: 'PROFILES_FILE_UNREADABLE' }
        : { ok: false, error: 'ACCOUNT_WRITE_FAILED' }
    }
    return removed ? { ok: true } : { ok: false, error: 'PROFILE_NOT_FOUND' }
  }

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
    // V0.5.10: auditViewer.tabs — read per page load, so a config edit shows up
    // on reload. Absent/empty means every tab (console-tabs.ts owns that rule).
    consoleTabs: () => getConfig().auditViewer.tabs ?? {},
    // V0.5.13: the console-written layer + the 设置 tab block + its write route.
    // A tab toggle carries no credential and grants no permission, so it is NOT
    // behind allowCredentialWrite — only the console token and the same-origin
    // gate, like every other /api route.
    consoleTabLocal: () => consolePrefs.visibility(),
    consoleTabReport,
    setConsoleTab: (id, hidden) => consolePrefs.setHidden(id, hidden),
    // V0.5.11: multi-account views + the three write/thin wrappers.
    accounts,
    switchAccount,
    saveAccount,
    removeAccount,
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
    configProblems: () => missingConnectionFields(effectiveConfig()),
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
    accounts,
    switchAccount,
    saveAccount,
    removeAccount,
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
