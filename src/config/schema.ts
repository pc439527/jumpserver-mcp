import { z } from 'zod'
import {
  CONSOLE_TAB_IDS,
  DEFAULT_ASSET_CACHE_TTL_SECONDS,
  DEFAULT_BATCH_CONCURRENCY,
  DEFAULT_MAX_SESSIONS,
  DEFAULT_PASSWORD_ENV,
  DEFAULT_RISK_JUDGE,
  DEFAULT_TERMINAL_SCROLLBACK,
  MAX_BATCH_CONCURRENCY,
  MAX_SESSIONS_CEILING,
  type ConsoleTabId,
  type JumpServerConfig,
  type PermissionMode,
} from './types.js'
import { DEFAULT_JUMPERSERVER_PORT, ENV_KEYS, type EnvConnection } from './env.js'

/**
 * MCP-local config extension:
 *  - auditPath   JSONL audit sink (default <project>/data/audit.jsonl)
 *  - requireArm  when true, tools stay LOCKED until jumpserver_arm is called
 *                (default false — the WorkBuddy per-tool approval dialog is
 *                the outer gate, same role as the DSH /jumpserver command).
 *  - auditViewer embedded real-time audit page (default: on, stable address
 *                http://127.0.0.1:8765/, handed to the model for opening in
 *                the WorkBuddy preview panel).
 */
export interface AuditViewerConfig {
  enabled: boolean
  port: number
  autoOpen: boolean
  /** EADDRINUSE => ephemeral port so each conversation keeps its own console (default true). */
  portFallback: boolean
  /**
   * V0.5.1: serve one stable token-free address per workspace
   * (`http://127.0.0.1:port/`, token injected into the page) instead of a
   * per-process `?token=` URL on a possibly-ephemeral port (default true).
   */
  stableUrl: boolean
  /** V0.4.2: console access-token lifetime in minutes (default 720; 0 = never expires). */
  tokenTtlMinutes: number
  /**
   * V0.5.9: per-tab visibility of the console navigation (all tabs on by
   * default). Only the keys the operator actually wrote are kept here; defaults
   * and the always-on rule for `settings` are applied by `resolveConsoleTabs()`
   * in src/runtime/console-tabs.ts, which is the single judge of what is
   * visible. This is a UI visibility switch, NOT a permission switch — see
   * that module's header.
   */
  tabs?: Partial<Record<ConsoleTabId, boolean>>
  /**
   * V0.5.11: whether the local console may create / edit / delete bastion
   * account credentials (the multi-account store). The console listens on
   * 127.0.0.1 only and every request must carry the access token, but an
   * enterprise deployment may still want the write entry point switched off.
   * When false the 设置 tab renders the account list READ-ONLY and every write
   * route refuses. Default true.
   */
  allowCredentialWrite?: boolean
}

export type McpConfig = JumpServerConfig & {
  auditPath?: string
  requireArm: boolean
  auditViewer: AuditViewerConfig
}

/**
 * V0.5.0/V0.5.2: the operator-facing text for an incomplete connection.
 *
 * Written for whoever is staring at a connector that will not run, not for
 * someone reading the source: it names both supported places to fix the
 * problem and lists the exact environment keys the process reads.
 *
 * V0.5.2 exports it separately so the SAME wording is used by the boot-time
 * throw AND by the per-tool `CONFIG_INCOMPLETE` answer — a user who sees the
 * message inside a tool call must get exactly the instructions a user who
 * sees it in the startup log gets.
 */
export function configIncompleteMessage(missing: readonly string[]): string {
  const wants = ENV_KEYS
  return (
    'jumpserver-mcp: no JumpServer ' + missing.join(' / ') + ' configured.\n' +
    'Provide it in either place — ENV wins over config.json:\n' +
    '  1. WorkBuddy → 连接器 → JumpServer: fill 地址 / 端口 / 用户名 / 密码\n' +
    '  2. config.json: copy config.example.json and set "' + missing.join('", "') + '"\n' +
    'Environment keys read at startup: ' +
    [wants.host, wants.port, wants.username, wants.password].join(', ')
  )
}

/**
 * V0.5.0: raised when neither the connector form nor config.json supplies a
 * required connection value.
 *
 * V0.5.2: this is now the STRICT path, used by `parseConfig` (and its tests).
 * The runtime boots through `parseConfigLenient` instead, so a missing
 * connection can no longer kill the MCP process before the handshake.
 */
export class ConfigIncompleteError extends Error {
  readonly missing: readonly string[]

  constructor(missing: readonly string[]) {
    super(configIncompleteMessage(missing))
    this.name = 'ConfigIncompleteError'
    this.missing = missing
  }
}

const permissionModes = ['READ_ONLY', 'AUTO', 'FULL_ACCESS'] as const

/**
 * V0.5.0: `host` and `username` are OPTIONAL and carry no length constraint.
 *
 * They used to be required, which made config.json mandatory — a new user had
 * to find and hand-edit a JSON file before the connector would start. Both
 * values can now arrive from the WorkBuddy connector form (via environment
 * variables), so the schema accepts either source and `parseConfig` rejects
 * the result only when the MERGED view is still incomplete.
 *
 * An empty string is deliberately NOT a schema error: it means "not set",
 * exactly as it does in the environment layer, so the operator receives the
 * same actionable message ("fill the connector form or config.json") instead
 * of a raw zod complaint about a single field.
 */
const configSchema = z.object({
  enabled: z.boolean().optional(),
  host: z.string().optional(),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  passwordEnv: z.string().optional(),
  hostFingerprint: z.string().optional(),
  knownHostsPath: z.string().optional(),
  connectTimeout: z.number().optional(),
  commandTimeout: z.number().optional(),
  idleTimeout: z.number().optional(),
  permissionMode: z.enum(permissionModes).optional(),
  privilegedReadInReadOnly: z.boolean().optional(),
  timeZone: z.string().optional(),
  allowedTargets: z.array(z.string()).optional(),
  deniedTargets: z.array(z.string()).optional(),
  batchConcurrency: z.number().int().min(1).max(MAX_BATCH_CONCURRENCY).optional(),
  maxSessions: z.number().int().min(1).max(MAX_SESSIONS_CEILING).optional(),
  assetCacheTtlSeconds: z.number().optional(),
  assetGroups: z.record(z.object({ keywords: z.array(z.string()) })).optional(),
  runbooks: z
    .record(
      z.object({
        title: z.string().optional(),
        description: z.string().optional(),
        steps: z
          .array(
            z.object({
              id: z.string().min(1),
              title: z.string().optional(),
              profile: z.string().optional(),
              command: z.string().optional(),
              timeout: z.number().optional(),
              // V0.4.2: assertions evaluated against the step output.
              // V0.4.3: `probe` narrows a profile-step assertion to one probe.
              expect: z
                .object({
                  probe: z.string().optional(),
                  contains: z.string().optional(),
                  notContains: z.string().optional(),
                  matches: z.string().optional(),
                  exitCode: z.number().int().optional(),
                  notEmpty: z.boolean().optional(),
                  minLines: z.number().int().min(0).optional(),
                  message: z.string().optional(),
                })
                .optional(),
            }),
          )
          .min(1),
      }),
    )
    .optional(),
  autoReconnect: z.boolean().optional(),
  enableAudit: z.boolean().optional(),
  auditPath: z.string().optional(),
  auditViewer: z
    .object({
      enabled: z.boolean().optional(),
      port: z.number().int().min(1).max(65535).optional(),
      autoOpen: z.boolean().optional(),
      portFallback: z.boolean().optional(),
      stableUrl: z.boolean().optional(),
      // V0.4.2: console access-token lifetime in minutes (0 = never expires).
      tokenTtlMinutes: z.number().int().min(0).max(10080).optional(),
      /**
       * V0.5.9: per-tab visibility of the console navigation. Each key is
       * optional; an omitted key means "visible". Zod only enforces the TYPES
       * here — whether a tab may actually be hidden (settings may not) is the
       * business rule of resolveConsoleTabs(), deliberately kept out of the
       * schema so config parsing and UI rendering can never disagree.
       */
      tabs: z
        .object({
          terminal: z.boolean().optional(),
          assets: z.boolean().optional(),
          topology: z.boolean().optional(),
          jobs: z.boolean().optional(),
          audit: z.boolean().optional(),
          stats: z.boolean().optional(),
          sessions: z.boolean().optional(),
          settings: z.boolean().optional(),
        })
        .optional(),
      /**
       * V0.5.11: allow the console to write account credentials (default true).
       * See AuditViewerConfig.allowCredentialWrite.
       */
      allowCredentialWrite: z.boolean().optional(),
    })
    .optional(),
  requireArm: z.boolean().optional(),
  terminalScrollback: z.number().int().min(100).optional(),
  /**
   * V0.5.7: optional semantic second opinion for UNKNOWN commands (Jev /
   * TypeSafe AI). ADVISORY ONLY — see src/security/risk-judge.ts. Disabled by
   * default: a fresh config never sends a command to a third party.
   */
  riskJudge: z
    .object({
      enabled: z.boolean().optional(),
      endpoint: z.string().optional(),
      apiKeyEnv: z.string().optional(),
      apiKeyFile: z.string().optional(),
      model: z.string().optional(),
      timeoutMs: z.number().int().min(100).max(10000).optional(),
      cacheTtlSeconds: z.number().int().min(0).max(86400).optional(),
      redactNetwork: z.boolean().optional(),
      // V0.5.8: the narrow, fail-closed path by which a confident "read-only"
      // verdict may skip the human round-trip on an otherwise unclassified
      // command. Only UNKNOWN commands that the gate already sent to approval
      // are eligible; MODIFY / DANGEROUS / READ never are.
      autoAllow: z
        .object({
          enabled: z.boolean().optional(),
          minReadOnly: z.number().min(0).max(1).optional(),
          minConfidence: z.number().min(0).max(1).optional(),
          maxRiskScore: z.number().min(0).max(4).optional(),
          minSafeProbability: z.number().min(0).max(1).optional(),
          maxNeedsPrivilege: z.number().min(0).max(1).optional(),
        })
        .optional(),
    })
    .optional(),
})

/**
 * V0.5.9: normalize `auditViewer.tabs` into a plain partial map.
 *
 * Rule (deliberate, and the only place it lives): keep a key ONLY when the
 * caller explicitly wrote it, iterate in CONSOLE_TAB_IDS order so the object is
 * deterministic, and store nothing else. No defaults are injected and no
 * "settings cannot be hidden" check happens here — an empty object simply means
 * "operator configured nothing", and resolveConsoleTabs() turns that into the
 * full tab list. Keeping the schema layer free of that business rule means the
 * config object stays a faithful echo of the file, and there is exactly one
 * implementation of the visibility semantics.
 */
function normalizeConsoleTabs(
  raw: Partial<Record<ConsoleTabId, boolean>> | undefined,
): Partial<Record<ConsoleTabId, boolean>> {
  const out: Partial<Record<ConsoleTabId, boolean>> = {}
  if (!raw) return out
  for (const id of CONSOLE_TAB_IDS) {
    const value = raw[id]
    if (value !== undefined) out[id] = value
  }
  return out
}

/**
 * Validate raw JSON, overlay the connector-supplied environment values, and
 * fill every default so the core receives a full JumpServerConfig.
 *
 * `input` may be an EMPTY object — config.json is optional. `host` /
 * `username` may end up EMPTY; that is not a parse error, it is an incomplete
 * CONNECTION and `configProblems()` reports it. Callers decide how to react:
 * `parseConfig` throws, `parseConfigLenient` hands the problems back.
 *
 * Note: the environment password is deliberately NOT copied into
 * `cfg.password`. Credentials injected by the connector stay out of the config
 * object so that any log line, console payload or serialization of the config
 * cannot accidentally carry a live secret; `resolvePassword()` reads the
 * environment directly, per connect.
 */
function buildConfig(input: unknown, env: EnvConnection): McpConfig {
  const raw = configSchema.parse(input)

  const host = env.host ?? raw.host
  const username = env.username ?? raw.username

  const cfg: McpConfig = {
    enabled: raw.enabled ?? true,
    terminalScrollback: raw.terminalScrollback ?? DEFAULT_TERMINAL_SCROLLBACK,
    host: host ?? '',
    port: env.port ?? raw.port ?? DEFAULT_JUMPERSERVER_PORT,
    username: username ?? '',
    password: raw.password,
    passwordEnv: raw.passwordEnv ?? DEFAULT_PASSWORD_ENV,
    hostFingerprint: raw.hostFingerprint,
    knownHostsPath: raw.knownHostsPath,
    connectTimeout: raw.connectTimeout ?? 15,
    commandTimeout: raw.commandTimeout ?? 60,
    idleTimeout: raw.idleTimeout ?? 30,
    permissionMode: (raw.permissionMode ?? 'READ_ONLY') as PermissionMode,
    privilegedReadInReadOnly: raw.privilegedReadInReadOnly,
    timeZone: raw.timeZone,
    allowedTargets: raw.allowedTargets,
    deniedTargets: raw.deniedTargets,
    batchConcurrency: raw.batchConcurrency ?? DEFAULT_BATCH_CONCURRENCY,
    maxSessions: raw.maxSessions ?? DEFAULT_MAX_SESSIONS,
    assetCacheTtlSeconds: raw.assetCacheTtlSeconds ?? DEFAULT_ASSET_CACHE_TTL_SECONDS,
    assetGroups: raw.assetGroups,
    runbooks: raw.runbooks,
    autoReconnect: raw.autoReconnect ?? true,
    enableAudit: raw.enableAudit ?? true,
    requireArm: raw.requireArm ?? false,
    auditViewer: {
      enabled: raw.auditViewer?.enabled ?? true,
      port: raw.auditViewer?.port ?? 8765,
      autoOpen: raw.auditViewer?.autoOpen ?? true,
      portFallback: raw.auditViewer?.portFallback ?? true,
      // V0.5.1: stable address disables the ephemeral fallback (a random port
      // is exactly what made handover URLs go stale), so it is the effective
      // switch for "one fixed console per workspace".
      stableUrl: raw.auditViewer?.stableUrl ?? true,
      tokenTtlMinutes: raw.auditViewer?.tokenTtlMinutes ?? 720,
      // V0.5.9: per-tab visibility, kept exactly as written (possibly empty).
      tabs: normalizeConsoleTabs(raw.auditViewer?.tabs),
      // V0.5.11: the console may manage account credentials unless the operator
      // switches the entry point off (a default-true opt-out).
      allowCredentialWrite: raw.auditViewer?.allowCredentialWrite ?? true,
    },
    // V0.5.7: advisory-only semantic judge for UNKNOWN commands. The API key
    // itself is read from the environment per call (like the SSH password), so
    // it never enters the config object or any serialization of it.
    riskJudge: {
      enabled: raw.riskJudge?.enabled ?? DEFAULT_RISK_JUDGE.enabled,
      endpoint: raw.riskJudge?.endpoint ?? DEFAULT_RISK_JUDGE.endpoint,
      apiKeyEnv: raw.riskJudge?.apiKeyEnv ?? DEFAULT_RISK_JUDGE.apiKeyEnv,
      apiKeyFile: raw.riskJudge?.apiKeyFile ?? DEFAULT_RISK_JUDGE.apiKeyFile,
      model: raw.riskJudge?.model ?? DEFAULT_RISK_JUDGE.model,
      timeoutMs: raw.riskJudge?.timeoutMs ?? DEFAULT_RISK_JUDGE.timeoutMs,
      cacheTtlSeconds: raw.riskJudge?.cacheTtlSeconds ?? DEFAULT_RISK_JUDGE.cacheTtlSeconds,
      redactNetwork: raw.riskJudge?.redactNetwork ?? DEFAULT_RISK_JUDGE.redactNetwork,
      autoAllow: {
        enabled: raw.riskJudge?.autoAllow?.enabled ?? DEFAULT_RISK_JUDGE.autoAllow.enabled,
        minReadOnly: raw.riskJudge?.autoAllow?.minReadOnly ?? DEFAULT_RISK_JUDGE.autoAllow.minReadOnly,
        minConfidence: raw.riskJudge?.autoAllow?.minConfidence ?? DEFAULT_RISK_JUDGE.autoAllow.minConfidence,
        maxRiskScore: raw.riskJudge?.autoAllow?.maxRiskScore ?? DEFAULT_RISK_JUDGE.autoAllow.maxRiskScore,
        minSafeProbability:
          raw.riskJudge?.autoAllow?.minSafeProbability ?? DEFAULT_RISK_JUDGE.autoAllow.minSafeProbability,
        maxNeedsPrivilege: raw.riskJudge?.autoAllow?.maxNeedsPrivilege ?? DEFAULT_RISK_JUDGE.autoAllow.maxNeedsPrivilege,
      },
    },
  }
  if (raw.auditPath !== undefined && raw.auditPath.length > 0) cfg.auditPath = raw.auditPath
  return cfg
}

/**
 * V0.5.2: which required connection values are still missing. An EMPTY array
 * means the connection is usable.
 *
 * This is the single definition of "the connection is complete", so the
 * startup log, the console's 设置 tab, the boot-time strict check and the
 * per-tool `CONFIG_INCOMPLETE` answer can never disagree about it.
 */
export function configProblems(cfg: McpConfig): string[] {
  const missing: string[] = []
  if (cfg.host.length === 0) missing.push('host')
  if (cfg.username.length === 0) missing.push('username')
  return missing
}

/**
 * V0.5.2: the RUNTIME entry point. Never throws because the connection is
 * incomplete — the process must stay alive long enough to complete the MCP
 * handshake, otherwise the host reports "the server failed to start" and the
 * user is told nothing about the missing form fields.
 *
 * Malformed config (bad JSON type, out-of-range port, schema violation) still
 * throws: a missing value is recoverable at runtime, a broken file is not.
 */
export function parseConfigLenient(input: unknown, env: EnvConnection = {}): { cfg: McpConfig; problems: string[] } {
  const cfg = buildConfig(input, env)
  return { cfg, problems: configProblems(cfg) }
}

/**
 * The STRICT entry point: identical result, but an incomplete connection is a
 * hard error. Kept for callers (and tests) that want the refusal up front.
 */
export function parseConfig(input: unknown, env: EnvConnection = {}): McpConfig {
  const cfg = buildConfig(input, env)
  const missing = configProblems(cfg)
  if (missing.length > 0) throw new ConfigIncompleteError(missing)
  return cfg
}
