import { z } from 'zod'
import {
  DEFAULT_ASSET_CACHE_TTL_SECONDS,
  DEFAULT_BATCH_CONCURRENCY,
  DEFAULT_MAX_SESSIONS,
  DEFAULT_PASSWORD_ENV,
  DEFAULT_TERMINAL_SCROLLBACK,
  MAX_BATCH_CONCURRENCY,
  MAX_SESSIONS_CEILING,
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
}

export type McpConfig = JumpServerConfig & {
  auditPath?: string
  requireArm: boolean
  auditViewer: AuditViewerConfig
}

/**
 * V0.5.0: raised when neither the connector form nor config.json supplies a
 * required connection value.
 *
 * The message is written for whoever is staring at a failed MCP server, not
 * for someone reading the source: it names both supported places to fix the
 * problem and lists the exact environment keys the process reads.
 */
export class ConfigIncompleteError extends Error {
  readonly missing: readonly string[]

  constructor(missing: readonly string[]) {
    const wants = ENV_KEYS
    super(
      'jumpserver-mcp: no JumpServer ' + missing.join(' / ') + ' configured.\n' +
        'Provide it in either place — ENV wins over config.json:\n' +
        '  1. WorkBuddy → 连接器 → JumpServer: fill 地址 / 端口 / 用户名 / 密码\n' +
        '  2. config.json: copy config.example.json and set "' + missing.join('", "') + '"\n' +
        'Environment keys read at startup: ' +
        [wants.host, wants.port, wants.username, wants.password].join(', '),
    )
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
    })
    .optional(),
  requireArm: z.boolean().optional(),
  terminalScrollback: z.number().int().min(100).optional(),
})

/**
 * Validate raw JSON, overlay the connector-supplied environment values, and
 * fill every default so the core receives a full JumpServerConfig.
 *
 * `input` may be an EMPTY object — config.json is now optional. The merged
 * result is checked for the connection minimum (host + username); everything
 * else falls back to a default.
 *
 * Note: the environment password is deliberately NOT copied into
 * `cfg.password`. Credentials injected by the connector stay out of the config
 * object so that any log line, console payload or serialization of the config
 * cannot accidentally carry a live secret; `resolvePassword()` reads the
 * environment directly, per connect.
 */
export function parseConfig(input: unknown, env: EnvConnection = {}): McpConfig {
  const raw = configSchema.parse(input)

  const host = env.host ?? raw.host
  const username = env.username ?? raw.username

  const missing: string[] = []
  if (host === undefined || host.length === 0) missing.push('host')
  if (username === undefined || username.length === 0) missing.push('username')
  if (missing.length > 0) throw new ConfigIncompleteError(missing)

  const cfg: McpConfig = {
    enabled: raw.enabled ?? true,
    terminalScrollback: raw.terminalScrollback ?? DEFAULT_TERMINAL_SCROLLBACK,
    host: host as string,
    port: env.port ?? raw.port ?? DEFAULT_JUMPERSERVER_PORT,
    username: username as string,
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
    },
  }
  if (raw.auditPath !== undefined && raw.auditPath.length > 0) cfg.auditPath = raw.auditPath
  return cfg
}
