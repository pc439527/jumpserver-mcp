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

/**
 * MCP-local config extension:
 *  - auditPath   JSONL audit sink (default <project>/data/audit.jsonl)
 *  - requireArm  when true, tools stay LOCKED until jumpserver_arm is called
 *                (default false — the WorkBuddy per-tool approval dialog is
 *                the outer gate, same role as the DSH /jumpserver command).
 *  - auditViewer embedded real-time audit page (default: on, port 8765,
 *                auto-open browser on the FIRST audited command).
 */
export interface AuditViewerConfig {
  enabled: boolean
  port: number
  autoOpen: boolean
  /** EADDRINUSE => ephemeral port so each conversation keeps its own console (default true). */
  portFallback: boolean
  /** V0.4.2: console access-token lifetime in minutes (default 720; 0 = never expires). */
  tokenTtlMinutes: number
}

export type McpConfig = JumpServerConfig & {
  auditPath?: string
  requireArm: boolean
  auditViewer: AuditViewerConfig
}

const permissionModes = ['READ_ONLY', 'AUTO', 'FULL_ACCESS'] as const

const configSchema = z.object({
  enabled: z.boolean().optional(),
  host: z.string().min(1, 'host is required, e.g. 203.0.113.10'),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1, 'username is required'),
  password: z.string().optional(),
  passwordEnv: z.string().optional(),
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
              expect: z
                .object({
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
      // V0.4.2: console access-token lifetime in minutes (0 = never expires).
      tokenTtlMinutes: z.number().int().min(0).max(10080).optional(),
    })
    .optional(),
  requireArm: z.boolean().optional(),
  terminalScrollback: z.number().int().min(100).optional(),
})

/** Validate raw JSON and fill every default so the core receives a full JumpServerConfig. */
export function parseConfig(input: unknown): McpConfig {
  const raw = configSchema.parse(input)
  const cfg: McpConfig = {
    enabled: raw.enabled ?? true,
    terminalScrollback: raw.terminalScrollback ?? DEFAULT_TERMINAL_SCROLLBACK,
    host: raw.host,
    port: raw.port ?? 2222,
    username: raw.username,
    password: raw.password,
    passwordEnv: raw.passwordEnv ?? DEFAULT_PASSWORD_ENV,
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
      tokenTtlMinutes: raw.auditViewer?.tokenTtlMinutes ?? 720,
    },
  }
  if (raw.auditPath !== undefined && raw.auditPath.length > 0) cfg.auditPath = raw.auditPath
  return cfg
}
