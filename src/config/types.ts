/** Runtime configuration of the JumpServer connector (V0.1). */
export type PermissionMode = 'READ_ONLY' | 'AUTO' | 'FULL_ACCESS'

export const PERMISSION_MODES: readonly PermissionMode[] = ['READ_ONLY', 'AUTO', 'FULL_ACCESS'] as const

/**
 * V0.3.1 risk classes (single fact source for gating + audit):
 *   READ             - confirmed read-only (semantic rule matched)
 *   PRIVILEGED_READ  - confirmed read-only, needs root/sudo (sudo cat /etc/shadow)
 *   UNKNOWN          - the classifier has NO semantic rule for this command; it is
 *                      NOT claimed to modify anything
 *   MODIFY           - confirmed state change (mutating verb / write redirect)
 *   DANGEROUS        - host-destructive / irreversible (rm -rf /, mkfs, reboot...)
 */
export type CommandRisk = 'READ' | 'PRIVILEGED_READ' | 'UNKNOWN' | 'MODIFY' | 'DANGEROUS'

/** Every risk value in matrix order (README + classifier snapshot report). */
export const COMMAND_RISKS: readonly CommandRisk[] = ['READ', 'PRIVILEGED_READ', 'UNKNOWN', 'MODIFY', 'DANGEROUS'] as const

/** Legacy alias (V0.2.x LOW == privileged read). Kept for config compat. */
export const LEGACY_RISK_LOW = 'LOW' as const

/**
 * V0.2.7: how the HUAMN sidebar terminal input is gated (Agent commands keep
 * using permissionMode). FOLLOW_AGENT applies the same READ_ONLY/AUTO/FULL
 * matrix to manual input; CONFIRM_MODIFY (default) lets reads pass and asks
 * the user to confirm modifying commands; FULL_ACCESS is the old behavior.
 */
export type ManualPolicy = 'FOLLOW_AGENT' | 'CONFIRM_MODIFY' | 'FULL_ACCESS'

export interface JumpServerConfig {
  /** Master switch: when false every jumpserver_* tool refuses with DISABLED (default true) */
  enabled: boolean
  /** Open the browser JumpServer Terminal drawer automatically on session page? (default true) */
  autoOpenTerminal: boolean
  /** Terminal scrollback line budget (default 5000) */
  terminalScrollback: number
  /** Bastion gateway host (transport host), e.g. 203.0.113.10 */
  host: string
  /** Bastion SSH port, default 2222 */
  port: number
  /** Bastion login username */
  username: string
  /** Literal password; prefer passwordEnv reference. Never returned to the model. */
  password?: string
  /** Credential-ref (env var name) for the password, resolved per connect. */
  passwordEnv: string
  /** Connect timeout in seconds (default 15) */
  connectTimeout: number
  /** Per-command default timeout in seconds (default 60) */
  commandTimeout: number
  /** Idle close timeout in minutes (default 30) */
  idleTimeout: number
  /** Command permission mode (default READ_ONLY) */
  permissionMode: PermissionMode
  /**
   * V0.3.1: whether PRIVILEGED_READ (sudo ... reads) may auto-run in READ_ONLY
   * mode (default false — READ_ONLY only auto-runs plain READ).
   */
  privilegedReadInReadOnly?: boolean
  /** V0.2.7: manual sidebar terminal input policy (default CONFIRM_MODIFY). */
  manualPermissionMode?: ManualPolicy
  /** How long one capture of the KoKo 'p' asset list is cached per conversation (seconds; default 300). */
  assetCacheTtlSeconds?: number
  /**
   * V0.2.6: system asset groups / aliases — group name -> keywords. The tool
   * jumpserver_assets(group="OA") OR-matches every keyword across
   * name/ip/platform/node/comment, so a server named portal-nginx counts as an
   * "OA" server without the model guessing raw substrings.
   */
  assetGroups?: Record<string, AssetGroupDef>
  /** Auto reconnect at most 2 times with 1s/3s backoff when idle (default true) */
  autoReconnect: boolean
  /** Persist command audit records (default true) */
  enableAudit: boolean
}

/** V0.2.6: one asset group definition (keyword list). */
export interface AssetGroupDef {
  keywords: string[]
}

/** Default terminal scrollback (rows). */
export const DEFAULT_TERMINAL_SCROLLBACK = 5000

/** Default asset-list cache TTL (seconds). One 'p' feeds 5 minutes of local filtering. */
export const DEFAULT_ASSET_CACHE_TTL_SECONDS = 300

/** Hard cap on the terminal observer's raw output byte budget (ring buffer). */
export const MAX_TERMINAL_BYTES = 4 * 1024 * 1024

/** Default timeout maps (ms). enterAsset is generous: KoKo dials the asset with a progress banner. */
export const DEFAULT_TIMEOUTS = {
  connect: 15000,
  enterAsset: 40000,
  probe: 15000,
  command: 60000,
  leave: 15000,
  listAssets: 15000,
} as const

/** Hard cap on one command's captured output (1 MiB). */
export const MAX_OUTPUT_BYTES = 1024 * 1024

/** Max per-command timeout allowed (10 min). */
export const MAX_COMMAND_TIMEOUT_MS = 600000

/** Bounded capture window for the KoKo 'p' asset-list screen (bytes). */
export const MAX_ASSET_CAPTURE_BYTES = 256 * 1024

export const DEFAULT_PASSWORD_ENV = 'JUMPSERVER_PASSWORD'

/** Resolve the manual terminal policy with its default (CONFIRM_MODIFY). */
export function manualPolicyOf(cfg: Pick<JumpServerConfig, 'manualPermissionMode'>): ManualPolicy {
  return cfg.manualPermissionMode ?? 'CONFIRM_MODIFY'
}
