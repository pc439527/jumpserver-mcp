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

export interface JumpServerConfig {
  /** Master switch: when false every jumpserver_* tool refuses with DISABLED (default true) */
  enabled: boolean
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
  /**
   * V0.4.0 display timezone for audit timestamps (IANA name, default
   * Asia/Shanghai). Storage stays UTC — only the console / jumpserver_audit
   * rendering converts. Use "local" to follow the MCP host's own zone.
   */
  timeZone?: string
  /**
   * V0.4.0 scope guard: when set, only these targets may be entered/run
   * (substring match on the requested target). Empty/absent = unrestricted.
   */
  allowedTargets?: string[]
  /** V0.4.0 scope guard: these targets are always refused (checked first). */
  deniedTargets?: string[]
  /**
   * V0.4.1: how many targets of ONE batch/inspect/topology call may be
   * processed concurrently (each target still gets its own serialized
   * session turn). Default 1 (strictly sequential — the safe, auditable
   * baseline). Raise deliberately: more concurrency = more simultaneous
   * bastion sessions, which the bastion may rate-limit or audit differently.
   */
  batchConcurrency?: number
  /**
   * V0.4.1: hard cap on simultaneous JumpServer sessions (the session pool).
   * Default 4. When every slot is busy, further targets wait instead of
   * opening yet another bastion login.
   */
  maxSessions?: number
  /** How long one capture of the KoKo 'p' asset list is cached per conversation (seconds; default 300). */
  assetCacheTtlSeconds?: number
  /**
   * V0.2.6: system asset groups / aliases — group name -> keywords. The tool
   * jumpserver_assets(group="OA") OR-matches every keyword across
   * name/ip/platform/node/comment, so a server named portal-nginx counts as an
   * "OA" server without the model guessing raw substrings.
   */
  assetGroups?: Record<string, AssetGroupDef>
  /**
   * V0.4.1: named runbooks (Profile / Runbook) — a reusable, reviewed survey
   * recipe. jumpserver_profile_run executes one by name against a target set.
   */
  runbooks?: Record<string, RunbookDef>
  /** Auto reconnect at most 2 times with 1s/3s backoff when idle (default true) */
  autoReconnect: boolean
  /** Persist command audit records (default true) */
  enableAudit: boolean
}

/** V0.2.6: one asset group definition (keyword list). */
export interface AssetGroupDef {
  keywords: string[]
}

/**
 * V0.4.2: one assertion attached to a runbook step.
 *
 * Assertions turn a runbook from "collect and eyeball" into "collect and
 * judge": each step's captured output is checked against these rules and the
 * runbook reports PASS / FAIL per target. All rules must hold (AND).
 */
export interface RunbookExpect {
  /** Output must contain this substring (case-insensitive). */
  contains?: string
  /** Output must NOT contain this substring (case-insensitive). */
  notContains?: string
  /** Output must match this regular expression (case-insensitive, no /flags form). */
  matches?: string
  /** Exit code must equal this value (default: only checked when set). */
  exitCode?: number
  /** Output must be non-empty after trimming. */
  notEmpty?: boolean
  /** Output must have at least this many lines. */
  minLines?: number
  /** Human note echoed into the report when this assertion fails. */
  message?: string
}

/**
 * V0.4.1: one named runbook step.
 *
 * A step is EITHER an inspect profile (the connector supplies the reviewed
 * read-only probes) OR an explicit command. Explicit commands are re-classified
 * by the same classifier every other tool uses: a step that is not READ is
 * skipped (reported), never silently executed — so a runbook is safe in
 * READ_ONLY mode by construction.
 */
export interface RunbookStep {
  /** Stable id echoed in the result so a step can be referenced in reports. */
  id: string
  /** Human label (optional). */
  title?: string
  /** Inspect profile to run for this step (mutually exclusive with command). */
  profile?: string
  /** Explicit read-only command (mutually exclusive with profile). */
  command?: string
  /** Per-step timeout in seconds. */
  timeout?: number
  /** V0.4.2: assertions evaluated against this step's output. */
  expect?: RunbookExpect
}

/** V0.4.1: a named runbook = an ordered list of read-only steps. */
export interface RunbookDef {
  title?: string
  description?: string
  steps: RunbookStep[]
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

/** V0.4.1: default concurrency for a multi-target batch (1 = sequential). */
export const DEFAULT_BATCH_CONCURRENCY = 1

/** V0.4.1: default session-pool size (simultaneous bastion sessions). */
export const DEFAULT_MAX_SESSIONS = 4

/** V0.4.1: hard ceiling for batchConcurrency / maxSessions (protects the bastion). */
export const MAX_BATCH_CONCURRENCY = 8
export const MAX_SESSIONS_CEILING = 16

/** Bounded capture window for the KoKo 'p' asset-list screen (bytes). */
export const MAX_ASSET_CAPTURE_BYTES = 256 * 1024

export const DEFAULT_PASSWORD_ENV = 'JUMPSERVER_PASSWORD'
