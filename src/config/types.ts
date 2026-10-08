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
  /**
   * V0.5.0: pinned SSH host-key fingerprint, e.g. "SHA256:AbCdEf…".
   * When set, only a byte-identical host key is accepted and any other key is
   * refused as HOST_KEY_MISMATCH. When absent, the first contact is trusted
   * and recorded in `knownHostsPath` (TOFU), and every later contact must
   * match that record.
   */
  hostFingerprint?: string
  /**
   * V0.5.0: known_hosts store used by TOFU (default
   * <project>/data/known_hosts.json). Ignored when hostFingerprint is set —
   * a match is still recorded there for visibility.
   */
  knownHostsPath?: string
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
  /**
   * V0.5.7: optional semantic second opinion for UNKNOWN commands (Jev /
   * TypeSafe AI). ADVISORY ONLY — it never changes a gate decision. See
   * src/security/risk-judge.ts for the full safety contract.
   */
  riskJudge?: RiskJudgeConfig
}

/**
 * V0.5.7 risk judge settings.
 *
 * The judge is consulted ONLY for commands the deterministic classifier
 * returns UNKNOWN for, and its verdict is rendered into the approval copy.
 * It cannot allow, deny or downgrade anything: with `enabled:false` (the
 * default) the connector behaves exactly as before.
 */
export interface RiskJudgeConfig {
  /** Master switch (default false — no outbound request is ever made). */
  enabled: boolean
  /** System One endpoint (default https://api.typesafe.ai/v1/systemone). */
  endpoint: string
  /** Credential-ref (env var name) holding the API key (default TYPESAFE_API_KEY). */
  apiKeyEnv: string
  /**
   * Optional file holding the API key (default ''). Consulted only when the
   * env var above is empty, mirroring ~/.workbuddy/typesafe/ts.py. Storing the
   * PATH here keeps the secret itself out of config.json.
   */
  apiKeyFile: string
  /** Model alias (default jev-latest). */
  model: string
  /**
   * Per-call timeout in ms (default 1500). The gate is on the critical path:
   * a slow judge must degrade to null, never delay an approval prompt.
   */
  timeoutMs: number
  /** Verdict cache TTL per redacted command, seconds (default 3600). */
  cacheTtlSeconds: number
  /**
   * Mask IPs / FQDNs / home-directory account names before the command leaves
   * the process (default true). System paths (/etc, /var/log) are preserved —
   * they carry the semantics the judgement needs, credentials never are.
   */
  redactNetwork: boolean
  /**
   * V0.5.8: the ONE place a judge verdict may change a gate outcome.
   *
   * The advisory judge (above) only decorates an approval prompt. Turning this
   * on lets a confident "this command only reads" verdict skip the human
   * round-trip on a command the rule classifier could not rule on — the main
   * source of friction during multi-host collection, where every unclassified
   * probe costs a confirm cycle per host.
   *
   * It is deliberately narrow and fail-closed: it applies only where the
   * deterministic gate already said "ask a human" (never where it said
   * "blocked"), only to `UNKNOWN` classifications, only when every threshold
   * below is met, and never to a composed command. `MODIFY`, `DANGEROUS`,
   * `READ` and `PRIVILEGED_READ` are still decided by the classifier alone and
   * are never sent anywhere.
   */
  autoAllow: RiskJudgeAutoAllowConfig
}

/**
 * V0.5.8 auto-allow thresholds. Every value is a veto: the verdict must pass
 * ALL of them. Defaults are the conservative end of the measured distribution
 * (see README) — raise nothing without reading the actual verdicts first.
 */
export interface RiskJudgeAutoAllowConfig {
  /** Master switch (default false). Off = advisory-only, exactly as V0.5.7. */
  enabled: boolean
  /** Minimum P(command only reads) — the noul answer (default 0.9). */
  minReadOnly: number
  /** Minimum of the confidences the model reported for its answers (default 0.7). */
  minConfidence: number
  /**
   * Highest accepted expected rubric position on the 0..4 scale the API returns
   * (0 = 随时可执行 … 4 = 禁止自动执行). Default 1.0 keeps auto-allow inside the
   * two safest rubric bands.
   */
  maxRiskScore: number
  /**
   * Minimum probability mass the rubric distribution puts on its two safest
   * bands (P(0)+P(1)), default 0.85. A verdict whose distribution is missing or
   * spread out is refused — the expected value alone can hide a fat tail.
   */
  minSafeProbability: number
  /** Maximum P(the command needs root/sudo), default 0.3. */
  maxNeedsPrivilege: number
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
  /**
   * V0.4.3: narrow the assertion to ONE probe of a profile step.
   *
   * A profile step expands to N probes whose outputs are unrelated to each
   * other (`ss -lntp` vs `cat /etc/hosts`). Asserting "contains LISTEN"
   * against every probe independently is wrong: it reports FAIL on a healthy
   * host. `probe` names the single probe id the assertion targets, e.g.
   * `expect: { probe: "listen", contains: "LISTEN" }`.
   *
   * When omitted on a profile step, the assertion is evaluated ONCE against
   * the aggregated output of all probes (see RunbookStepResult.aggregated).
   * On a command step this field is meaningless and ignored.
   */
  probe?: string
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

/**
 * V0.5.9: the stable identifiers of the embedded console's navigation tabs.
 *
 * These ids are shared verbatim by the nav buttons (`data-tab`), the tab
 * sections (`id="tab-<name>"`) and the hash router, so they must not be
 * renamed without touching the viewer's markup.
 */
export type ConsoleTabId = 'terminal' | 'assets' | 'topology' | 'jobs' | 'audit' | 'stats' | 'sessions' | 'settings'

/**
 * Every console tab id, in navigation order.
 *
 * The order IS the rendered order: `resolveConsoleTabs()` walks this array, so
 * the viewer never has to sort and a filtered tab list keeps its place.
 */
export const CONSOLE_TAB_IDS: readonly ConsoleTabId[] = [
  'terminal',
  'assets',
  'topology',
  'jobs',
  'audit',
  'stats',
  'sessions',
  'settings',
] as const

/** Default visibility of every console tab: all on. */
export const DEFAULT_CONSOLE_TABS: Record<ConsoleTabId, boolean> = {
  terminal: true,
  assets: true,
  topology: true,
  jobs: true,
  audit: true,
  stats: true,
  sessions: true,
  settings: true,
}

/**
 * Tabs that can never be hidden.
 *
 * `settings` is the console's only explanation and diagnostics entry point —
 * and the page that documents this very switch. Hiding it would strand an
 * operator with a console that has lost tabs and no way to find out why, so
 * the rule is enforced inside `resolveConsoleTabs()` rather than delegated to
 * each caller.
 */
export const ALWAYS_ON_CONSOLE_TABS: readonly ConsoleTabId[] = ['settings'] as const

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

/** V0.5.7: default credential-ref for the optional risk judge (Jev / TypeSafe AI). */
export const DEFAULT_RISK_JUDGE_API_KEY_ENV = 'TYPESAFE_API_KEY'

/** V0.5.7: default System One endpoint. */
export const DEFAULT_RISK_JUDGE_ENDPOINT = 'https://api.typesafe.ai/v1/systemone'

/** V0.5.7: fallback key file — the same one ~/.workbuddy/typesafe/ts.py reads. */
export const DEFAULT_RISK_JUDGE_API_KEY_FILE = '~/.workbuddy/typesafe/api_key'

/** V0.5.7: default risk-judge settings (disabled — nothing leaves the process). */
export const DEFAULT_RISK_JUDGE: RiskJudgeConfig = {
  enabled: false,
  endpoint: DEFAULT_RISK_JUDGE_ENDPOINT,
  apiKeyEnv: DEFAULT_RISK_JUDGE_API_KEY_ENV,
  apiKeyFile: DEFAULT_RISK_JUDGE_API_KEY_FILE,
  model: 'jev-latest',
  timeoutMs: 1500,
  cacheTtlSeconds: 3600,
  redactNetwork: true,
  // V0.5.8: opt-in, and conservative even then. See RiskJudgeAutoAllowConfig.
  autoAllow: {
    enabled: false,
    minReadOnly: 0.9,
    minConfidence: 0.7,
    maxRiskScore: 1,
    minSafeProbability: 0.85,
    maxNeedsPrivilege: 0.3,
  },
}
