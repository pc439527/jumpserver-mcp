/**
 * `jumpserver-mcp --doctor` — answer "why is this connector not working?" in
 * ONE command, without starting the MCP server.
 *
 * WHY THIS EXISTS: every failure this project has actually seen was invisible
 * from inside a conversation. A missing connection field killed the process
 * before the handshake (fixed in V0.5.2, but the user still had to know to
 * look). A config.json with a string port threw a raw zod dump into a log
 * nobody reads. A read-only install directory made the audit sink fail
 * silently. In every case the operator's only tool was "read the source".
 *
 * DESIGN RULES
 *  - No side effects that outlive the run: no port BINDING (a connect probe
 *    only), no SSH, no state written except a probe file that is deleted.
 *  - No secrets. The credential line reports WHICH layer supplies a password,
 *    never the value — same contract as the console's 设置 tab.
 *  - Never throws. A diagnostic that explodes on the exact input it is meant to
 *    diagnose (a malformed config) is useless, so every failure is caught and
 *    reported as a failed check.
 *  - Errors are TRANSLATED, not forwarded. `[{code,expected,received,...}]` is
 *    a stack trace wearing a costume; the operator gets `port: Expected number,
 *    received string`.
 *  - Reports to stdout, because this is a human running a CLI, not a host
 *    speaking JSON-RPC. `--doctor` never connects the stdio transport.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createConnection } from 'node:net'
import { dirname, join } from 'node:path'
import { configIncompleteMessage, parseConfigLenient, type McpConfig } from '../config/schema.js'
import {
  ENV_KEYS,
  LIFECYCLE_ENV_KEYS,
  readEnvConnection,
  sourceOf,
  type EnvConnection,
} from '../config/env.js'
import { projectRoot } from './runtime.js'
import { defaultProfileFilePath, ProfileStore, type ProfileView } from './profile-store.js'
import { DEFAULT_RISK_JUDGE } from '../config/types.js'
import { resolveApiKey } from '../security/risk-judge.js'
import { PLUGIN_VERSION } from '../version.js'
// V0.6.1 (B-4): the expected tool surface, checked against the COMPILED build.
import { ALWAYS_TOOL_NAMES } from './tool-names.js'
import { computeReadiness, parseEndpointHostPort } from './readiness.js'

export type DoctorStatus = 'ok' | 'warn' | 'fail'

export interface DoctorCheck {
  name: string
  status: DoctorStatus
  /** What was found. Always safe to print: no credential values. */
  detail: string
  /** What to do about it. Present whenever status is warn or fail. */
  fix?: string
}

export interface DoctorReport {
  checks: DoctorCheck[]
  /** 0 = usable, 1 = at least one check failed. */
  exitCode: number
}

export interface DoctorOptions {
  env?: NodeJS.ProcessEnv
  /** Injected so the port probe can be stubbed in tests. */
  probePort?: (port: number) => Promise<'listening' | 'free'>
  /** Minimum Node major version the connector supports. */
  minNodeMajor?: number
  /**
   * V0.5.12: where the account store lives. Defaults to
   * ~/.workbuddy/jumpserver-mcp/profiles.json. Injected so an in-process test
   * (or a diagnostic run against another profile) does not silently read the
   * accounts saved on this machine — that is how a "no configuration at all"
   * fixture turns into "connection: complete".
   */
  profilesPath?: string
  /**
   * V0.7.1 (D-9): injected reachability probe. A test must never open a
   * socket, so the readiness check takes its probe from here.
   */
  probeReachability?: (host: string, port: number) => Promise<import('./readiness.js').Reachability>
}

/** The default probe: CONNECT to 127.0.0.1:port, never bind it. */
function tcpProbe(port: number, timeoutMs = 800): Promise<'listening' | 'free'> {
  return new Promise((resolve) => {
    const socket = createConnection({ host: '127.0.0.1', port })
    const done = (result: 'listening' | 'free') => {
      socket.removeAllListeners()
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(timeoutMs)
    socket.on('connect', () => done('listening'))
    socket.on('timeout', () => done('free'))
    socket.on('error', () => done('free'))
  })
}

/**
 * Turn a config failure into one readable line per problem.
 *
 * zod's `issues` array carries the useful information (a path and a sentence)
 * wrapped in four fields nobody reads. A shape that is NOT a zod error keeps
 * its plain message, because inventing structure for an unknown error is how
 * diagnostics start lying.
 */
export function formatConfigError(error: unknown): string {
  if (error !== null && typeof error === 'object' && Array.isArray((error as { issues?: unknown }).issues)) {
    const issues = (error as { issues: Array<{ path?: Array<string | number>; message?: unknown }> }).issues
    const lines = issues.map((issue) => {
      const where = (issue.path ?? []).map((part) => String(part)).join('.')
      const message = typeof issue.message === 'string' ? issue.message : 'invalid value'
      return where.length > 0 ? where + ': ' + message : message
    })
    return lines.length > 0 ? lines.join('; ') : 'config did not match the expected shape'
  }
  return error instanceof Error ? error.message : String(error)
}

/**
 * A monotonic counter for probe file names — see `probeWritable`.
 */
let probeCounter = 0

/**
 * The probe file name for one write check.
 *
 * Exported so the uniqueness rule can be tested directly: the name must
 * differ between two checks in the same process AND between two processes
 * (the pid part), because the whole point is that concurrent doctor runs
 * cannot delete each other's probe.
 */
export function nextProbeFileName(dir: string): string {
  return join(dir, '.doctor-probe-' + String(process.pid) + '-' + String(probeCounter++))
}

/**
 * Prove a directory can actually be written to by writing to it. `access(W_OK)`
 * is not enough: it reports the permission bits, not whether the filesystem is
 * read-only, out of space, or a container overlay that discards writes.
 *
 * The probe file name is UNIQUE per process (V0.6.1): a fixed name made two
 * concurrent doctor runs delete each other's probe, and on Windows the
 * surviving `writeFileSync` then failed with EBUSY/ENOENT — the directory was
 * perfectly writable, but the doctor reported it as NOT writable and the run
 * exited 1. A diagnostic that blames the wrong layer is worse than no
 * diagnostic, so the probe must not be able to collide.
 */
function probeWritable(dir: string): { ok: boolean; detail: string } {
  const probe = nextProbeFileName(dir)
  try {
    mkdirSync(dir, { recursive: true })
  } catch (error) {
    return { ok: false, detail: 'cannot create: ' + (error instanceof Error ? error.message : String(error)) }
  }
  try {
    writeFileSync(probe, 'ok', 'utf8')
    return { ok: true, detail: 'writable' }
  } catch (error) {
    return { ok: false, detail: 'not writable: ' + (error instanceof Error ? error.message : String(error)) }
  } finally {
    // Best-effort cleanup: a leftover probe file is litter, but failing to
    // remove it must NOT turn a writable directory into a failed check.
    try {
      rmSync(probe, { force: true })
    } catch {
      /* ignore */
    }
  }
}

function nodeCheck(actualVersion: string, minMajor: number): DoctorCheck {
  const major = Number(actualVersion.split('.')[0])
  if (Number.isFinite(major) && major >= minMajor) {
    return {
      name: 'node runtime',
      status: 'ok',
      detail: 'v' + actualVersion + ' on ' + process.platform + '/' + process.arch,
    }
  }
  return {
    name: 'node runtime',
    status: 'fail',
    detail: 'v' + actualVersion + ' is below the required Node >=' + minMajor,
    fix: 'install Node ' + minMajor + ' or newer and restart the host (WorkBuddy uses the node on PATH)',
  }
}

/** Read + JSON-parse config.json. A schema violation is a separate, later step. */
function readConfigFile(configPath: string): { present: boolean; value: Record<string, unknown>; broken: string | null } {
  if (!existsSync(configPath)) return { present: false, value: {}, broken: null }
  try {
    const parsed: unknown = JSON.parse(readFileSync(configPath, 'utf8'))
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('the root must be a JSON object')
    }
    return { present: true, value: parsed as Record<string, unknown>, broken: null }
  } catch (error) {
    return { present: true, value: {}, broken: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * V0.6.1 (B-4): does the COMPILED build publish the whole tool surface?
 *
 * Reads `lib/server.js` and `lib/runtime/tools-ops.js` and looks for each
 * expected tool name. A name that is missing means the build is stale (the
 * source was edited but `tsc` never ran) — the single most common cause of
 * "the connector is connected but the host sees no tools".
 *
 * Read-only by construction: two file reads, no imports of the server
 * module (which would boot it), no sockets.
 */
export function checkCompiledToolSurface(root: string): { status: DoctorStatus; detail: string; fix?: string } {
  const candidates = [
    join(root, 'lib', 'server.js'),
    join(root, 'lib', 'runtime', 'tools-ops.js'),
  ]
  const present = candidates.filter((p) => existsSync(p))
  if (present.length === 0) {
    return {
      status: 'fail',
      detail: 'no compiled build found at lib/ — the connector has never been built',
      fix: 'run `npm run build` (tsc -p tsconfig.json) in the connector directory',
    }
  }
  let blob = ''
  for (const path of present) {
    try {
      blob += readFileSync(path, 'utf8')
    } catch {
      /* unreadable file — the missing-name report below will show it */
    }
  }
  const missing = ALWAYS_TOOL_NAMES.filter((name) => !blob.includes(name))
  if (missing.length > 0) {
    return {
      status: 'fail',
      detail: 'the compiled build is missing ' + String(missing.length) + ' tool(s): ' + missing.join(', ') +
        ' — lib/ is STALE relative to src/',
      fix: 'run `npm run build` and RESTART the connector process (the tool table is fixed when the process starts — a new conversation is required for the host to see the new table)',
    }
  }
  return {
    status: 'ok',
    detail: 'the compiled build publishes all ' + String(ALWAYS_TOOL_NAMES.length) + ' always-on tools' +
      (present.length < candidates.length ? ' (ops tools file not found)' : ''),
  }
}

/**
 * V0.5.12: the account selected in the ops console 设置 tab, or null.
 * Zero side effects by construction — ProfileStore only READS here (a missing
 * file is simply "no accounts"), and getActive() returns a redacted
 * ProfileView, so no key is loaded and no secret is decrypted. A store the
 * runtime would refuse to write is still perfectly readable, which is exactly
 * what a diagnostic wants. Never throws: a broken profiles file must not turn
 * --doctor into the crash it is meant to explain.
 */
function readActiveAccount(filePath: string): ProfileView | null {
  try {
    return new ProfileStore({ filePath }).getActive()
  } catch {
    return null
  }
}

export async function runDoctor(options: DoctorOptions = {}): Promise<DoctorReport> {
  const env = options.env ?? process.env
  const minNodeMajor = options.minNodeMajor ?? 20
  const probePort = options.probePort ?? tcpProbe
  const checks: DoctorCheck[] = []

  checks.push(nodeCheck(process.versions.node, minNodeMajor))

  const root = projectRoot()
  const configPath = env[LIFECYCLE_ENV_KEYS.configPath] ?? join(root, 'config.json')
  const file = readConfigFile(configPath)

  // ---- connector-injected environment variables -------------------------
  // Each step is attributed to the layer that actually failed: blaming the
  // config file for a bad JUMPSERVER_PORT sends the operator to the wrong place.
  let envConnection: EnvConnection = {}
  let envError: string | null = null
  try {
    envConnection = readEnvConnection(env)
  } catch (error) {
    envError = error instanceof Error ? error.message : String(error)
  }
  if (envError !== null) {
    checks.push({
      name: 'connector env',
      status: 'fail',
      detail: envError,
      fix: 'fix or unset that JUMPSERVER_* variable — the connector form writes these',
    })
  }

  // ---- config file: JSON syntax AND schema ------------------------------
  let config: McpConfig | null = null
  let schemaError: string | null = null
  if (file.broken === null) {
    try {
      config = parseConfigLenient(file.value, envConnection).cfg
    } catch (error) {
      schemaError = formatConfigError(error)
    }
  }

  if (!file.present) {
    checks.push({
      name: 'config file',
      status: 'ok',
      detail: 'none at ' + configPath + ' — the connector form alone can supply the connection',
    })
  } else if (file.broken !== null) {
    checks.push({
      name: 'config file',
      status: 'fail',
      detail: configPath + ' is present but is not valid JSON: ' + file.broken,
      fix: 'fix the syntax, or delete the file and let the connector form supply the connection. A broken config is fatal at startup.',
    })
  } else if (schemaError !== null) {
    checks.push({
      name: 'config file',
      status: 'fail',
      detail: configPath + ' is valid JSON but invalid: ' + schemaError,
      fix: 'compare against config.example.json. A schema violation is fatal at startup, unlike a missing value.',
    })
  } else {
    checks.push({ name: 'config file', status: 'ok', detail: configPath + ' parses and passes validation' })
  }

  // ---- connection + credential + policy ---------------------------------
  if (config === null) {
    checks.push({
      name: 'connection',
      status: 'fail',
      detail: 'not evaluated — the config file must be fixed first',
      fix: 'the connection cannot be resolved until config.json parses and validates',
    })
    checks.push({ name: 'credential', status: 'warn', detail: 'not evaluated' })
    checks.push({ name: 'effective policy', status: 'warn', detail: 'not evaluated' })
  } else {
    // V0.5.12: the ops console's 设置 tab adds a THIRD layer — a saved account
    // — and it outranks both config.json and the injected credential (see
    // Runtime.effectiveConfig / resolvePassword). A doctor that only knew the
    // two config layers reported "NOT found in any layer" on a machine with a
    // perfectly good account selected, sending the operator off to fill a
    // password that was never going to be used; it could equally print a
    // host/username pair the connector was never going to dial. Read-only and
    // secret-free: ProfileView carries `hasSecret`, never the token.
    const account = readActiveAccount(options.profilesPath ?? defaultProfileFilePath())

    const missing: string[] = []
    if (config.host.length === 0) missing.push('host')
    if (config.username.length === 0) missing.push('username')

    if (account !== null) {
      checks.push({
        name: 'connection',
        status: 'ok',
        detail: account.host + ':' + account.port + ' as ' + account.username +
          ' (host and username from the saved account "' + account.label + '" — console 设置 tab)',
      })
    } else if (missing.length === 0) {
      checks.push({
        name: 'connection',
        status: 'ok',
        detail: config.host + ':' + config.port + ' as ' + config.username +
          ' (host from ' + sourceOf(file.value['host'], envConnection.host) +
          ', username from ' + sourceOf(file.value['username'], envConnection.username) + ')',
      })
    } else {
      checks.push({
        name: 'connection',
        status: 'fail',
        detail: 'INCOMPLETE — missing ' + missing.join(' / '),
        fix: configIncompleteMessage(missing),
      })
    }

    const injected = env[ENV_KEYS.password]
    const named = env[config.passwordEnv]
    let credentialDetail: string
    let credentialStatus: DoctorStatus = 'ok'
    if (account !== null && account.hasSecret) {
      credentialDetail = 'present, via the saved account "' + account.label + '" (selected in the console 设置 tab)'
    } else if (injected !== undefined && injected.length > 0) {
      credentialDetail = 'present, injected by the connector form (' + ENV_KEYS.password + ')'
    } else if (named !== undefined && named.length > 0) {
      credentialDetail = 'present, via the environment variable ' + config.passwordEnv
    } else if (config.password !== undefined && config.password.length > 0) {
      credentialDetail = 'present, literal "password" in config.json'
    } else {
      credentialStatus = 'warn'
      credentialDetail = account !== null
        ? 'the selected account "' + account.label + '" has no password saved, and no other layer supplies one'
        : 'NOT found in any layer'
    }
    checks.push({
      name: 'credential',
      status: credentialStatus,
      detail: credentialDetail + ' — the value itself is never read by this command',
      ...(credentialStatus === 'warn'
        ? {
            fix:
              'fill 密码 in WorkBuddy → 连接器 → JumpServer, or set ' + ENV_KEYS.password +
              (config.passwordEnv === ENV_KEYS.password ? '' : ' (or ' + config.passwordEnv + ')'),
          }
        : {}),
    })

    // ---- optional risk judge ---------------------------------------------
    // Configuration only — this command never calls the endpoint. Reports
    // WHICH layer supplies the key, never the value (same rule as `credential`).
    const judge = config.riskJudge ?? DEFAULT_RISK_JUDGE
    // V0.5.8: auto-allow can let an unclassified command run WITHOUT a human
    // prompt. A diagnostic must state that fact plainly — it is the one place
    // the connector can widen what executes without a person watching.
    const autoAllow = judge.autoAllow?.enabled === true
      ? '; auto-allow ON (只读≥' + String(judge.autoAllow.minReadOnly) + ' 置信≥' + String(judge.autoAllow.minConfidence) +
        ' 风险档≤' + String(Math.round(judge.autoAllow.maxRiskScore) + 1) + '/5 安全档≥' + String(judge.autoAllow.minSafeProbability) +
        ') — UNKNOWN commands that pass every gate run without asking'
      : '; auto-allow off (审批提示只带参考判定，不改变门禁结果)'
    if (judge.enabled !== true) {
      checks.push({ name: 'risk judge', status: 'ok', detail: 'disabled — no command ever leaves the process' + autoAllow })
    } else {
      const viaEnv = (env[judge.apiKeyEnv] ?? '').trim().length > 0
      const hasKey = viaEnv || resolveApiKey(judge, env).length > 0
      checks.push({
        name: 'risk judge',
        status: hasKey ? 'ok' : 'warn',
        detail: hasKey
          ? 'enabled, key via ' + (viaEnv ? 'env ' + judge.apiKeyEnv : 'file ' + judge.apiKeyFile) +
            ' (value never printed) — endpoint ' + judge.endpoint + ', timeout ' + String(judge.timeoutMs) + 'ms' + autoAllow
          : 'enabled but no credential found (env ' + judge.apiKeyEnv + ' / ' + judge.apiKeyFile + ')' + autoAllow,
        ...(hasKey
          ? {}
          : {
              fix:
                'set ' + judge.apiKeyEnv + ' or write the key to ' + judge.apiKeyFile +
                '. Without it the judge stays silently off — every UNKNOWN prompt looks the way it does today.',
            }),
      })
    }

    // ---- data directories ------------------------------------------------
    const auditPath = config.auditPath ?? join(root, 'data', 'audit.jsonl')
    const auditProbe = probeWritable(dirname(auditPath))
    checks.push({
      name: 'audit sink',
      status: auditProbe.ok ? 'ok' : 'fail',
      detail: auditPath + ' — ' + auditProbe.detail,
      ...(auditProbe.ok
        ? {}
        : { fix: 'the audit JSONL and the ops console both write here; point auditPath at a writable location' }),
    })

    const baselineDir = join(root, 'data', 'baselines')
    const baselineProbe = probeWritable(baselineDir)
    checks.push({
      name: 'baseline store',
      status: baselineProbe.ok ? 'ok' : 'fail',
      detail: baselineDir + ' — ' + baselineProbe.detail,
      ...(baselineProbe.ok ? {} : { fix: 'jumpserver_baseline_capture writes here; make the install directory writable' }),
    })

    // ---- console port ----------------------------------------------------
    if (config.auditViewer.enabled !== true) {
      checks.push({ name: 'ops console', status: 'ok', detail: 'disabled by config (auditViewer.enabled=false)' })
    } else {
      const port = config.auditViewer.port
      const state = await probePort(port)
      // Listening is NOT a failure: in the default stable-URL mode an earlier
      // conversation's console legitimately holds the port and the page simply
      // reconnects to the same address. What matters is that the address works.
      checks.push({
        name: 'ops console',
        status: 'ok',
        detail: state === 'listening'
          ? 'port ' + port + ' already serves a console (expected while another conversation is open — reload the page)'
          : 'port ' + port + ' is free; the console will listen there',
      })
    }

    checks.push({
      name: 'effective policy',
      status: 'ok',
      detail: config.permissionMode + ', requireArm=' + String(config.requireArm) +
        ', maxSessions=' + String(config.maxSessions) +
        ', batchConcurrency=' + String(config.batchConcurrency) +
        ', timeZone=' + String(config.timeZone ?? 'system (resolved)') +
        ', allow=' + String((config.allowedTargets ?? []).length) +
        ' deny=' + String((config.deniedTargets ?? []).length) +
        ', assetGroups=' + String(Object.keys(config.assetGroups ?? {}).length) +
        ', runbooks=' + String(Object.keys(config.runbooks ?? {}).length),
    })
  }

  // ---- the COMPILED tool surface (V0.6.1 / B-4) ------------------------
  // The recurring "the host says connected but `mcp__jumpserver` has zero
  // sub-tools" complaint has a mundane cause that the connector can prove:
  // the `lib/` build is STALE. `lib/` is a build artifact — editing `src/`
  // changes nothing until `tsc` runs, and the MCP process caches its
  // schema at spawn time. So a source edit without a rebuild looks exactly
  // like a host-side registration failure.
  //
  // This check reads the BUILT files and looks for each expected tool name.
  // It opens no socket, binds no port and starts no server — `--doctor`
  // stays side-effect free.
  const toolSurface = checkCompiledToolSurface(root)
  checks.push({
    name: 'tool surface',
    status: toolSurface.status,
    detail: toolSurface.detail,
    ...(toolSurface.fix !== undefined ? { fix: toolSurface.fix } : {}),
  })

  // ---- ssh2 is the only non-trivial dependency --------------------------
  try {
    await import('ssh2')
    checks.push({ name: 'ssh2 transport', status: 'ok', detail: 'module loads' })
  } catch (error) {
    checks.push({
      name: 'ssh2 transport',
      status: 'fail',
      detail: 'cannot load ssh2: ' + (error instanceof Error ? error.message : String(error)),
      fix: 'reinstall the package — the connector cannot reach the bastion without it',
    })
  }

  // ---- readiness (V0.7.1 / D-9) -----------------------------------------
  // The question an operator actually has is not "is the config valid?" but
  // "can I start work on the bastion right now?". The readiness check answers
  // that in one verdict, using only READ-ONLY probes: the console discovery
  // files on disk, the target scope in the config, and TCP CONNECT probes to
  // the bastion and to the risk judge. It binds no port, opens no SSH session
  // and writes nothing.
  if (config !== null) {
    const judge = config.riskJudge ?? DEFAULT_RISK_JUDGE
    const judgeEndpoint = judge.enabled === true ? parseEndpointHostPort(judge.endpoint) : null
    const account = readActiveAccount(options.profilesPath ?? defaultProfileFilePath())
    const gatewayHost = account !== null ? account.host : config.host
    const gatewayPort = account !== null ? account.port : config.port
    const readiness = await computeReadiness({
      consoleDir: join(dirname(config.auditPath ?? join(root, 'data', 'audit.jsonl')), 'consoles'),
      gatewayHost,
      gatewayPort,
      allowedTargets: (config.allowedTargets ?? []).length,
      deniedTargets: (config.deniedTargets ?? []).length,
      assetGroups: Object.keys(config.assetGroups ?? {}).length,
      judgeEnabled: judge.enabled === true,
      ...(judgeEndpoint !== null ? { judgeHost: judgeEndpoint.host, judgePort: judgeEndpoint.port } : {}),
      ...(options.probeReachability !== undefined ? { probe: options.probeReachability } : {}),
    })

    const consoleDetail = readiness.consoleUrl !== null
      ? 'live at ' + readiness.consoleUrl + ' (pid ' + String(readiness.consoles[0]?.pid ?? '?') +
        ', ' + String(readiness.consoles.length) + ' instance(s))'
      : (readiness.staleConsoles.length > 0
        ? 'none live — ' + String(readiness.staleConsoles.length) + ' stale discovery file(s) from a process that is gone'
        : 'none live yet (the console starts with the connector)')

    checks.push({
      name: 'readiness',
      // V0.7.1 (D-9): a NETWORK blocker is a warning, not a failure. The
      // doctor's exit code has always meant "is the CONFIGURATION usable";
      // a bastion that is momentarily unreachable is an operational
      // condition. A CONFIGURATION blocker (the scope allows nothing) IS a
      // failure — no command could ever run.
      status: readiness.verdict === 'ready'
        ? 'ok'
        : (readiness.blockerIsConfig === true ? 'fail' : 'warn'),
      detail: readiness.verdict.toUpperCase() + ' — ' + readiness.reason +
        ' | gateway ' + readiness.gatewayAddress + ' = ' + readiness.gateway +
        ' | console: ' + consoleDetail +
        ' | scope allow=' + String(readiness.allowedTargets) + ' deny=' + String(readiness.deniedTargets) +
        ' groups=' + String(readiness.assetGroups) +
        (readiness.judgeEnabled ? ' | judge=' + readiness.judge : ''),
      ...(readiness.verdict === 'not-ready'
        ? { fix: 'fix the blocking item above before starting work on the bastion' }
        : readiness.verdict === 'degraded'
          ? { fix: 'work can start, but the degraded item above will cost you something' }
          : {}),
    })
  }

  const exitCode = checks.some((c) => c.status === 'fail') ? 1 : 0
  return { checks, exitCode }
}

export function renderDoctor(report: DoctorReport): string {
  const glyph: Record<DoctorStatus, string> = { ok: 'OK  ', warn: 'WARN', fail: 'FAIL' }
  const lines: string[] = []
  lines.push('jumpserver-mcp ' + PLUGIN_VERSION + ' — self-check')
  lines.push('')
  for (const check of report.checks) {
    lines.push('[' + glyph[check.status] + '] ' + check.name + ': ' + check.detail)
    if (check.fix !== undefined) {
      for (const line of check.fix.split('\n')) lines.push('           ' + line)
    }
  }
  lines.push('')
  const failed = report.checks.filter((c) => c.status === 'fail').length
  const warned = report.checks.filter((c) => c.status === 'warn').length
  lines.push(
    report.exitCode === 0
      ? 'Result: usable' + (warned > 0 ? ' (' + warned + ' warning' + (warned === 1 ? '' : 's') + ')' : '')
      : 'Result: ' + failed + ' problem' + (failed === 1 ? '' : 's') + ' must be fixed before the connector can reach the bastion',
  )
  return lines.join('\n')
}

/** True when the process was asked for a diagnostic run instead of a server. */
export function wantsDoctor(argv: readonly string[] = process.argv.slice(2)): boolean {
  return argv.includes('--doctor') || argv.includes('-doctor')
}
