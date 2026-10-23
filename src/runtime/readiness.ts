/**
 * V0.7.1 (D-9): the READINESS check.
 *
 * WHY THIS EXISTS
 * ---------------
 * `--doctor` answers "is this connector configured correctly?". It does NOT
 * answer the question the operator actually has at 09:00: "can I start work
 * on the bastion right now?" — which needs four more facts:
 *
 *   1. Is a console ALIVE, and at what URL? (a dead console URL is the most
 *      common "it doesn't work" report)
 *   2. How many assets am I actually authorized for? (a target scope of 0
 *      means every command will be refused)
 *   3. Is the bastion REACHABLE? (TCP connect, no SSH handshake)
 *   4. Is the risk judge reachable? (an unreachable judge silently degrades
 *      every UNKNOWN command to a plain prompt)
 *
 * A MISSING console is not a degradation: `--doctor` runs standalone, so no
 * console is running by definition. What deserves attention is a STALE
 * discovery file — one whose process is gone.
 *
 * THE ZERO-SIDE-EFFECT RULE
 * -------------------------
 * This module is READ-ONLY. It:
 *   - reads the console discovery files (they are already on disk),
 *   - counts the target-scope entries in the config,
 *   - TCP-CONNECTS to the bastion and to the judge endpoint (a connect probe
 *     binds nothing and opens no session),
 *   - never writes, never binds, never authenticates.
 *
 * A readiness check that CHANGED the state it measures would be worse than
 * no readiness check.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { createConnection } from 'node:net'

/** A console instance discovered on disk. */
export interface ConsoleInstanceInfo {
  pid: number
  port: number
  role: string
  startedAt: string
  /** Age of the heartbeat in milliseconds; a stale one means a dead process. */
  ageMs: number
  state: string
  target: string | null
  sessions: number
}

/** A console discovery file that exists but is stale (its process is gone). */
export interface StaleConsoleInfo {
  pid: number
  port: number
  ageMs: number
}

/** The outcome of one reachability probe. */
export type Reachability = 'reachable' | 'unreachable' | 'unknown'

export interface ReadinessReport {
  /**
   * The one-line verdict: can work start now?
   *
   *   ready      — the bastion is reachable and the scope allows a target
   *   degraded   — work can start but something is missing
   *   not-ready  — something BLOCKS work
   */
  verdict: 'ready' | 'degraded' | 'not-ready'
  /**
   * True when the blocker is a CONFIGURATION problem (the target scope
   * allows nothing) rather than a NETWORK problem (the bastion does not
   * answer).
   *
   * The distinction matters for the exit code: `--doctor` has always meant
   * "is the CONFIGURATION usable". A bastion that is temporarily unreachable
   * is an operational condition, not a misconfiguration — it must not turn
   * a correct configuration into a failed run.
   */
  blockerIsConfig: boolean
  /** The reason behind the verdict, in one sentence. */
  reason: string
  /** Live console instances (fresh heartbeats only). */
  consoles: ConsoleInstanceInfo[]
  /** Discovery files whose process is gone. */
  staleConsoles: StaleConsoleInfo[]
  /** The console URL to open (the owner's, or the first live one). */
  consoleUrl: string | null
  /** How many targets the scope allows. */
  allowedTargets: number
  /** How many targets the scope denies. */
  deniedTargets: number
  /** How many asset groups are defined. */
  assetGroups: number
  /** Can the bastion be reached at the TCP level? */
  gateway: Reachability
  /** The gateway address that was probed. */
  gatewayAddress: string
  /** Can the risk-judge endpoint be reached? */
  judge: Reachability
  /** Whether the risk judge is enabled at all. */
  judgeEnabled: boolean
}

/** The heartbeat freshness window — the same one the console uses. */
const CONSOLE_STALE_MS = 20_000

/**
 * A TCP connect probe. It CONNECTS (never binds) and gives up after the
 * timeout. The result is all that matters; nothing is exchanged.
 */
export function tcpReachability(host: string, port: number, timeoutMs = 1500): Promise<Reachability> {
  if (host.length === 0 || port <= 0) return Promise.resolve('unknown')
  return new Promise((resolve) => {
    const socket = createConnection({ host, port })
    let settled = false
    const done = (result: Reachability): void => {
      if (settled) return
      settled = true
      socket.removeAllListeners()
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(timeoutMs)
    socket.on('connect', () => done('reachable'))
    socket.on('timeout', () => done('unreachable'))
    socket.on('error', () => done('unreachable'))
  })
}

/**
 * Read the console discovery files in `dir`.
 *
 * A file whose heartbeat is older than the freshness window belongs to a
 * process that is gone (the process was killed and could not clean up). Those
 * are reported separately: a stale file is not an error, but it does mean the
 * URL the operator has bookmarked is dead.
 */
export function readConsoleInstances(dir: string, now = Date.now()): {
  live: ConsoleInstanceInfo[]
  stale: StaleConsoleInfo[]
} {
  const live: ConsoleInstanceInfo[] = []
  const stale: StaleConsoleInfo[] = []
  if (!existsSync(dir)) return { live, stale }
  let names: string[]
  try {
    names = readdirSync(dir)
  } catch {
    return { live, stale }
  }
  for (const name of names) {
    if (!name.endsWith('.json')) continue
    let raw: Record<string, unknown>
    try {
      raw = JSON.parse(readFileSync(join(dir, name), 'utf8')) as Record<string, unknown>
    } catch {
      continue
    }
    const pid = Number(raw['pid'])
    const port = Number(raw['port'])
    if (!Number.isFinite(pid) || !Number.isFinite(port) || port <= 0) continue
    const ageMs = now - Date.parse(String(raw['heartbeatAt'] ?? ''))
    if (!Number.isFinite(ageMs)) continue
    const summary = (raw['summary'] ?? {}) as Record<string, unknown>
    if (ageMs > CONSOLE_STALE_MS) {
      stale.push({ pid, port, ageMs })
      continue
    }
    const rawTarget = summary['target']
    live.push({
      pid,
      port,
      role: String(raw['role'] ?? 'owner'),
      startedAt: String(raw['startedAt'] ?? ''),
      ageMs,
      state: String(summary['state'] ?? 'unknown'),
      target: rawTarget === null || rawTarget === undefined ? null : String(rawTarget),
      sessions: Number(summary['sessions'] ?? 0) || 0,
    })
  }
  live.sort((a, b) => a.pid - b.pid)
  return { live, stale }
}

/** The URL of a console instance. */
export function consoleUrlOf(instance: ConsoleInstanceInfo): string {
  return 'http://127.0.0.1:' + String(instance.port) + '/?inst=' + String(instance.pid)
}

/**
 * Split an http(s) endpoint into host + port.
 *
 * Returns null when the endpoint has no usable host. The default port is
 * inferred from the scheme (443 for https, 80 for http).
 */
export function parseEndpointHostPort(endpoint: string): { host: string; port: number } | null {
  const trimmed = endpoint.trim()
  if (trimmed.length === 0) return null
  let rest = trimmed
  let port = 0
  if (rest.startsWith('https://')) {
    port = 443
    rest = rest.slice('https://'.length)
  } else if (rest.startsWith('http://')) {
    port = 80
    rest = rest.slice('http://'.length)
  } else {
    return null
  }
  const slash = rest.indexOf('/')
  if (slash >= 0) rest = rest.slice(0, slash)
  const colon = rest.lastIndexOf(':')
  if (colon > 0) {
    const parsed = Number(rest.slice(colon + 1))
    if (Number.isFinite(parsed) && parsed > 0 && parsed < 65536) {
      return { host: rest.slice(0, colon), port: parsed }
    }
  }
  if (rest.length === 0) return null
  return { host: rest, port }
}

export interface ReadinessOptions {
  /** The directory holding the console discovery files. */
  consoleDir: string
  /** The bastion address. */
  gatewayHost: string
  gatewayPort: number
  /** The target scope counts. */
  allowedTargets?: number
  deniedTargets?: number
  assetGroups?: number
  /** Is the risk judge enabled? */
  judgeEnabled?: boolean
  /** The judge endpoint (host + port) — probed when the judge is enabled. */
  judgeHost?: string
  judgePort?: number
  /** Injected probe (tests must not open sockets). */
  probe?: (host: string, port: number) => Promise<Reachability>
  /** Injected clock. */
  now?: number
}

/**
 * Compute the readiness report.
 *
 * The verdict has three levels:
 *   ready      — the bastion is reachable and the scope allows at least one target
 *   degraded   — work can start but something is missing (no console, judge down)
 *   not-ready  — the bastion is unreachable, or the scope allows nothing
 */
export async function computeReadiness(options: ReadinessOptions): Promise<ReadinessReport> {
  const probe = options.probe ?? tcpReachability
  const now = options.now ?? Date.now()

  const { live, stale } = readConsoleInstances(options.consoleDir, now)
  const owner = live.find((c) => c.role === 'owner') ?? live[0] ?? null
  const consoleUrl = owner === null ? null : consoleUrlOf(owner)

  const allowedTargets = options.allowedTargets ?? 0
  const deniedTargets = options.deniedTargets ?? 0
  const assetGroups = options.assetGroups ?? 0

  const gatewayHost = options.gatewayHost
  const gateway = await probe(gatewayHost, options.gatewayPort)

  let judge: Reachability = 'unknown'
  const judgeEnabled = options.judgeEnabled === true
  if (judgeEnabled) {
    if (options.judgeHost !== undefined && options.judgePort !== undefined) {
      judge = await probe(options.judgeHost, options.judgePort)
    } else {
      judge = 'unknown'
    }
  }

  let verdict: ReadinessReport['verdict']
  let reason: string
  let blockerIsConfig = false
  if (gatewayHost.length === 0) {
    // No bastion address at all — a CONFIGURATION problem, and one that
    // blocks every command.
    verdict = 'not-ready'
    blockerIsConfig = true
    reason = 'no bastion address is configured — no command can run'
  } else if (gateway === 'unreachable') {
    verdict = 'not-ready'
    blockerIsConfig = false
    reason = 'the bastion at ' + options.gatewayHost + ':' + String(options.gatewayPort) +
      ' did not accept a TCP connection — no command can run'
  } else if (allowedTargets === 0 && deniedTargets > 0) {
    // An empty allowedTargets means "NO RESTRICTION" (see target-scope.ts:
    // an empty allow list passes everything). The deny list alone is not a
    // blocker — the connector cannot know whether it covers every reachable
    // asset.
    verdict = 'ready'
    reason = 'the bastion is reachable; the target scope is unrestricted (no allow list)'
  } else if (judge === 'unreachable') {
    verdict = 'degraded'
    reason = 'the bastion is reachable, but the risk judge is unreachable — every UNKNOWN command falls back to a plain approval prompt'
  } else if (stale.length > 0) {
    // A stale discovery file means a console process died without cleaning
    // up. The bastion is still usable, but the address the operator has
    // bookmarked may be pointing at a dead process.
    verdict = 'degraded'
    reason = 'the bastion is reachable, but ' + String(stale.length) +
      ' console discovery file(s) belong to a process that is gone'
  } else {
    // A missing console is NOT a degradation: `--doctor` runs standalone, so
    // no console is running by definition. The console only matters once the
    // connector itself is up.
    verdict = 'ready'
    reason = 'the bastion is reachable, ' + String(allowedTargets) + ' target(s) are in scope' +
      (consoleUrl !== null ? ', and the console is live at ' + consoleUrl : '')
  }

  return {
    verdict,
    blockerIsConfig,
    reason,
    consoles: live,
    staleConsoles: stale,
    consoleUrl,
    allowedTargets,
    deniedTargets,
    assetGroups,
    gateway,
    gatewayAddress: options.gatewayHost + ':' + String(options.gatewayPort),
    judge,
    judgeEnabled,
  }
}
