/**
 * V0.5.0 — SSH host-key verification: TOFU + optional fingerprint pinning.
 *
 * Before this module the connector used an encrypted SSH channel without ever
 * checking WHO was on the other end: `ssh2.connect()` ran with no
 * `hostVerifier`, so a machine that could intercept the route to the bastion
 * would collect the JumpServer password. Encryption without identity
 * verification is not a trust chain.
 *
 * Two modes, chosen by whether the operator pinned a fingerprint:
 *
 *   pinned    config.json (or the connector form) carries a SHA256/MD5
 *             fingerprint. Only a byte-identical key is accepted; anything
 *             else is refused as `pinned-mismatch`.
 *   TOFU      no pin. The first successful contact records the key in a local
 *             known_hosts file and accepts; every later contact must match
 *             that record or the connection is refused as `mismatch`.
 *
 * A mismatch is never auto-healed. Silently re-trusting a changed host key is
 * exactly the behaviour that makes TOFU worthless, so the refusal stands until
 * a human edits or deletes the known_hosts entry.
 *
 * Verification is synchronous because ssh2's `hostVerifier` is called inline
 * during the handshake; the store is loaded once when the guard is created and
 * persisted with a synchronous write.
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

export type HostKeyOutcome =
  /** Key matches an operator-pinned fingerprint. */
  | 'pinned-match'
  /** Key contradicts an operator-pinned fingerprint — hard refusal. */
  | 'pinned-mismatch'
  /** Key matches the previously recorded key for this host. */
  | 'known-match'
  /** Key differs from the recorded key — hard refusal (possible MITM). */
  | 'mismatch'
  /** First contact, no pin: the key was recorded and accepted. */
  | 'tofu-recorded'
  /** First contact with no store available to record into; accepted but unverifiable next time. */
  | 'tofu-unrecorded'

export interface HostKeyDecision {
  accept: boolean
  outcome: HostKeyOutcome
  /** SHA256 fingerprint of the key that was actually presented. */
  fingerprint: string
  /** Host-key algorithm parsed from the key blob (e.g. ssh-ed25519). */
  algorithm?: string
  /** The fingerprint we expected, when one was available (pin or record). */
  expected?: string
  /** Path of the known_hosts store, when one is configured. */
  storePath?: string
}

export interface KnownHostRecord {
  algorithm?: string
  fingerprint: string
  firstSeenAt: string
  /** 'tofu' = learned on first contact; 'pinned' = matched a configured fingerprint. */
  source: 'tofu' | 'pinned'
}

interface KnownHostsFile {
  version: 1
  hosts: Record<string, KnownHostRecord>
}

/** Parse the algorithm name out of an SSH host-key blob (uint32 length + name). */
export function parseKeyAlgorithm(key: Buffer): string | undefined {
  if (key.length < 4) return undefined
  const length = key.readUInt32BE(0)
  if (length <= 0 || 4 + length > key.length) return undefined
  return key.toString('utf8', 4, 4 + length)
}

function sha256Base64(key: Buffer): string {
  return createHash('sha256').update(key).digest('base64')
}

function sha256Hex(key: Buffer): string {
  return createHash('sha256').update(key).digest('hex')
}

function md5Hex(key: Buffer): string {
  return createHash('md5').update(key).digest('hex')
}

function stripPadding(value: string): string {
  return value.replace(/=+$/, '')
}

/** OpenSSH-style fingerprint, e.g. `SHA256:AbCdEf…` (no padding, like ssh-keygen -lf). */
export function sha256Fingerprint(key: Buffer): string {
  return 'SHA256:' + stripPadding(sha256Base64(key))
}

/** Legacy OpenSSH fingerprint, e.g. `MD5:aa:bb:cc:…`. */
export function md5Fingerprint(key: Buffer): string {
  const hex = md5Hex(key)
  const pairs = hex.match(/.{2}/g) ?? []
  return 'MD5:' + pairs.join(':')
}

/**
 * Compare a key against an operator-supplied fingerprint, accepting every
 * format a person is realistically going to paste:
 *
 *   SHA256:AbCdEf…   OpenSSH default (padding optional, case-sensitive body)
 *   MD5:aa:bb:cc:…   legacy ssh-keygen output
 *   <64 hex chars>   raw sha256 digest
 *   <43/44 base64>   bare sha256, padding optional
 */
export function matchesFingerprint(key: Buffer, expected: string): boolean {
  const value = expected.trim()
  const upper = value.toUpperCase()

  if (upper.startsWith('SHA256:')) {
    return stripPadding(value.slice(7).trim()) === stripPadding(sha256Base64(key))
  }
  if (upper.startsWith('MD5:')) {
    return value.slice(4).replace(/[:\s]/g, '').toLowerCase() === md5Hex(key)
  }
  if (/^[0-9a-f]{64}$/i.test(value)) {
    return value.toLowerCase() === sha256Hex(key)
  }
  return stripPadding(value) === stripPadding(sha256Base64(key))
}

/** Empty / whitespace-only fingerprints mean "not configured". */
export function normalizeFingerprint(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined
  const trimmed = raw.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

/** Normalize a host into its known_hosts key (lowercase, always port-qualified). */
export function knownHostsKey(host: string, port: number): string {
  return host.trim().toLowerCase() + ':' + String(port)
}

/**
 * JSON-backed known_hosts store.
 *
 * A corrupt or unreadable file is treated as empty rather than fatal: refusing
 * to start because a sidecar file is malformed would be a worse failure than
 * re-learning the key, and the next write repairs the file. The trade-off is
 * recorded here on purpose — an attacker who can corrupt the file can also
 * force a fresh TOFU, which is why pinning exists for environments that need
 * certainty.
 */
export class KnownHostsStore {
  readonly path: string
  private records: Record<string, KnownHostRecord>

  constructor(path: string) {
    this.path = path
    this.records = loadKnownHosts(path)
  }

  get(hostPort: string): KnownHostRecord | undefined {
    return this.records[hostPort]
  }

  /** Persist a record. Returns false when the file could not be written. */
  put(hostPort: string, record: KnownHostRecord): boolean {
    this.records[hostPort] = record
    try {
      mkdirSync(dirname(this.path), { recursive: true })
      const payload: KnownHostsFile = { version: 1, hosts: this.records }
      writeFileSync(this.path, JSON.stringify(payload, null, 2) + '\n', 'utf8')
      return true
    } catch {
      return false
    }
  }

  /** Every recorded host (read-only view, for the console settings tab). */
  entries(): Record<string, KnownHostRecord> {
    return { ...this.records }
  }
}

function loadKnownHosts(path: string): Record<string, KnownHostRecord> {
  if (!existsSync(path)) return {}
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<KnownHostsFile>
    if (parsed === null || typeof parsed !== 'object') return {}
    const hosts = parsed.hosts
    if (hosts === null || typeof hosts !== 'object') return {}
    return hosts as Record<string, KnownHostRecord>
  } catch {
    return {}
  }
}

export interface HostKeyGuardOptions {
  host: string
  port: number
  /** Operator-pinned fingerprint; when set only a match is accepted. */
  fingerprint?: string
  /** known_hosts path; when absent, TOFU decisions cannot be persisted. */
  storePath?: string
  /** Notified for every decision so the caller can log / audit it. */
  onDecision?: (decision: HostKeyDecision) => void
}

export interface HostKeyGuard {
  /** ssh2 `hostVerifier` (synchronous form). */
  verifier: (key: Buffer) => boolean
  /** The most recent decision, or undefined before the first verification. */
  last: () => HostKeyDecision | undefined
}

/**
 * Build the verifier handed to ssh2. Every call records its decision so the
 * connect-failure path can report WHY the handshake was refused instead of a
 * generic "host verification failed".
 */
export function createHostKeyGuard(opts: HostKeyGuardOptions): HostKeyGuard {
  const pin = normalizeFingerprint(opts.fingerprint)
  const storePath = opts.storePath !== undefined && opts.storePath.length > 0 ? opts.storePath : undefined
  const store = storePath !== undefined ? new KnownHostsStore(storePath) : null
  const hostPort = knownHostsKey(opts.host, opts.port)
  let last: HostKeyDecision | undefined

  const verifier = (key: Buffer): boolean => {
    const fingerprint = sha256Fingerprint(key)
    const algorithm = parseKeyAlgorithm(key)

    if (pin !== undefined) {
      const ok = matchesFingerprint(key, pin)
      last = {
        accept: ok,
        outcome: ok ? 'pinned-match' : 'pinned-mismatch',
        fingerprint,
        algorithm,
        expected: pin,
        storePath,
      }
      if (ok && store !== null) {
        store.put(hostPort, { algorithm, fingerprint, firstSeenAt: new Date().toISOString(), source: 'pinned' })
      }
      opts.onDecision?.(last)
      return ok
    }

    const known = store?.get(hostPort)
    if (known !== undefined) {
      const ok = known.fingerprint === fingerprint
      last = {
        accept: ok,
        outcome: ok ? 'known-match' : 'mismatch',
        fingerprint,
        algorithm,
        expected: known.fingerprint,
        storePath,
      }
      opts.onDecision?.(last)
      return ok
    }

    const recorded = store !== null
      ? store.put(hostPort, { algorithm, fingerprint, firstSeenAt: new Date().toISOString(), source: 'tofu' })
      : false
    last = {
      accept: true,
      outcome: recorded ? 'tofu-recorded' : 'tofu-unrecorded',
      fingerprint,
      algorithm,
      storePath,
    }
    opts.onDecision?.(last)
    return true
  }

  return { verifier, last: () => last }
}

/** Operator-facing explanation for a refused host key. */
export function describeHostKeyRefusal(decision: HostKeyDecision): string {
  const where = decision.storePath !== undefined ? decision.storePath : '(no known_hosts file configured)'
  if (decision.outcome === 'pinned-mismatch') {
    return (
      'refused: the bastion presented a host key that does not match the pinned fingerprint ' +
      '(expected ' + String(decision.expected) + ', got ' + decision.fingerprint + '). ' +
      'If the bastion was legitimately rebuilt, update the configured fingerprint; ' +
      'do not clear this blindly.'
    )
  }
  return (
    'refused: the bastion host key changed since the last successful connection ' +
    '(expected ' + String(decision.expected) + ', got ' + decision.fingerprint + '). ' +
    'This is the signature of a man-in-the-middle, but it also happens after a legitimate ' +
    'bastion rebuild. Verify out of band, then edit or delete the entry for this host in ' + where + '.'
  )
}
