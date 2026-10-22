/**
 * V0.6.0: target self-verification.
 *
 * The "假成功" (silent wrong-machine) defect: a batch asked for
 * `192.168.30.2` but the session was still sitting on the shell of
 * `192.168.30.3`, and the commands ran on the WRONG machine while the tool
 * reported success. Nothing in the connector noticed, because entering an
 * asset was believed on the strength of "a shell prompt appeared".
 *
 * This module answers one question with evidence: given what the caller
 * REQUESTED and what the shell REPORTS about itself, may we trust that the
 * shell is the requested asset?
 *
 * Evidence sources (both come from the probe that runs right after the
 * asset shell appears):
 *   - `ips`    — the asset's own IPv4 addresses (`hostname -I`)
 *   - `hostname` — the asset's hostname
 *
 * The rules are deliberately CONSERVATIVE — a wrong "verified" verdict is
 * the dangerous direction, so anything that cannot be decided stays
 * 'unverified' (allowed, but flagged) instead of being forced to 'verified':
 *
 *   requested is an IP literal
 *     → the asset's own address list must contain it, else MISMATCH
 *   requested is a name
 *     → the hostname is only compared when the hostname itself looks like an
 *       IP (e.g. `k8s-192-168-30-3`); a plain name↔hostname comparison would
 *       produce false mismatches on every asset whose display name differs
 *       from its hostname
 *
 * Multi-NIC and NAT are the two false-positive sources; both are handled by
 * requiring a POSITIVE match (the address list contains the requested IP)
 * rather than an exact single-address equality.
 */

export type TargetVerifyStatus = 'verified' | 'unverified' | 'mismatch'

export interface TargetVerifyInput {
  /** What the caller asked for (asset IP or asset name). */
  target: string
  /** The asset's own hostname, as reported by the probe. */
  hostname: string | null
  /** The asset's own IPv4 addresses, as reported by the probe. */
  ips: readonly string[]
}

export interface TargetVerifyResult {
  status: TargetVerifyStatus
  /** Human-readable reason, surfaced in the error detail. */
  reason: string
  /** The IPs that were actually observed on the shell. */
  observedIps: string[]
}

const IPV4 = /^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/

export function isIpv4Literal(value: string): boolean {
  if (!IPV4.test(value)) return false
  return value.split('.').every((part) => Number(part) <= 255)
}

/**
 * A hostname that EMBEDS an IP (`k8s-192-168-30-3`) is a strong, free
 * witness of which machine the shell sits on. Return that IP, if any.
 */
export function hostnameEmbeddedIp(hostname: string | null): string | null {
  if (hostname === null) return null
  const dashed = /([0-9]{1,3})(?:-[0-9]{1,3}){3}(?![0-9-])/.exec(hostname)
  if (dashed !== null) {
    const candidate = dashed[0].replace(/-/g, '.')
    if (isIpv4Literal(candidate)) return candidate
  }
  const plain = /(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9.])/.exec(hostname)
  if (plain !== null && isIpv4Literal(plain[1]!)) return plain[1]!
  return null
}

/**
 * Decide whether the shell may be trusted as the requested asset.
 */
export function verifyTargetIdentity(input: TargetVerifyInput): TargetVerifyResult {
  const observedIps = input.ips.filter((ip) => ip.length > 0)
  const target = input.target.trim()
  const hostname = input.hostname

  if (isIpv4Literal(target)) {
    if (observedIps.length === 0) {
      return {
        status: 'unverified',
        reason: 'the asset shell reported no IPv4 address (hostname -I unavailable), so the requested IP could not be confirmed',
        observedIps,
      }
    }
    if (observedIps.includes(target)) {
      return { status: 'verified', reason: 'the asset shell owns the requested IP ' + target, observedIps }
    }
    // The requested IP is absent. If the HOSTNAME embeds a DIFFERENT IP, the
    // shell is provably a different machine (e.g. requested 192.168.30.2 while
    // the shell answers k8s-192-168-30-3) — that is the "假成功" case.
    const embedded = hostnameEmbeddedIp(hostname)
    if (embedded !== null && embedded !== target) {
      return {
        status: 'mismatch',
        reason: 'the shell hostname (' + hostname + ') belongs to ' + embedded + ', not to the requested ' + target,
        observedIps,
      }
    }
    return {
      status: 'mismatch',
      reason: 'the asset shell does not own the requested IP ' + target + ' (its addresses are ' + observedIps.join(', ') + ')',
      observedIps,
    }
  }

  // Requested a NAME. The display name of an asset is not necessarily its
  // hostname, so only an embedded IP in the hostname can decide.
  const embedded = hostnameEmbeddedIp(hostname)
  if (embedded === null) {
    return {
      status: 'unverified',
      reason: 'the requested target is a name and the shell hostname (' + (hostname ?? 'unknown') + ') carries no IP to compare',
      observedIps,
    }
  }
  if (hostname !== null && hostname === target) {
    return { status: 'verified', reason: 'the shell hostname matches the requested target ' + target, observedIps }
  }
  return {
    status: 'unverified',
    reason: 'the requested target is a name and the shell hostname (' + hostname + ') embeds ' + embedded + ', which cannot be compared to a name',
    observedIps,
  }
}
