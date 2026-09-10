/**
 * Target scope guard (V0.4.0, tightened in V0.4.3).
 *
 * Restrict which assets this MCP connector may touch. Deny always wins.
 *
 * V0.4.3: the old matcher was a plain substring test, so an exact IP entry
 * "192.168.79.10" also matched "192.168.79.100" — a scope leak in the
 * permissive direction (more assets reachable than configured) and a
 * surprising one in the deny direction. Entries now declare their intent:
 *
 *   "192.168.79.10"      exact  — only that literal target
 *   "192.168.79."        prefix — an IP/name prefix (trailing dot or dash)
 *   "oa-*"               glob   — explicit wildcard
 *   "192.168.79.0/24"    cidr   — an IPv4 range
 *   "10.1.2.3:2222"      exact  — host:port stays exact
 *
 * A bare string with no wildcard/dot/dash is treated as EXACT, which is the
 * safe reading: configs that used to rely on substring now match only what
 * they literally named.
 */
import { JumpServerError } from '../jumpserver/errors.js'

export interface TargetScopeConfig {
  allowedTargets?: string[]
  deniedTargets?: string[]
}

/** Parse an IPv4 literal into 4 octets, or null when it is not one. */
function ipv4(value: string): [number, number, number, number] | null {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (n > 255) return null
    octets.push(n)
  }
  return [octets[0]!, octets[1]!, octets[2]!, octets[3]!]
}

/** CIDR containment for IPv4 literals; non-IPv4 input never matches. */
function inCidr(target: string, cidr: string): boolean {
  const slash = cidr.indexOf('/')
  if (slash < 0) return false
  const network = ipv4(cidr.slice(0, slash))
  const targetIp = ipv4(target)
  const bits = Number(cidr.slice(slash + 1))
  if (network === null || targetIp === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false
  // Build both as 32-bit unsigned integers and compare the masked prefix.
  const toInt = (o: [number, number, number, number]) => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return ((toInt(network) & mask) >>> 0) === ((toInt(targetIp) & mask) >>> 0)
}

/** Glob with only `*` meaningful; every other character is literal. */
function globMatch(target: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp('^' + escaped + '$', 'i').test(target)
}

/**
 * Does one configured entry cover this target?
 * Rules are evaluated in order; the first applicable form wins.
 */
function entryMatches(target: string, rawEntry: string): boolean {
  const entry = rawEntry.trim()
  if (entry.length === 0) return false

  // CIDR first: a '/' can only mean a network range.
  if (entry.includes('/')) return inCidr(target, entry)

  // Explicit wildcard.
  if (entry.includes('*')) return globMatch(target, entry)

  // A trailing dot / dash / colon declares an intentional prefix match, so
  // "192.168.79." and "oa-" keep working exactly as before.
  if (/[.\-:]$/.test(entry)) return target.startsWith(entry)

  // Everything else is EXACT: "192.168.79.10" must not match "192.168.79.100".
  return target === entry
}

function matches(list: readonly string[] | undefined, target: string): string | null {
  if (list === undefined || list.length === 0) return null
  const needle = target.trim().toLowerCase()
  if (needle.length === 0) return null
  for (const entry of list) {
    if (entryMatches(needle, entry.trim().toLowerCase())) return entry
  }
  return null
}

/** Throws TARGET_DENIED when the target is outside the configured scope. */
export function requireTargetAllowed(cfg: TargetScopeConfig, target: string | null | undefined): void {
  const value = (target ?? '').trim()
  if (value.length === 0) return
  const denied = matches(cfg.deniedTargets, value)
  if (denied !== null) {
    throw new JumpServerError('TARGET_DENIED', 'target "' + value + '" is on deniedTargets (rule: ' + denied + ')')
  }
  if (cfg.allowedTargets === undefined || cfg.allowedTargets.length === 0) return
  if (matches(cfg.allowedTargets, value) === null) {
    throw new JumpServerError(
      'TARGET_DENIED',
      'target "' + value + '" is not in allowedTargets; add it to the config or pick another asset',
    )
  }
}
