import { PROBE_END_PREFIX, PROBE_PREFIX } from './command-runner.js'
import { cleanAnsi } from './output-buffer.js'

export interface ProbeInfo {
  hostname: string | null
  user: string | null
  pwd: string | null
  /**
   * V0.6.0: the asset's own IPv4 addresses (`hostname -I`), used for the
   * target self-verification (does the shell really sit on the asset that
   * was requested?). Empty when the host has no `hostname -I` — the check is
   * then skipped rather than failed.
   */
  ips: string[]
}

export { buildProbeScript } from './command-runner.js'

/**
 * Parse the labeled probe output between the start and end markers:
 *   __DSH_JS_PROBE_<m>
 *   H=hostname
 *   U=user
 *   P=pwd
 *   A=10.0.0.1,10.0.0.2
 *   __DSH_JS_PROBE_END_<m>
 * Robust to command echo, continuation prompts and banner noise: values are
 * found by their labels, not by line position.
 */
export function parseProbeOutput(raw: string, marker: string): ProbeInfo | null {
  const text = cleanAnsi(raw)
  const startLine = PROBE_PREFIX + marker
  const endLine = PROBE_END_PREFIX + marker
  const startIdx = text.indexOf(startLine)
  if (startIdx < 0) return null
  const endIdx = text.indexOf(endLine, startIdx)
  const body = endIdx >= 0 ? text.slice(startIdx, endIdx) : text.slice(startIdx)
  // Line-anchored: an echoed "printf 'H=%s...'" does not follow a newline,
  // while the real labeled output line does.
  const hay = '\n' + body
  const grab = (label: string): string | null => {
    const m = new RegExp('\\n' + label + '=([^\\n\\r]+)').exec(hay)
    if (m === null) return null
    const value = m[1]!.trim()
    return value.length > 0 && value !== '?' ? value : null
  }
  const hostname = grab('H')
  const user = grab('U')
  const pwd = grab('P')
  if (hostname === null || user === null || pwd === null) return null
  const rawIps = grab('A')
  const ips = rawIps === null
    ? []
    : rawIps.split(',').map((ip) => ip.trim()).filter((ip) => ip.length > 0)
  return { hostname, user, pwd, ips }
}
