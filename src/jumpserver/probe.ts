import { PROBE_END_PREFIX, PROBE_PREFIX } from './command-runner.js'
import { cleanAnsi } from './output-buffer.js'

export interface ProbeInfo {
  hostname: string | null
  user: string | null
  pwd: string | null
}

export { buildProbeScript } from './command-runner.js'

/**
 * Parse the labeled probe output between the start and end markers:
 *   __DSH_JS_PROBE_<m>
 *   H=hostname
 *   U=user
 *   P=pwd
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
  return { hostname, user, pwd }
}
