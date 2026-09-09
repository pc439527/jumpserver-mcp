import { stripMarkerLines } from './output-buffer.js'
import { randomHex } from './timing.js'

export const DONE_PREFIX = '__DSH_JS_DONE_'
export const PROBE_PREFIX = '__DSH_JS_PROBE_'

/** Build the script that runs command and prints a unique done marker with its exit code. */
export function buildDoneScript(command: string, marker: string): string {
  return (
    `${command}\n` +
    `__dsh_rc=$?\n` +
    `printf '\n${DONE_PREFIX}${marker}:%s\n' "$__dsh_rc"`
  )
}

/** Build the target-probe script: labeled H=/U=/P= lines between unique markers. */
export function buildProbeScript(marker: string): string {
  return (
    `printf '${PROBE_PREFIX}${marker}\n'\n` +
    `printf 'H=%s\\n' "$(hostname 2>/dev/null || echo ?)"\n` +
    `printf 'U=%s\\n' "$(whoami 2>/dev/null || echo ?)"\n` +
    `printf 'P=%s\\n' "$(pwd 2>/dev/null || echo ?)"\n` +
    `printf '${PROBE_END_PREFIX}${marker}\n'`
  )
}

export const PROBE_END_PREFIX = '__DSH_JS_PROBE_END_'

/** Parse the done marker's exit code from captured output; null while absent. */
export function parseDoneLine(text: string, marker: string): { exitCode: number } | null {
  const pattern = new RegExp(DONE_PREFIX + marker + '[:：](\\d+)')
  const match = pattern.exec(text)
  if (match === null) return null
  const exitCode = Number(match[1])
  return Number.isInteger(exitCode) ? { exitCode } : null
}

/** Strip marker lines, internal script lines and trailing whitespace for user-facing output. */
export function cleanCommandOutput(raw: string, marker: string): string {
  const withoutMarkers = stripMarkerLines(raw, DONE_PREFIX + marker)
  const lines = withoutMarkers
    .split('\n')
    .filter((line) => !line.includes('__dsh_rc'))
  return lines.join('\n').trim() + '\n'
}

export { randomHex }
