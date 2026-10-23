import { cleanAnsi } from './output-buffer.js'
import { randomHex } from './timing.js'

export const DONE_PREFIX = '__DSH_JS_DONE_'
export const PROBE_PREFIX = '__DSH_JS_PROBE_'

/** Escape a string for use inside a RegExp. */
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * V0.7.1 (D-4): the completion criterion.
 *
 * The marker must START a line AND carry DIGITS after the colon:
 *
 *     __DSH_JS_DONE_<hex>:0
 *
 * Both halves are load-bearing, and the second one is the important one.
 * The PTY echoes the connector's own script back to the screen, and that echo
 * contains the marker followed by the literal `%s`:
 *
 *     printf '\n__DSH_JS_DONE_508D68DB:%s\n' "$?"
 *
 * A matcher that accepts the marker alone therefore fires on the ECHO — the
 * connector would declare the command finished before the remote shell had
 * run it, and return only the echoed script. Requiring digits after the
 * colon rejects the echo (which carries `%s`) and accepts only the real
 * marker, so the completion signal can no longer be spoofed by the screen
 * contents or by the command's own output.
 *
 * Measured against the live bastion on 2026-10-23 — the raw capture was:
 *
 *     "printf 'NOEOL'\r\n...NOEOL...root@S030116:~# __dsh_rc=$?\r\n...
 *      printf '\r\n...> __DSH_JS_DONE_508D68DB:%s\r\n...
 *      ...\r\n__DSH_JS_DONE_508D68DB:0\r\n..."
 *
 * Note the `> ` continuation prompts: the old script embedded REAL newlines
 * inside the printf format, so bash treated it as a multi-line input. The
 * wrapper below uses a literal backslash-n instead, which keeps every
 * command a single line.
 */
export function doneMarkerPattern(marker: string): RegExp {
  return new RegExp('(?:^|\\n)' + escapeRegExp(DONE_PREFIX + marker) + '[:：](\\d+)')
}

/** The probe marker: line-anchored, no exit code. */
export function probeMarkerPattern(marker: string): RegExp {
  return new RegExp('(?:^|\\n)' + escapeRegExp(PROBE_PREFIX + marker))
}

/**
 * V0.7.1 (D-4): can a `; printf ...` wrapper be appended to this command?
 *
 * Two shell constructs make appending unsafe:
 *   - an UNQUOTED `#` starts a comment, which would swallow the wrapper;
 *   - a single unquoted `&` backgrounds the command, so `$?` would be the
 *     wrapper's own status rather than the command's.
 * A trailing incomplete operator (`|`, `>`, `<`, `&`) would also break the
 * line, and a trailing `;` would produce `;;`.
 */
export function canAppendInline(command: string): boolean {
  let quote: string | null = null
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!
    if (quote !== null) {
      if (ch === quote) quote = null
      continue
    }
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      continue
    }
    if (ch === '#') return false
    if (ch === '&') {
      // `&&` is a normal operator; a single `&` backgrounds the command.
      if (command[i + 1] === '&') {
        i++
        continue
      }
      return false
    }
  }
  const trimmed = command.replace(/\s+$/, '').replace(/;$/, '').trim()
  if (trimmed.length === 0) return false
  const last = trimmed[trimmed.length - 1]!
  return last !== '|' && last !== '>' && last !== '<' && last !== '&'
}

/**
 * V0.7.1 (D-4): build the script that runs the command and prints a unique
 * done marker with its exit code.
 *
 * WHY THE SCRIPT IS ONE LINE
 * --------------------------
 * The PTY echoes whatever the connector types. With the old three-line
 * script the shell echoed the command, RAN it, and only then echoed the next
 * line — so a command whose output has NO trailing newline ended up glued
 * to the prompt and to the echoed bookkeeping:
 *
 *     NOEOLroot@S030116:~# __dsh_rc=$?
 *
 * The output cleaner then dropped that whole line, and the REAL OUTPUT
 * DISAPPEARED. Measured on the live bastion: `printf 'NOEOL'` returned the
 * echoed command and nothing else.
 *
 * One line changes the ordering: the shell echoes the whole script BEFORE
 * it executes anything, so the real output always lands AFTER the echo and
 * can be separated by a known anchor instead of by guessing.
 *
 * Commands that cannot take an inline wrapper (`#`, `&`, a trailing
 * operator) fall back to a brace group. A brace group is still ONE command
 * to bash — it is not complete until the closing brace arrives — so the
 * ordering property is preserved.
 */
export function buildDoneScript(command: string, marker: string): string {
  const wrapper = `printf '\\n${DONE_PREFIX}${marker}:%s\\n' "$?"`
  if (canAppendInline(command)) {
    const trimmed = command.replace(/\s+$/, '').replace(/;$/, '')
    return `${trimmed} ; ${wrapper}`
  }
  return `{\n${command}\n} ; ${wrapper}`
}

/**
 * Build the target-probe script: labeled H=/U=/P=/A= lines between unique markers.
 *
 * V0.6.0: `A=` carries the asset's own IPv4 addresses (`hostname -I`). It is
 * additive — the connector still works on hosts where the command does not
 * exist (the value is then empty and the IP check is simply skipped).
 *
 * V0.7.1 (D-4): the printf formats use a LITERAL backslash-n. The old
 * script embedded real newlines inside the format, so bash read it as a
 * multi-line command and printed `> ` continuation prompts into the middle
 * of the probe output.
 */
export function buildProbeScript(marker: string): string {
  return (
    `printf '${PROBE_PREFIX}${marker}\\n'\n` +
    `printf 'H=%s\\n' "$(hostname 2>/dev/null || echo ?)"\n` +
    `printf 'U=%s\\n' "$(whoami 2>/dev/null || echo ?)"\n` +
    `printf 'P=%s\\n' "$(pwd 2>/dev/null || echo ?)"\n` +
    `printf 'A=%s\\n' "$(hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//')"\n` +
    `printf '${PROBE_END_PREFIX}${marker}\\n'`
  )
}

export const PROBE_END_PREFIX = '__DSH_JS_PROBE_END_'

/**
 * Parse the done marker's exit code from captured output; null while absent.
 *
 * V0.7.1 (D-4): the marker must start a line and carry digits — see
 * doneMarkerPattern() for why the digit requirement is the load-bearing part.
 */
export function parseDoneLine(text: string, marker: string): { exitCode: number } | null {
  const match = doneMarkerPattern(marker).exec(text)
  if (match === null) return null
  const exitCode = Number(match[1])
  return Number.isInteger(exitCode) ? { exitCode } : null
}

/**
 * V0.7.1 (D-4): turn the raw PTY capture into the command's own output.
 *
 * The three properties that must hold:
 *   1. The REAL output is never lost — not even when it has no trailing
 *      newline and is glued to the prompt or to the echoed wrapper.
 *   2. The connector's own bookkeeping (the echoed script, the marker) never
 *      reaches the model.
 *   3. The result always ends with exactly one newline, so the model sees a
 *      complete final line.
 *
 * The `script` argument is the exact text the connector wrote; the PTY
 * echoed it back verbatim, so removing that text removes the echo without
 * guessing where the output starts.
 */
export function cleanCommandOutput(raw: string, marker: string, script?: string): string {
  const text = cleanAnsi(raw)
  const token = DONE_PREFIX + marker

  // Cut at the REAL marker (line-anchored, digits). Everything after it is
  // the next prompt and belongs to the NEXT operation, not to this output.
  const markerMatch = doneMarkerPattern(marker).exec(text)
  const head = markerMatch === null ? text : text.slice(0, markerMatch.index)

  // The connector's own script came back as an ECHO. The echo is a whole
  // line (or a run of lines, when readline wrapped it), and it can carry
  // fragments of the wrapper — so the removal is line-based:
  //
  //   - a line that IS the echoed script disappears;
  //   - a line that merely CONTAINS the wrapper keeps everything else on it,
  //     because a real output can share a line with the echo (an output
  //     without a trailing newline is glued to whatever follows it).
  const lines = head.split('\n')
  const kept: string[] = []
  for (const line of lines) {
    if (script !== undefined && script.length > 0 && line.includes(script)) continue
    if (isEchoOnlyLine(line, token)) continue
    kept.push(stripWrapperFragments(line, token))
  }

  return finalize(kept.join('\n'))
}

/**
 * True when a line is nothing but the connector's own bookkeeping.
 *
 * The echoed wrapper looks like `printf '\n__DSH_JS_DONE_x:%s\n' "$?"`, and
 * the echoed rc capture like `__dsh_rc=$?`. A line that still carries other
 * content is NOT an echo — it is real output that happens to share the line.
 *
 * The echo of the WHOLE script is one line too (the script is one line),
 * and it carries the user's own command text in front of the wrapper:
 *
 *     printf 'NOEOL' ; printf '\n__DSH_JS_DONE_x:%s\n' "$?"
 *
 * That leading part is the USER's command, not connector bookkeeping — so it
 * must not be removed as an echo, and the caller removes it by matching the
 * script text it wrote. What this function removes is the part that is
 * unambiguously ours.
 */
function isEchoOnlyLine(line: string, token: string): boolean {
  const trimmed = line.trim()
  if (trimmed.length === 0) return false
  if (!trimmed.includes(token) && !trimmed.includes('__dsh_rc')) return false
  // Everything left on the line must be wrapper noise: the printf wrapper,
  // the rc capture, the semicolon between them, or quoting leftovers.
  const residue = trimmed
    .split(`printf '\\n${token}:%s\\n' "$?"`).join('')
    .split(`printf '\n${token}:%s\n' "$?"`).join('')
    .split(token).join('')
    .split('__dsh_rc=$?').join('')
    .split('__dsh_rc').join('')
    .replace(/["'();]/g, '')
    .replace(/\s+/g, '')
  return residue.length === 0
}

/** Remove the wrapper fragments from a line, keeping every other character. */
function stripWrapperFragments(line: string, token: string): string {
  return line
    .split(`printf '\\n${token}:%s\\n' "$?"`).join('')
    .split(`printf '\n${token}:%s\n' "$?"`).join('')
    .split(token).join('')
    .split('__dsh_rc=$?').join('')
    .split('__dsh_rc').join('')
}

/** Trim surrounding blank lines and guarantee exactly one trailing newline. */
function finalize(text: string): string {
  const trimmed = text.replace(/^[ \t]*\r?\n/, '').replace(/\s+$/, '')
  if (trimmed.length === 0) return ''
  return trimmed + '\n'
}

export { randomHex }
