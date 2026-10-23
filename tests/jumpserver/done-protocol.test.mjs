/**
 * V0.7.1 (D-4): the completion protocol must survive a REAL PTY capture.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The connector had a silent data-loss bug: a command whose output has NO
 * trailing newline lost its output entirely. The live bastion showed it on
 * 2026-10-23 — `printf 'NOEOL'` returned the echoed command and nothing
 * else, because:
 *
 *   1. the old done-script embedded REAL newlines inside the printf format,
 *      so bash read it as a MULTI-line command and printed `> ` continuation
 *      prompts into the middle of the output;
 *   2. the PTY echoed the script back, and the echoed line contained the
 *      completion marker, so a substring match could fire on the ECHO —
 *      declaring the command finished before it had run;
 *   3. the output without a trailing newline got glued to the prompt and to
 *      the echoed bookkeeping, and the cleaner dropped that whole line.
 *
 * The fixtures below are VERBATIM captures from the live bastion
 * (192.168.74.130 -> 192.168.30.116, account 欧建达/114976), taken with
 * the connector's own session code on 2026-10-23. They are the regression
 * net for that whole chain.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  buildDoneScript,
  canAppendInline,
  cleanCommandOutput,
  doneMarkerPattern,
  parseDoneLine,
  probeMarkerPattern,
} from '../../lib/jumpserver/command-runner.js'

/** The real capture of `printf 'NOEOL'` BEFORE the fix (v0.7.0 script). */
const RAW_NO_NEWLINE_OLD = [
  "printf 'NOEOL'\r\n",
  '[?2004l\rNOEOL[?2004h]0;root@S030116: ~',
  'root@S030116:~# __dsh_rc=$?\r\n',
  '[?2004l\r[?2004h]0;root@S030116: ~root@S030116:~# printf \'\r\n',
  '[?2004l\r[?2004h> __DSH_JS_DONE_508D68DB:%s\r\n',
  '[?2004l\r[?2004h> \' "$__dsh_rc"\r\n',
  '[?2004l\r\r\n__DSH_JS_DONE_508D68DB:0\r\n',
  '[?2004h]0;root@S030116: ~root@S030116:~# ',
].join('')

/** The real capture of `printf 'NOEOL'` AFTER the fix (v0.7.1 script). */
const RAW_NO_NEWLINE_NEW = [
  "printf 'NOEOL' ; printf '\\n__DSH_JS_DONE_FF9E4F07:%s\\n' \"$?\"\r\n",
  '[?2004l\rNOEOL\r\n__DSH_JS_DONE_FF9E4F07:0\r\n',
  '[?2004h]0;root@S030116: ~root@S030116:~# ',
].join('')

/** A real capture of a normal command with a trailing newline. */
const RAW_NORMAL = [
  "echo HELLO ; printf '\\n__DSH_JS_DONE_1A2B3C4D:%s\\n' \"$?\"\r\n",
  '[?2004l\rHELLO\r\n__DSH_JS_DONE_1A2B3C4D:0\r\n',
  '[?2004h]0;root@S030116: ~root@S030116:~# ',
].join('')

// ---------------------------------------------------------------------------
// D-4: the completion criterion
// ---------------------------------------------------------------------------

test('the done marker must start a line and carry digits', () => {
  const pattern = doneMarkerPattern('508D68DB')
  // The real marker: line-anchored + digits -> matches.
  assert.ok(pattern.test('\n__DSH_JS_DONE_508D68DB:0'))
  // The ECHO of the connector's own script: mid-line + %s -> must NOT match.
  assert.equal(pattern.test("printf '\\n__DSH_JS_DONE_508D68DB:%s\\n' \"$?\""), false)
  // A marker that does not start a line -> must NOT match.
  assert.equal(pattern.test('xx__DSH_JS_DONE_508D68DB:0'), false)
  // A marker with no digits -> must NOT match.
  assert.equal(pattern.test('\n__DSH_JS_DONE_508D68DB:%s'), false)
})

test('parseDoneLine reads the exit code but ignores the echoed marker', () => {
  assert.deepEqual(parseDoneLine('\n__DSH_JS_DONE_508D68DB:0', '508D68DB'), { exitCode: 0 })
  assert.deepEqual(parseDoneLine('\n__DSH_JS_DONE_508D68DB:127', '508D68DB'), { exitCode: 127 })
  // The echo carries %s -> not a completion.
  assert.equal(parseDoneLine("printf '\\n__DSH_JS_DONE_508D68DB:%s\\n'", '508D68DB'), null)
})

test('the probe marker is line-anchored too', () => {
  const pattern = probeMarkerPattern('58766F')
  assert.ok(pattern.test('\n__DSH_JS_PROBE_58766F'))
  // The echoed copy sits mid-line -> must NOT match.
  assert.equal(pattern.test("printf '__DSH_JS_PROBE_58766F\\n'"), false)
})

// ---------------------------------------------------------------------------
// D-4: the data-loss regression (the whole point of this file)
// ---------------------------------------------------------------------------

test('REGRESSION: output without a trailing newline is NOT lost (real capture)', () => {
  // The session layer passes the exact script it wrote, so the echo can be
  // removed as a whole line — mirror that here.
  const script = buildDoneScript("printf 'NOEOL'", 'FF9E4F07')
  const out = cleanCommandOutput(RAW_NO_NEWLINE_NEW, 'FF9E4F07', script)
  assert.ok(out.includes('NOEOL'), 'the real output must survive: got ' + JSON.stringify(out))
  assert.equal(out.includes('__DSH_JS_DONE_'), false, 'the marker must not leak')
  assert.equal(out.includes('printf'), false, 'the echoed script must not leak')
  assert.ok(out.endsWith('\n'), 'the output must end with a newline')
})

test('the OLD capture kept its output too — the cleaner no longer drops glued lines', () => {
  // The old protocol echoed the script as MULTIPLE lines (`> ` continuation
  // prompts), so the real output was glued to the prompt and to the echoed
  // `__dsh_rc=$?`. The old cleaner dropped that whole line and the output was
  // LOST. The new cleaner removes only the connector's own fragments, so the
  // output survives even for a capture produced by the old protocol.
  const out = cleanCommandOutput(RAW_NO_NEWLINE_OLD, '508D68DB')
  assert.ok(out.includes('NOEOL'), 'the output must survive: got ' + JSON.stringify(out))
  assert.equal(out.includes('__DSH_JS_DONE_'), false, 'the marker must not leak')
  assert.equal(out.includes('__dsh_rc'), false, 'the rc capture must not leak')
})

test('a normal command keeps its output and drops the bookkeeping', () => {
  const out = cleanCommandOutput(RAW_NORMAL, '1A2B3C4D')
  assert.ok(out.includes('HELLO'))
  assert.equal(out.includes('__DSH_JS_DONE_'), false)
  assert.equal(out.includes('printf'), false)
})

test('multi-line output survives intact', () => {
  const raw = [
    "ls ; printf '\\n__DSH_JS_DONE_AAAA:%s\\n' \"$?\"\r\n",
    '[?2004l\rtotal 4\r\ndrwxr-xr-x 2 root root 4096 .\r\n__DSH_JS_DONE_AAAA:0\r\n',
  ].join('')
  const out = cleanCommandOutput(raw, 'AAAA')
  assert.ok(out.includes('total 4'))
  assert.ok(out.includes('drwxr-xr-x'))
  assert.equal(out.includes('__DSH_JS_DONE_'), false)
})

// ---------------------------------------------------------------------------
// D-4: the script shape
// ---------------------------------------------------------------------------

test('the done script is ONE line for an ordinary command', () => {
  const script = buildDoneScript('printf \'NOEOL\'', 'FF9E4F07')
  assert.equal(script.includes('\n'), false, 'a multi-line script makes bash print `> ` continuation prompts')
  assert.ok(script.includes('"$?"'), 'the exit code must be captured')
})

test('the script keeps a literal backslash-n, never a real newline', () => {
  const script = buildDoneScript('echo hi', 'FF9E4F07')
  assert.ok(script.includes('\\n'), 'printf must receive a literal backslash-n')
  assert.equal(script.includes('\n'), false)
})

test('a command with an unquoted # falls back to a brace group', () => {
  // The inline form would be swallowed by the comment.
  assert.equal(canAppendInline('ls # comment'), false)
  const script = buildDoneScript('ls # comment', 'FF9E4F07')
  assert.ok(script.includes('{'), 'the fallback must use a brace group')
})

test('a command with a quoted # is still safe inline', () => {
  assert.equal(canAppendInline("grep '#' file"), true)
})

test('a backgrounded command is not appended inline', () => {
  assert.equal(canAppendInline('sleep 1 &'), false)
})

test('a trailing incomplete operator is not appended inline', () => {
  assert.equal(canAppendInline('cat file |'), false)
  assert.equal(canAppendInline('cat file >'), false)
})

test('&& and || are safe inline', () => {
  assert.equal(canAppendInline('a && b'), true)
  assert.equal(canAppendInline('a || b'), true)
})

test('a trailing semicolon is normalized away', () => {
  const script = buildDoneScript('echo hi ;', 'FF9E4F07')
  assert.equal(script.includes(';;'), false, 'a doubled semicolon is a syntax error')
})
