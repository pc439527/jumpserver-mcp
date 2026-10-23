/**
 * Test helper: commands the RULE classifier genuinely cannot classify.
 *
 * The UNKNOWN branch is where the approval prompt, the semantic judge and
 * auto-allow all live. A test for that branch therefore needs a command the
 * rules do NOT cover — and when a rule IS added for it (an improvement, not a
 * regression), every such test silently stops exercising the branch it was
 * written for and starts reporting a failure that points at the wrong place.
 *
 * That is exactly what happened in V0.5.9: `lsnrctl status`, `showmount -e`,
 * `hdb info` and `sapcontrol -function GetProcessList` became READ, and nine
 * gate tests kept passing a command that never reached the gate ("Missing
 * expected rejection", "false !== true").
 *
 * So the samples are defined ONCE here and validated at import time: when one
 * of them stops being UNKNOWN, the failure says WHY on the spot instead of
 * surfacing as a mysterious assertion failure two files away.
 *
 * Deliberately NOT named `*.test.mjs` — run-tests.mjs collects every test file
 * it walks past, and this is infrastructure.
 */
import assert from 'node:assert/strict'
import { classifyCommand } from '../../lib/security/permission.js'

/**
 * Confirmed UNKNOWN against the rules as of V0.5.9. Any replacement must be a
 * command a real operator might type on a bastion — not an invented string —
 * so the fixture keeps representing reality.
 */
export const UNKNOWN_COMMANDS = ['pcs status', 'ceph -s', 'sapctl status']

/** The default sample; use when a test needs only one unclassified command. */
export const UNKNOWN_COMMAND = UNKNOWN_COMMANDS[0]

for (const command of UNKNOWN_COMMANDS) {
  const classified = classifyCommand(command)
  assert.equal(
    classified.risk,
    'UNKNOWN',
    'fixture drift: "' +
      command +
      '" is now classified ' +
      classified.risk +
      ' (rule ' +
      (classified.ruleId ?? '-') +
      '), so a test using it never reaches the UNKNOWN branch. Pick another unclassified command and update UNKNOWN_COMMANDS.',
  )
}
