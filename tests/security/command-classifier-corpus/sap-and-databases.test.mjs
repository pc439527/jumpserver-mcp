/**
 * Command-classifier corpus — SAP / HANA / Oracle / Redis.
 *
 * These are the commands this connector's operator actually types. The
 * assertion is deliberately limited to the RISK LEVEL: `ruleId` is an
 * implementation detail that changes as rules land, but a risk level is a
 * security promise, so that is what gets frozen.
 *
 * A `KNOWN GAP` block records a READ-ONLY command the classifier has no rule
 * for. It currently reports UNKNOWN, which keeps READ_ONLY mode closed around
 * it — safe, but inconvenient. Recording it here means the day someone adds
 * the rule, this file fails and the change becomes a deliberate decision
 * instead of a silent behaviour shift.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyCommand } from '../../../lib/security/command-classifier.js'

function check(rows) {
  for (const [expected, command] of rows) {
    const actual = classifyCommand(command).risk
    assert.equal(actual, expected, command + ' should be ' + expected + ', got ' + actual)
  }
}

test('SAP host commands the classifier must confirm as READ', () => {
  check([
    ['READ', 'df -h'],
    ['READ', 'du -sh /hana/data'],
    ['READ', 'free -m'],
    ['READ', 'uptime'],
    ['READ', 'cat /usr/sap/LH00/HDB00/work/dev_w0/M_services.trc'],
  ])
})

test('SAP HANA-specific binaries are UNKNOWN — KNOWN GAP', () => {
  // Read-only in practice (HDB info / sapcontrol GetProcessList), but HDB and
  // sapcontrol also have mutating verbs (HDB stop, sapcontrol Start), so a
  // blanket READ rule would be wrong. A verb-aware rule is the fix.
  check([
    ['UNKNOWN', 'HDB info'],
    ['UNKNOWN', 'HDB version'],
    ['UNKNOWN', 'sapcontrol -nr 00 -function GetProcessList'],
  ])
})

test('switching user through su is UNKNOWN (the inner command is opaque)', () => {
  check([['UNKNOWN', 'su - lh00adm -c "HDB info"']])
})

test('Oracle host commands', () => {
  check([
    ['READ', 'ps -ef | grep pmon'],
    ['READ', 'cat /u01/app/oracle/diag/rdbms/orcl/trace/alert_orcl.log'],
    // KNOWN GAP: lsnrctl status is read-only; lsnrctl also has mutating verbs
    // (stop / reload), so this needs a verb-aware rule rather than a blanket READ.
    ['UNKNOWN', 'lsnrctl status'],
    // sqlplus can run arbitrary SQL, including DDL — UNKNOWN is correct here.
    ['UNKNOWN', 'sqlplus -s / as sysdba'],
  ])
})

test('redis-cli read verbs are READ', () => {
  check([
    ['READ', 'redis-cli info memory'],
    ['READ', 'redis-cli -a secret ping'],
    ['READ', 'redis-cli config get maxmemory'],
  ])
})

test('a redis-cli mutation is not READ', () => {
  const risk = classifyCommand('redis-cli flushall').risk
  assert.notEqual(risk, 'READ', 'flushall must never be classified read-only')
})
