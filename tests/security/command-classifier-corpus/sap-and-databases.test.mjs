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

test('SAP HANA binaries are classified by verb', () => {
  // V0.5.9: the KNOWN GAP recorded here is CLOSED. The verb-aware rules landed
  // exactly where this comment predicted they would be needed.
  //
  // NOTE (V0.5.2): this file exercises the GENERIC classifier directly, where
  // hdbsql is legitimately UNKNOWN. `hdbsql` IS covered — but by the
  // database-CLI chain in permission.ts, which runs BEFORE this classifier.
  // Its contract lives in ../sql-command-classifier.test.mjs.
  check([
    ['READ', 'HDB info'],
    ['READ', 'HDB version'],
    ['READ', 'sapcontrol -nr 00 -function GetProcessList'],
    ['READ', 'sapcontrol -nr 00 -function GetVersionInfo'],
    ['READ', 'sapcontrol -nr 00 -function GetAlertTree'],
  ])
})

test('SAP HANA mutating verbs are never READ', () => {
  for (const command of [
    'HDB stop',
    'HDB start',
    'sapcontrol -nr 00 -function Stop',
    'sapcontrol -nr 00 -function RestartInstance',
  ]) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must never be read-only')
  }
  // An unrecognised -function is a refusal, not a guess.
  assert.equal(classifyCommand('sapcontrol -nr 00 -function DoSomethingNew').risk, 'UNKNOWN')
})

test('switching user through su is UNKNOWN (the inner command is opaque)', () => {
  check([['UNKNOWN', 'su - lh00adm -c "HDB info"']])
})

test('Oracle host commands', () => {
  check([
    ['READ', 'ps -ef | grep pmon'],
    ['READ', 'cat /u01/app/oracle/diag/rdbms/orcl/trace/alert_orcl.log'],
    // V0.5.9: the KNOWN GAP is closed — `lsnrctl status` only queries state.
    ['READ', 'lsnrctl status'],
    // sqlplus can run arbitrary SQL, including DDL — UNKNOWN is correct here.
    ['UNKNOWN', 'sqlplus -s / as sysdba'],
  ])
})

test('lsnrctl mutations are never READ, and a bare lsnrctl stays unknown', () => {
  for (const command of ['lsnrctl stop', 'lsnrctl reload', 'lsnrctl set log_status off']) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must never be read-only')
  }
  // No verb = an interactive shell that can do anything.
  assert.equal(classifyCommand('lsnrctl').risk, 'UNKNOWN')
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
