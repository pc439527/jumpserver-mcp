/**
 * Command-classifier corpus — V0.7.0 (batch C): approval classification
 * accuracy.
 *
 * This file freezes the behaviour that batch C changed. Every row is a real
 * command from the audit corpus (data/audit.jsonl), and every row is a
 * SAFETY PROMISE, not an implementation detail:
 *
 *  - a read-only command must not be blocked (the whole point of the batch);
 *  - a writing command must never be released (the hard gate).
 *
 * The corpus is organised by the ROOT CAUSE of the misclassification, not by
 * the tool, because every root cause had a structural defect behind it:
 *
 *  1. form vs word        — `crontab -l` vs `crontab -e`
 *  2. verb position       — `kubectl -n ns patch` vs `kubectl -n ns get`
 *  3. substitution        — `$(...)` is executed, so it is analysed
 *  4. shell structure     — `for`/`while`/`done`/`<` are syntax, not commands
 *  5. option clusters     — `tar czf` is `-c -z -f`
 *  6. escaped names       — `\cp` is still `cp`
 */
import test from 'node:test'
import assert from 'node:assert/strict'
// The AUTHORITATIVE classifier is the chain in permission.ts
// (mysql/mariadb and hdbsql are classified BEFORE the generic shell
// classifier). Importing the base classifier directly would miss the whole
// database-CLI part of the contract.
import { classifyCommand } from '../../../lib/security/permission.js'

function check(rows) {
  for (const [expected, command] of rows) {
    const actual = classifyCommand(command).risk
    assert.equal(actual, expected, command + ' should be ' + expected + ', got ' + actual)
  }
}

// ---------------------------------------------------------------- form vs word

test('crontab is classified by its FORM, not by the word', () => {
  check([
    ['READ', 'crontab -l'],
    ['READ', 'crontab -l -u weaver'],
    ['READ', 'crontab -l 2>/dev/null | head -10'],
    ['MODIFY', 'crontab -e'],
    ['MODIFY', 'crontab -r'],
    // A bare `crontab` installs a crontab from stdin.
    ['MODIFY', 'crontab'],
  ])
})

test('a crontab listing is not a modification, but the file copy is', () => {
  // The two forms look alike in the audit log; only the form decides.
  assert.equal(classifyCommand('cat /etc/crontab').risk, 'READ')
  assert.equal(classifyCommand('head -60 /etc/crontab').risk, 'READ')
  assert.equal(classifyCommand('ls -l /etc/crontab').risk, 'READ')
})

// -------------------------------------------------------------- verb position

test('the kubectl verb is found behind global flags', () => {
  check([
    ['READ', 'kubectl -n default get pod -o wide'],
    ['READ', 'kubectl --namespace=kube-system get pods'],
    // A mutation behind global flags must NOT degrade to "unknown".
    ['MODIFY', 'kubectl -n kube-system patch configmap coredns --type merge -p "{}"'],
    ['MODIFY', 'kubectl -n default delete pod foo'],
  ])
})

// -------------------------------------------------------------- substitution

test('a command substitution is analysed recursively', () => {
  check([
    ['READ', 'T=$(grep -c . /var/log/app.log); echo "T=$T"'],
    ['READ', 'SS=$(grep -E "^-. [0-9]{5}" /var/log/app.log | grep -c synccache); echo "$SS"'],
    ['READ', 'echo "$(hostname)"'],
    // The literal text in single quotes is NOT executed.
    ['READ', "echo 'literal $(notcmd)'"],
  ])
})

test('a substitution body that is unanalysable or writing is never released', () => {
  for (const command of [
    'x=$(some-unknown-cli)',
    'x=$(rm -f /tmp/a)',
    'x=$(dd if=/dev/zero of=/dev/sda)',
    'kubectl exec pod -- sh -c "x=$(some-unknown-cli)"',
    'kubectl exec pod -- sh -c "x=$(rm -f /tmp/a)"',
    'kubectl exec pod -- sh -c "x=$(dd if=/dev/zero of=/dev/sda)"',
  ]) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must never be read-only')
  }
})

// ------------------------------------------------------------ shell structure

test('shell syntax is not mistaken for a command', () => {
  check([
    ['READ', 'for f in /tmp/*.log; do echo "$f"; done'],
    ['READ', 'while IFS= read -r p; do echo "$p"; done < /tmp/list'],
    ['READ', 'if [ -f /etc/hosts ]; then echo present; fi'],
    ['READ', '[ -f /etc/hosts ]'],
    // `done < file` is a redirection, not a command.
    ['READ', 'while read p; do echo "$p"; done < /tmp/list'],
  ])
})

test('a redirection after a shell keyword still writes when it writes', () => {
  assert.equal(classifyCommand('done > /tmp/out').risk, 'MODIFY')
  assert.equal(classifyCommand('x > /tmp/out').risk, 'MODIFY')
  assert.equal(classifyCommand('x < /tmp/in').risk, 'UNKNOWN')
})

test('a group opener does not hide the command inside it', () => {
  check([
    ['READ', '(docker ps --format "{{.Names}}" 2>/dev/null | head -40 || echo NO_DOCKER)'],
    ['READ', 'hostname && date && (docker ps 2>/dev/null | head -40 || echo NO_DOCKER)'],
  ])
})

// ------------------------------------------------------------ option clusters

test('a bundled short-option cluster is recognised', () => {
  // `tar czf` is `-c -z -f`; matching only `-c` missed the create.
  check([
    ['MODIFY', 'tar czf out.tar.gz dir'],
    ['MODIFY', 'tar -czf out.tar.gz dir'],
    ['MODIFY', 'tar xzf in.tar.gz'],
    ['MODIFY', 'tar -xzf in.tar.gz'],
    ['READ', 'tar tf in.tar.gz'],
  ])
})

test('an escaped command name is still the command', () => {
  // `\cp` is the letter c followed by p: the backslash only escapes the `c`.
  assert.equal(classifyCommand('\\cp -r /a /b/').risk, 'MODIFY')
})

// ------------------------------------------------------- read-only additions

test('the read-only tools of the audit corpus are confirmed readers', () => {
  check([
    ['READ', 'cd /data/crm_export && ls -la'],
    ['READ', 'printf "%s-%s\\n" a b'],
    ['READ', 'bash -n /usr/weaver/Resin4/bin/resin_healthcheck.sh'],
    ['READ', 'mysqldumpslow -s t -t 12 /var/log/mysql/mysql-slow.log'],
    ['READ', 'ifconfig eth0'],
    ['READ', '/sbin/ifconfig eth0'],
    ['READ', 'zgrep -c synccache /var/log/access.log.gz'],
    ['READ', 'pgrep -a java'],
    ['READ', 'nmcli dev show ens192'],
    ['READ', 'nmcli device show ens192'],
    ['READ', 'openssl x509 -in /etc/a.pem -noout -dates -subject'],
    ['READ', 'mysql --version'],
    ['READ', 'time mysql -uroot -pxxx db -N -e "select 1"'],
    ['READ', 'mysql -uroot -pxxx db -N -e "select 1" 2>/dev/null'],
  ])
})

test('the writing counterparts of the new readers stay writing', () => {
  check([
    ['MODIFY', 'openssl x509 -in /etc/a.pem -out /tmp/b.pem'],
    ['MODIFY', 'stty cols 300'],
    ['MODIFY', 'hdbuserstore create -u someone'],
    ['MODIFY', 'exportfs'],
    ['MODIFY', 'mysql -uroot -pxxx db -e "ANALYZE TABLE t"'],
  ])
})

test('the SAP query functions are read, the SAP state functions are not', () => {
  check([
    ['READ', 'sapcontrol -nr 00 -function GetProcessList'],
    ['READ', 'sapcontrol -nr 01 -function EnqGetStatistic'],
    ['READ', 'hdbuserstore list'],
    ['READ', '/usr/sap/SHP/HDB00/exe/hdbuserstore list'],
    ['MODIFY', 'sapcontrol -nr 00 -function StartInstance'],
  ])
})

test('awk comparison operators are not mistaken for redirections', () => {
  // `if(index($0,"x")>0)` compares; `print > "f"` redirects.
  check([
    ['READ', "awk '{s+=$2; if($2>m)m=$2; n++} END {print n}' /var/log/app.log"],
    ['READ', "awk '{b=int($2/1000); if(b>15)b=16; c[b]++} END{for(i=0;i<=16;i++) print i}' /var/log/app.log"],
    ['MODIFY', "awk '{print $1 > \"out.txt\"}' /var/log/app.log"],
  ])
})

test('the database CLI still refuses a redirection to a real file', () => {
  // `2>/dev/null` is harmless, `> out.txt` writes a file.
  assert.equal(classifyCommand('mysql -uroot -pxxx db -N -e "select 1" 2>/dev/null').risk, 'READ')
  assert.notEqual(classifyCommand('mysql -uroot -pxxx db -N -e "select 1" > out.txt').risk, 'READ')
})
