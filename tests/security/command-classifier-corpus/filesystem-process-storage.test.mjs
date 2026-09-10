/**
 * Command-classifier corpus — the filesystem / process / storage commands an
 * ops engineer reaches for during an incident.
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

test('read-only file inspection is READ', () => {
  check([
    ['READ', 'find /var/log -name "*.log" -mtime +7'],
    ['READ', 'grep -rn "ERROR" /var/log/nginx/'],
    ['READ', "awk '{print $1}' /var/log/nginx/access.log"],
    ['READ', 'sed -n "1,20p" /etc/hosts'],
    ['READ', 'wc -l /var/log/syslog'],
    ['READ', 'ls -la /opt'],
    ['READ', 'head -n 50 /etc/passwd'],
  ])
})

test('sed -i is MODIFY while sed without -i stays READ', () => {
  check([
    ['READ', 'sed -n "1,20p" /etc/hosts'],
    ['MODIFY', 'sed -i "s/a/b/" /etc/hosts'],
  ])
})

test('file mutations are MODIFY', () => {
  check([
    ['MODIFY', 'rm -f /tmp/old.log'],
    ['MODIFY', 'mv /tmp/a /tmp/b'],
    ['MODIFY', 'cp /etc/hosts /tmp/hosts.bak'],
    ['MODIFY', 'chmod 644 /etc/hosts'],
    ['MODIFY', 'echo hello > /tmp/x'],
    ['MODIFY', 'mkdir -p /tmp/newdir'],
  ])
})

test('find with -delete or -exec is never READ', () => {
  // A read-looking search tool becomes a mutation amplifier in one flag.
  for (const command of ['find /tmp -name "*.tmp" -delete', 'find / -name "x" -exec rm {} \\;']) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must not be READ')
  }
})

test('process inspection is READ', () => {
  check([
    ['READ', 'ps aux'],
    ['READ', 'top -bn1'],
    ['READ', 'lsof -i :8080'],
    ['READ', 'jps -l'],
  ])
})

test('jstack is UNKNOWN — KNOWN GAP', () => {
  // jstack only dumps thread stacks; it belongs with `jps` as READ. It is a
  // gap, not a hazard: UNKNOWN keeps READ_ONLY mode closed, so the cost is an
  // extra approval, never an unguarded execution.
  check([['UNKNOWN', 'jstack 12345']])
})

test('storage inspection is READ', () => {
  check([
    ['READ', 'mount | grep nfs'],
    ['READ', 'nfsstat -m'],
    ['READ', 'lsblk'],
    ['READ', 'fdisk -l'],
  ])
})

test('showmount is UNKNOWN — KNOWN GAP', () => {
  // `showmount -e` is a read-only NFS export listing; `showmount -a` is too.
  check([['UNKNOWN', 'showmount -e 10.0.0.5']])
})

test('filesystem-formatting commands are DANGEROUS, not merely MODIFY', () => {
  check([['DANGEROUS', 'mkfs.ext4 /dev/sdb1']])
})

test('a disk-exhausting or unbounded copy is never READ', () => {
  for (const command of ['cp -r / /mnt/backup', 'truncate -s 0 /var/log/syslog']) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must not be READ')
  }
})
