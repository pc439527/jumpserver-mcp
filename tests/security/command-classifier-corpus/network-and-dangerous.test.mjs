/**
 * Command-classifier corpus — network inspection and the destructive cases.
 *
 * The destructive half is the important one: these are the commands where a
 * wrong READ verdict would let READ_ONLY mode run them unattended.
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

test('network inspection commands are READ', () => {
  check([
    ['READ', 'ss -lntp'],
    ['READ', 'netstat -tunlp'],
    ['READ', 'ip addr show'],
    ['READ', 'ping -c 4 8.8.8.8'],
    ['READ', 'traceroute 8.8.8.8'],
    ['READ', 'tcpdump -i eth0 -c 100 port 80'],
    ['READ', 'iptables -L -n'],
  ])
})

test('a GET-style curl is READ but a POST is not', () => {
  check([
    ['READ', 'curl -I http://localhost:8080'],
    ['READ', 'curl -s http://localhost:8080/health'],
    ['MODIFY', 'curl -X POST -d @payload.json http://api.example.com/v1/x'],
  ])
})

test('a curl that uploads a file is never READ', () => {
  for (const command of ['curl -T backup.tar http://backup.example.com/put', 'curl --data-binary @x.bin http://api/x']) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must not be READ')
  }
})

test('host-destroying commands are DANGEROUS', () => {
  check([
    ['DANGEROUS', 'rm -rf /'],
    ['DANGEROUS', 'chmod -R 777 /'],
    ['DANGEROUS', 'dd if=/dev/zero of=/dev/sda'],
    ['DANGEROUS', 'reboot'],
    ['DANGEROUS', 'shutdown -h now'],
    ['DANGEROUS', 'mkfs.ext4 /dev/sda1'],
    ['DANGEROUS', 'kill -9 -1'],
  ])
})

test('recursive deletion is MODIFY even when the path is not the root', () => {
  // `rm -rf /` is DANGEROUS (above). A wide deletion under a directory is
  // MODIFY: gated and audited, but not auto-refused. Recorded deliberately —
  // this is the boundary between "scary" and "irreversible host loss".
  check([
    ['MODIFY', 'rm -rf /var/log/*'],
    ['MODIFY', 'rm -f /tmp/old.log'],
  ])
})

test('opaque shell syntax is UNKNOWN, never READ', () => {
  check([
    ['UNKNOWN', 'bash -c "systemctl status nginx"'],
    ['UNKNOWN', 'echo $(whoami)'],
    ['UNKNOWN', 'python3 -c "import os"'],
  ])
})

test('an opaque wrapper can never launder a dangerous command into READ', () => {
  for (const command of [
    'bash -c "rm -rf /"',
    'sh -c "dd if=/dev/zero of=/dev/sda"',
    'echo "$(reboot)"',
  ]) {
    const risk = classifyCommand(command).risk
    assert.notEqual(risk, 'READ', command + ' must never be READ')
    assert.notEqual(risk, 'MODIFY', command + ' must never be downgraded to MODIFY')
  }
})
