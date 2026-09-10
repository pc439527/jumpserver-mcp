/**
 * Command-classifier corpus — Docker, Kubernetes, nginx, systemd, journalctl.
 *
 * Same contract as the other corpus files: the risk level is the assertion,
 * rule ids are not.
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

test('docker inspection commands are READ', () => {
  check([
    ['READ', 'docker ps'],
    ['READ', 'docker ps -a --format "{{.Names}}"'],
    ['READ', 'docker logs --tail 100 nginx'],
    ['READ', 'docker inspect nginx'],
    ['READ', 'docker stats --no-stream'],
  ])
})

test('docker mutations are not READ', () => {
  check([
    ['MODIFY', 'docker compose up -d'],
    ['MODIFY', 'docker rm -f nginx'],
    ['MODIFY', 'docker system prune -af'],
  ])
})

test('kubectl reads are READ', () => {
  check([
    ['READ', 'kubectl get pods -A'],
    ['READ', 'kubectl describe pod nginx-abc'],
    ['READ', 'kubectl logs -f deploy/nginx'],
  ])
})

test('kubectl delete is MODIFY', () => {
  check([['MODIFY', 'kubectl delete pod nginx-abc']])
})

test('nginx validation and config reads', () => {
  check([
    ['READ', 'nginx -t'],
    ['READ', 'cat /etc/nginx/nginx.conf'],
    ['READ', 'tail -n 200 /var/log/nginx/error.log'],
    // KNOWN GAP: `nginx -s reload` mutates runtime state. It is refused as
    // UNKNOWN rather than MODIFY — conservative and therefore safe, but the
    // operator copy should say "reload" rather than "unknown command".
    ['UNKNOWN', 'nginx -s reload'],
  ])
})

test('systemctl status / journalctl are READ', () => {
  check([
    ['READ', 'systemctl status nginx'],
    ['READ', 'journalctl -u nginx -n 100'],
    ['READ', 'journalctl -u nginx -f'],
  ])
})

test('systemctl start/stop/restart are MODIFY', () => {
  check([
    ['MODIFY', 'systemctl restart nginx'],
    ['MODIFY', 'systemctl stop firewalld'],
  ])
})

test('a stopped or masked unit is never reported as READ', () => {
  for (const command of ['systemctl disable nginx', 'systemctl mask nginx', 'systemctl kill nginx']) {
    assert.notEqual(classifyCommand(command).risk, 'READ', command + ' must not be READ')
  }
})
