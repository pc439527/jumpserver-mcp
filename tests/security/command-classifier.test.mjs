/**
 * Classifier contract tests — the classifier is the component that must never
 * be changed "by feel". Every expectation here is a safety property, not an
 * implementation detail; a failure means a command could run with the wrong
 * gate.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyCommand, CLASSIFIER_VERSION } from '../../lib/security/command-classifier.js'

const MATRIX = [
  // [command, expected risk]
  ['free -m', 'READ'],
  ['ss -lntp', 'READ'],
  ['sudo ss -lntp', 'PRIVILEGED_READ'],
  ['systemctl status nginx', 'READ'],
  ['systemctl restart nginx', 'MODIFY'],
  ['curl https://example.com/health', 'READ'],
  ['curl -X POST -d a https://example.com/api', 'MODIFY'],
  ['rm -rf /', 'DANGEROUS'],
  ['unknown-company-cli xxx', 'UNKNOWN'],
  // V0.4.0 inspect profiles rely on these
  ['jps -lv', 'READ'],
  ['nginx -T', 'READ'],
  ['docker ps', 'READ'],
  ['ps -eo pid,ppid,user,%cpu,%mem,etime,args', 'READ'],
  ['ip -o addr', 'READ'],
  ['cat /etc/hosts', 'READ'],
  ['systemctl --type=service --state=running', 'READ'],
]

for (const [command, risk] of MATRIX) {
  test('classify: ' + command + ' => ' + risk, () => {
    const result = classifyCommand(command)
    assert.equal(result.risk, risk, 'command=' + command + ' rule=' + result.ruleId + ' reason=' + result.reason)
  })
}

test('sudo never downgrades the inner command', () => {
  assert.equal(classifyCommand('sudo cat /etc/shadow').risk, 'PRIVILEGED_READ')
  assert.equal(classifyCommand('cat /etc/shadow').risk, 'READ')
})

test('every classification is explainable and versioned', () => {
  for (const [command] of MATRIX) {
    const result = classifyCommand(command)
    assert.ok(result.ruleId.length > 0, command + ' has no ruleId')
    assert.ok(result.reason.length > 0, command + ' has no reason')
    assert.equal(result.classifierVersion, CLASSIFIER_VERSION)
    assert.ok(['HIGH', 'LOW'].includes(result.confidence))
    assert.equal(result.normalizedCommand, command.replace(/\s+/g, ' ').trim())
  }
})

test('empty command is never treated as safe', () => {
  assert.equal(classifyCommand('   ').risk, 'UNKNOWN')
})

test('a pipeline is classified by its worst segment', () => {
  assert.equal(classifyCommand('cat /var/log/app.log | grep ERROR').risk, 'READ')
  assert.equal(classifyCommand('cat /var/log/app.log | systemctl restart nginx').risk, 'MODIFY')
})
