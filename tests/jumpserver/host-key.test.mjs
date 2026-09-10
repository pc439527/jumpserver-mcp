/**
 * V0.5.0 SSH host-key verification (TOFU + optional pinning).
 *
 * These tests drive the verifier directly with synthetic host-key blobs — the
 * ssh2 handshake is not involved. The behaviour that matters is the decision:
 * a first contact is trusted and recorded, a matching contact passes silently,
 * and ANY contradiction is refused rather than silently re-trusted.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createHostKeyGuard,
  describeHostKeyRefusal,
  knownHostsKey,
  KnownHostsStore,
  matchesFingerprint,
  md5Fingerprint,
  parseKeyAlgorithm,
  sha256Fingerprint,
} from '../../lib/jumpserver/host-key.js'

/** Build an SSH host-key blob: uint32-prefixed algorithm name + raw key bytes. */
function blob(algorithm, seed) {
  const name = Buffer.from(algorithm, 'utf8')
  const payload = Buffer.alloc(32)
  for (let i = 0; i < payload.length; i += 1) payload[i] = (seed + i) & 0xff
  const head = Buffer.alloc(4)
  head.writeUInt32BE(name.length, 0)
  const size = Buffer.alloc(4)
  size.writeUInt32BE(payload.length, 0)
  return Buffer.concat([head, name, size, payload])
}

const ED25519_A = blob('ssh-ed25519', 7)
const ED25519_B = blob('ssh-ed25519', 99)

function tempStore() {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-knownhosts-'))
  return join(dir, 'known_hosts.json')
}

/* ------------------------------------------------------------ primitives */

test('parseKeyAlgorithm reads the algorithm out of the key blob', () => {
  assert.equal(parseKeyAlgorithm(ED25519_A), 'ssh-ed25519')
})

test('parseKeyAlgorithm refuses a truncated blob instead of guessing', () => {
  assert.equal(parseKeyAlgorithm(Buffer.alloc(2)), undefined)
  const bogus = Buffer.alloc(6)
  bogus.writeUInt32BE(50, 0)
  assert.equal(parseKeyAlgorithm(bogus), undefined, 'declared length exceeds the buffer')
})

test('sha256Fingerprint matches openssh formatting (no padding)', () => {
  const fp = sha256Fingerprint(ED25519_A)
  assert.ok(fp.startsWith('SHA256:'))
  assert.equal(fp.endsWith('='), false)
  const raw = createHash('sha256').update(ED25519_A).digest('base64').replace(/=+$/, '')
  assert.equal(fp, 'SHA256:' + raw)
})

test('matchesFingerprint accepts every format an operator may paste', () => {
  const base64 = sha256Fingerprint(ED25519_A)
  const hex = createHash('sha256').update(ED25519_A).digest('hex')
  assert.equal(matchesFingerprint(ED25519_A, base64), true, 'SHA256: form')
  assert.equal(matchesFingerprint(ED25519_A, base64.slice(7)), true, 'bare base64 form')
  assert.equal(matchesFingerprint(ED25519_A, hex), true, 'raw hex form')
  assert.equal(matchesFingerprint(ED25519_A, md5Fingerprint(ED25519_A)), true, 'legacy MD5 form')
  assert.equal(matchesFingerprint(ED25519_A, 'SHA256:AAAAinvalid'), false)
})

test('a fingerprint for another key never matches', () => {
  assert.equal(matchesFingerprint(ED25519_A, sha256Fingerprint(ED25519_B)), false)
})

/* ----------------------------------------------------------------- TOFU */

test('first contact is trusted and recorded (TOFU)', () => {
  const path = tempStore()
  const guard = createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path })
  assert.equal(guard.verifier(ED25519_A), true)
  const decision = guard.last()
  assert.equal(decision.outcome, 'tofu-recorded')
  assert.equal(decision.accept, true)
  assert.equal(decision.algorithm, 'ssh-ed25519')

  const stored = JSON.parse(readFileSync(path, 'utf8'))
  const record = stored.hosts[knownHostsKey('jump.example.com', 2222)]
  assert.ok(record, 'the key must be persisted')
  assert.equal(record.fingerprint, sha256Fingerprint(ED25519_A))
  assert.equal(record.source, 'tofu')
})

test('a repeat contact with the same key is accepted as known-match', () => {
  const path = tempStore()
  createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path }).verifier(ED25519_A)
  const second = createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path })
  assert.equal(second.verifier(ED25519_A), true)
  assert.equal(second.last().outcome, 'known-match')
})

test('a changed host key is REFUSED and the refusal is explained', () => {
  const path = tempStore()
  createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path }).verifier(ED25519_A)
  const second = createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path })
  assert.equal(second.verifier(ED25519_B), false, 'a changed key must not be auto-trusted')
  const decision = second.last()
  assert.equal(decision.outcome, 'mismatch')
  assert.equal(decision.expected, sha256Fingerprint(ED25519_A))
  assert.equal(decision.fingerprint, sha256Fingerprint(ED25519_B))
  assert.match(describeHostKeyRefusal(decision), /host key changed/)
})

test('a refused key is NOT written over the recorded one', () => {
  const path = tempStore()
  createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path }).verifier(ED25519_A)
  createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path }).verifier(ED25519_B)
  const stored = JSON.parse(readFileSync(path, 'utf8'))
  assert.equal(
    stored.hosts[knownHostsKey('jump.example.com', 2222)].fingerprint,
    sha256Fingerprint(ED25519_A),
    'the original record must survive so the next attempt still fails loudly',
  )
})

/* --------------------------------------------------------------- pinning */

test('a pinned fingerprint accepts a match', () => {
  const guard = createHostKeyGuard({
    host: 'jump.example.com',
    port: 2222,
    fingerprint: sha256Fingerprint(ED25519_A),
  })
  assert.equal(guard.verifier(ED25519_A), true)
  assert.equal(guard.last().outcome, 'pinned-match')
})

test('a pinned fingerprint refuses anything else, even on first contact', () => {
  const guard = createHostKeyGuard({
    host: 'jump.example.com',
    port: 2222,
    fingerprint: sha256Fingerprint(ED25519_A),
  })
  assert.equal(guard.verifier(ED25519_B), false)
  assert.equal(guard.last().outcome, 'pinned-mismatch')
  assert.match(describeHostKeyRefusal(guard.last()), /pinned fingerprint/)
})

test('pinning wins over a stale known_hosts record', () => {
  const path = tempStore()
  // Record B from an earlier (unpinned) contact, then pin A.
  createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path }).verifier(ED25519_B)
  const pinned = createHostKeyGuard({
    host: 'jump.example.com',
    port: 2222,
    storePath: path,
    fingerprint: sha256Fingerprint(ED25519_A),
  })
  assert.equal(pinned.verifier(ED25519_A), true, 'the pin is authoritative')
})

test('a blank pin is treated as "not configured"', () => {
  const path = tempStore()
  const guard = createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path, fingerprint: '   ' })
  assert.equal(guard.verifier(ED25519_A), true)
  assert.equal(guard.last().outcome, 'tofu-recorded')
})

/* ------------------------------------------------------------ store edge */

test('without a store the key is accepted but reported as unrecorded', () => {
  const guard = createHostKeyGuard({ host: 'jump.example.com', port: 2222 })
  assert.equal(guard.verifier(ED25519_A), true)
  assert.equal(guard.last().outcome, 'tofu-unrecorded')
})

test('hosts are tracked per host:port, so two bastions do not collide', () => {
  const path = tempStore()
  const store = new KnownHostsStore(path)
  store.put(knownHostsKey('a.example.com', 2222), { fingerprint: 'SHA256:x', firstSeenAt: 'now', source: 'tofu' })
  store.put(knownHostsKey('a.example.com', 2200), { fingerprint: 'SHA256:y', firstSeenAt: 'now', source: 'tofu' })
  assert.equal(store.get(knownHostsKey('a.example.com', 2222)).fingerprint, 'SHA256:x')
  assert.equal(store.get(knownHostsKey('a.example.com', 2200)).fingerprint, 'SHA256:y')
  assert.equal(store.get(knownHostsKey('b.example.com', 2222)), undefined)
})

test('host keys are matched case-insensitively', () => {
  assert.equal(knownHostsKey('Jump.Example.COM', 2222), knownHostsKey('jump.example.com', 2222))
})

test('a corrupt known_hosts file degrades to empty instead of crashing', () => {
  const path = tempStore()
  writeFileSync(path, '{ this is not json', 'utf8')
  const guard = createHostKeyGuard({ host: 'jump.example.com', port: 2222, storePath: path })
  assert.equal(guard.verifier(ED25519_A), true, 'a broken sidecar must not brick the connector')
  assert.equal(guard.last().outcome, 'tofu-recorded')
  const repaired = JSON.parse(readFileSync(path, 'utf8'))
  assert.ok(repaired.hosts[knownHostsKey('jump.example.com', 2222)], 'the next write repairs the file')
})

test('a known_hosts file with a non-object hosts field is treated as empty', () => {
  const path = tempStore()
  writeFileSync(path, JSON.stringify({ version: 1, hosts: 'nope' }), 'utf8')
  const store = new KnownHostsStore(path)
  assert.equal(store.get(knownHostsKey('jump.example.com', 2222)), undefined)
})
