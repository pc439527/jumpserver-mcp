/**
 * CredentialVault: AES-256-GCM sealing of a profile password.
 * Every test works inside its own temp directory — the real
 * ~/.workbuddy/jumpserver-mcp/vault.key is never read or created here.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CredentialVault } from '../../lib/security/credential-vault.js'

async function withVault(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'js-vault-'))
  const keyPath = join(dir, 'vault.key')
  try {
    await fn({ dir, keyPath, vault: new CredentialVault({ keyPath }) })
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined)
  }
}

// Flip one bit of a base64 segment so it stays well-formed but decrypts wrong.
function flipSegment(segment) {
  const buf = Buffer.from(segment, 'base64')
  const copy = Buffer.alloc(buf.length, 0)
  buf.copy(copy)
  copy[0] = copy[0] ^ 0x01
  return copy.toString('base64')
}

test('round-trips plain, unicode and separator-heavy payloads', async () => {
  await withVault(async ({ vault }) => {
    const payloads = ['', 'p@ss:word', '生产维护账号口令', 'a:b\nc\r\n', ':'.repeat(8), 'x'.repeat(4096)]
    for (const payload of payloads) {
      const token = vault.encrypt(payload)
      assert.equal(typeof token, 'string')
      assert.equal(vault.decrypt(token), payload)
    }
  })
})

test('first encrypt creates a 32-byte key file and never reuses an IV', async () => {
  await withVault(async ({ keyPath, vault }) => {
    const first = vault.encrypt('same-secret')
    const second = vault.encrypt('same-secret')
    assert.notEqual(first, second, 'iv must be random per call')
    assert.equal(vault.decrypt(first), 'same-secret')
    assert.equal(vault.decrypt(second), 'same-secret')

    const key = await readFile(keyPath)
    assert.equal(key.length, 32, 'key file must hold exactly 32 bytes')
    assert.equal((await stat(keyPath)).size, 32)
    assert.equal(vault.isAvailable(), true)
  })
})

test('a second vault instance with the same key file decrypts existing tokens', async () => {
  await withVault(async ({ keyPath, vault }) => {
    const token = vault.encrypt('hand-off')
    const other = new CredentialVault({ keyPath })
    assert.equal(other.decrypt(token), 'hand-off')
  })
})

test('a different key cannot decrypt the token (returns null)', async () => {
  await withVault(async ({ dir, vault }) => {
    const token = vault.encrypt('cross-key')
    const foreign = new CredentialVault({ keyPath: join(dir, 'other.key') })
    assert.equal(foreign.decrypt(token), null)
  })
})

test('tampering with any segment yields null instead of throwing', async () => {
  await withVault(async ({ vault }) => {
    const token = vault.encrypt('tamper-me')
    const parts = token.split(':')
    assert.equal(parts.length, 4)
    for (const index of [1, 2, 3]) {
      const broken = [...parts]
      broken[index] = flipSegment(parts[index])
      assert.equal(vault.decrypt(broken.join(':')), null, `segment ${index} must fail closed`)
    }
    assert.equal(vault.decrypt('garbage'), null)
    assert.equal(vault.decrypt('v2:a:b:c'), null)
    assert.equal(vault.decrypt('v1:a:b'), null)
    assert.equal(vault.decrypt(''), null)
  })
})

test('a corrupted key file fails closed: encrypt throws, decrypt returns null', async () => {
  await withVault(async ({ keyPath, vault }) => {
    // Wrong length => corrupted, and the vault must NOT overwrite it.
    await writeFile(keyPath, Buffer.alloc(16, 0x41))
    const before = await readFile(keyPath)
    assert.equal(before.length, 16)

    const plain = 'never-in-the-error'
    assert.throws(
      () => vault.encrypt(plain),
      (error) => {
        assert.match(String(error.message), /key is missing or corrupted/)
        assert.equal(String(error.message).includes(plain), false, 'error must not leak plaintext')
        return true
      },
    )
    assert.equal(vault.decrypt('v1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:AAAA'), null)
    assert.equal(vault.isAvailable(), false)

    const after = await readFile(keyPath)
    assert.equal(after.length, 16, 'corrupted key file must be left untouched')
  })
})

test('encrypt refuses to run when the key cannot be written', async () => {
  await withVault(async ({ dir }) => {
    // A directory in place of the key file: setup cannot succeed.
    const keyPath = join(dir, 'as-directory')
    await rm(keyPath, { recursive: true, force: true })
    const { mkdir } = await import('node:fs/promises')
    await mkdir(keyPath)
    const vault = new CredentialVault({ keyPath })
    assert.equal(vault.isAvailable(), false)
    assert.throws(() => vault.encrypt('x'), /key is missing or corrupted/)
  })
})
