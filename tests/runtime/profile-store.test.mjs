/**
 * ProfileStore: multiple named JumpServer logins on disk, with the password
 * kept only as a vault token. All work happens in a temp directory — the real
 * ~/.workbuddy/jumpserver-mcp/profiles.json is never touched.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CredentialVault } from '../../lib/security/credential-vault.js'
import { ProfileStore } from '../../lib/runtime/profile-store.js'

async function withStore(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'js-profiles-'))
  const filePath = join(dir, 'profiles.json')
  const keyPath = join(dir, 'vault.key')
  const vault = new CredentialVault({ keyPath })
  const make = () => new ProfileStore({ filePath, vault, log: () => undefined })
  try {
    await fn({ dir, filePath, keyPath, vault, store: make(), make })
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined)
  }
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

test('a missing or empty file reads as an empty store', async () => {
  await withStore(async ({ filePath, store }) => {
    assert.deepEqual(store.list(), [])
    assert.equal(store.getActive(), null)
    assert.equal(store.integrity().broken, false)

    await writeFile(filePath, '', 'utf8')
    assert.deepEqual(store.list(), [])
    assert.equal(store.integrity().broken, false)
  })
})

test('upsert without an id creates a profile with a generated id', async () => {
  await withStore(async ({ store }) => {
    const view = store.upsert({ label: '生产维护账号', host: 'jump.example.com', port: 22, username: 'ops' })
    assert.equal(typeof view.id, 'string')
    assert.ok(view.id.length > 0)
    assert.equal(view.hasSecret, false)
    assert.equal(view.active, false)
    assert.equal(view.createdAt, view.updatedAt)
    assert.equal(store.list().length, 1)
    assert.equal(store.getActive(), null)
  })
})

test('a stored password is encrypted at rest and reachable only via resolvePassword', async () => {
  await withStore(async ({ filePath, store }) => {
    const password = 'S3cr3t-口令:with\nnewline'
    const view = store.upsert({ label: 'maintenance', host: 'jump.example.com', port: 2222, username: 'maint', password })
    assert.equal(view.hasSecret, true)
    assert.equal(store.resolvePassword(view.id), password)

    const listed = store.list()
    assert.equal(JSON.stringify(listed).includes(password), false, 'list must not contain the plaintext')
    const raw = await readFile(filePath, 'utf8')
    assert.equal(raw.includes(password), false, 'profiles.json must not contain the plaintext')

    const token = JSON.parse(raw).profiles[0].secret.token
    assert.match(token, /^v1:/)
    assert.equal(JSON.stringify(listed).includes(token), false, 'list must not contain the vault token')
    assert.equal(store.integrity().broken, false)
  })
})

test('upsert with an undefined password keeps the stored secret and createdAt', async () => {
  await withStore(async ({ store }) => {
    const password = 'keep-me'
    const created = store.upsert({ label: 'a', host: 'h1', port: 22, username: 'u1', password })
    await wait(5)
    const updated = store.upsert({ id: created.id, label: 'a2', host: 'h2', port: 2200, username: 'u2' })
    assert.equal(updated.id, created.id)
    assert.equal(updated.createdAt, created.createdAt, 'createdAt is immutable')
    assert.ok(updated.updatedAt > created.updatedAt, 'updatedAt must advance')
    assert.equal(updated.hasSecret, true)
    assert.equal(updated.label, 'a2')
    assert.equal(updated.host, 'h2')
    assert.equal(store.resolvePassword(created.id), password)
  })
})

test('upsert with a null password explicitly clears the stored secret', async () => {
  await withStore(async ({ store }) => {
    const created = store.upsert({ label: 'a', host: 'h1', port: 22, username: 'u1', password: 'drop-me' })
    const cleared = store.upsert({ id: created.id, label: 'a', host: 'h1', port: 22, username: 'u1', password: null })
    assert.equal(cleared.hasSecret, false)
    assert.equal(store.resolvePassword(created.id), undefined)
  })
})

test('upsert with an unknown id is refused', async () => {
  await withStore(async ({ store }) => {
    assert.throws(() => store.upsert({ id: 'nope', label: 'a', host: 'h', port: 22, username: 'u' }), /unknown profile id/)
    assert.deepEqual(store.list(), [])
  })
})

test('setActive rejects an unknown id without rewriting the file', async () => {
  await withStore(async ({ filePath, store }) => {
    const a = store.upsert({ label: 'a', host: 'h1', port: 22, username: 'u1' })
    const b = store.upsert({ label: 'b', host: 'h2', port: 22, username: 'u2' })
    store.setActive(b.id)
    const before = await readFile(filePath, 'utf8')

    assert.equal(store.setActive('ghost-id'), null)
    assert.equal(store.getActive().id, b.id)
    assert.equal(await readFile(filePath, 'utf8'), before, 'file must be untouched')

    const active = store.setActive(a.id)
    assert.equal(active.id, a.id)
    assert.equal(active.active, true)
    assert.equal(store.getActive().id, a.id)
  })
})

test('remove drops the profile and clears an active pointer to it', async () => {
  await withStore(async ({ store }) => {
    const a = store.upsert({ label: 'a', host: 'h1', port: 22, username: 'u1' })
    const b = store.upsert({ label: 'b', host: 'h2', port: 22, username: 'u2' })
    assert.equal(store.remove('ghost-id'), false)

    store.setActive(a.id)
    assert.equal(store.remove(a.id), true)
    assert.equal(store.list().some((p) => p.id === a.id), false)
    assert.equal(store.getActive(), null, 'active pointer must be cleared')

    store.setActive(b.id)
    assert.equal(store.remove(b.id), true)
    assert.deepEqual(store.list(), [])
    assert.equal(store.getActive(), null)
  })
})

test('data survives a new store instance over the same file', async () => {
  await withStore(async ({ store, make }) => {
    const password = 'persisted-secret'
    const created = store.upsert({ label: 'persist', host: 'jump.example.com', port: 22, username: 'ops', password })
    store.setActive(created.id)

    const reopened = make()
    const views = reopened.list()
    assert.equal(views.length, 1)
    assert.equal(views[0].id, created.id)
    assert.equal(views[0].label, 'persist')
    assert.equal(views[0].hasSecret, true)
    assert.equal(reopened.getActive().id, created.id)
    assert.equal(reopened.resolvePassword(created.id), password)
  })
})

test('a corrupt file is reported and left untouched, never silently replaced', async () => {
  await withStore(async ({ filePath, store }) => {
    const garbage = '{ this is not json at all'
    await writeFile(filePath, garbage, 'utf8')

    assert.deepEqual(store.list(), [])
    assert.equal(store.getActive(), null)
    const integrity = store.integrity()
    assert.equal(integrity.broken, true)
    assert.equal(typeof integrity.message, 'string')
    assert.equal(integrity.message.includes(garbage), false, 'integrity message must not echo file content')
    assert.equal(await readFile(filePath, 'utf8'), garbage, 'the corrupt file must not be rewritten')

    // Writes refuse rather than destroy data the operator might recover.
    assert.throws(() => store.upsert({ label: 'x', host: 'h', port: 22, username: 'u' }), /refusing to overwrite/)
    assert.equal(await readFile(filePath, 'utf8'), garbage)
  })
})

test('a structurally wrong file is treated as broken as well', async () => {
  await withStore(async ({ filePath, store }) => {
    const wrong = JSON.stringify({ version: 2, activeProfileId: null, profiles: [] })
    await writeFile(filePath, wrong, 'utf8')
    assert.deepEqual(store.list(), [])
    assert.equal(store.integrity().broken, true)
    assert.equal(await readFile(filePath, 'utf8'), wrong)
  })
})
