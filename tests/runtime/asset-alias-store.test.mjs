/**
 * E-5 · the asset alias reverse-lookup cache.
 *
 * The failure this guards (N-17): the asset list and the asset the operator
 * means are not the same string. `s113181_BI节点2` vs `BI-02`; a list IP that
 * belongs to a different machine. The symptom was a bare `ASSET_NOT_FOUND`
 * ("check the name/IP") for an asset that WAS in the list — a dead end the
 * model could not close.
 *
 * The contract:
 *   1. The lookup is CONSERVATIVE — it proposes, it never rewrites.
 *   2. Every candidate says WHY it was proposed (the match kind).
 *   3. The cache survives a restart (it is persisted).
 *   4. A corrupt / missing cache is not an error.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  AliasStore,
  aliasStorePath,
  buildAliasIndex,
  findAliasCandidates,
  formatAliasSuggestions,
  normalizeAlias,
} from '../../lib/runtime/asset-alias-store.js'

/** A KoKo asset row in the shape the store consumes. */
function asset(name, ip, extra = {}) {
  return {
    index: 1,
    name,
    ip: ip ?? null,
    platform: extra.platform ?? null,
    node: extra.node ?? null,
    comment: extra.comment ?? null,
    raw: name + ' ' + (ip ?? ''),
  }
}

const LIST = [
  asset('s113181_BI节点2', '192.168.148.181'),
  asset('oa-app-01', '192.168.148.36'),
  asset('ESB-PROD-01', '10.10.1.21'),
  asset('k8s-192-168-30-3', '192.168.30.3'),
]

test('E-5: normalizeAlias folds case and separators', () => {
  assert.equal(normalizeAlias('BI-02'), 'bi02')
  assert.equal(normalizeAlias('s113181_BI节点2'), 's113181bi节点2')
  assert.equal(normalizeAlias('  OA_APP.01 '), 'oaapp01')
})

test('E-5: an exact name match ranks first', () => {
  const index = buildAliasIndex(LIST, 0)
  const hits = findAliasCandidates(index, 'oa-app-01')
  assert.equal(hits.length > 0, true)
  assert.equal(hits[0].name, 'oa-app-01')
  assert.equal(hits[0].kind, 'exact-name')
  assert.equal(hits[0].score, 0.99)
})

test('E-5: an exact IP match ranks first', () => {
  const index = buildAliasIndex(LIST, 0)
  const hits = findAliasCandidates(index, '192.168.148.36')
  assert.equal(hits[0].name, 'oa-app-01')
  assert.equal(hits[0].kind, 'exact-ip')
  assert.equal(hits[0].score, 1)
})

test('E-5: a separator-only difference still matches (BI-02 ↔ bi02)', () => {
  const index = buildAliasIndex([asset('bi02', '10.0.0.2')], 0)
  const hits = findAliasCandidates(index, 'BI-02')
  assert.equal(hits.length, 1)
  assert.equal(hits[0].kind, 'exact-name')
})

test('E-5: a partial name is proposed with an explainable kind', () => {
  const index = buildAliasIndex(LIST, 0)
  const hits = findAliasCandidates(index, 'BI节点')
  assert.equal(hits.length > 0, true)
  assert.equal(hits[0].name, 's113181_BI节点2')
  assert.equal(hits[0].kind, 'name-substring')
})

test('E-5: a short prefix does NOT match (too many false positives)', () => {
  // "oa" would match dozens of assets on a real workspace; a suggestion
  // channel that proposes everything is not a suggestion channel.
  const index = buildAliasIndex(LIST, 0)
  const hits = findAliasCandidates(index, 'oa')
  assert.equal(hits.some((h) => h.kind === 'prefix'), false)
})

test('E-5: a long prefix matches', () => {
  const index = buildAliasIndex(LIST, 0)
  const hits = findAliasCandidates(index, 'oa-app')
  assert.equal(hits.some((h) => h.name === 'oa-app-01'), true)
})

test('E-5: candidates are ranked by score, strongest first', () => {
  const index = buildAliasIndex(LIST, 0)
  const hits = findAliasCandidates(index, '192.168.30.3')
  assert.equal(hits.length > 0, true)
  for (let i = 1; i < hits.length; i += 1) {
    assert.ok(hits[i - 1].score >= hits[i].score, 'candidates must be sorted by score')
  }
})

test('E-5: the candidate list is bounded', () => {
  const many = Array.from({ length: 50 }, (_, i) => asset('srv-' + String(i) + '-node', '10.0.0.' + String(i)))
  const index = buildAliasIndex(many, 0)
  assert.equal(findAliasCandidates(index, 'srv', 5).length <= 5, true)
})

test('E-5: an empty alias proposes nothing', () => {
  const index = buildAliasIndex(LIST, 0)
  assert.deepEqual(findAliasCandidates(index, '   '), [])
})

test('E-5: a cold cache proposes nothing', () => {
  const index = buildAliasIndex([], 0)
  assert.deepEqual(findAliasCandidates(index, 'anything'), [])
})

test('E-5: the store persists the listing and reloads it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-alias-'))
  const path = join(dir, 'asset-aliases.json')
  const store = new AliasStore(path)
  store.update(LIST, 12345)
  assert.equal(store.get().count, 4)

  // A fresh instance must see the SAME listing — this is the whole point of
  // persisting it (a connector restart must not lose the ground truth).
  const reloaded = new AliasStore(path)
  assert.equal(reloaded.get().count, 4)
  assert.equal(reloaded.get().updatedAt, 12345)
  assert.equal(reloaded.candidates('192.168.30.3')[0].name, 'k8s-192-168-30-3')
})

test('E-5: a corrupt cache file is ignored, not fatal', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-alias-bad-'))
  const path = join(dir, 'asset-aliases.json')
  writeFileSync(path, '{not json', 'utf8')
  const store = new AliasStore(path)
  assert.equal(store.get().count, 0)
  assert.deepEqual(store.candidates('anything'), [])
  // And it must recover: a later successful update rewrites the file.
  store.update(LIST, 1)
  assert.equal(new AliasStore(path).get().count, 4)
})

test('E-5: a missing cache file is not an error', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-alias-none-'))
  const store = new AliasStore(join(dir, 'does-not-exist.json'))
  assert.equal(store.get().count, 0)
})

test('E-5: the persisted file is valid JSON with the records', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-alias-json-'))
  const path = join(dir, 'asset-aliases.json')
  new AliasStore(path).update(LIST, 7)
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  assert.equal(raw.count, 4)
  assert.equal(raw.updatedAt, 7)
  assert.equal(raw.records.length, 4)
  assert.equal(raw.records[0].nameKey, 's113181bi节点2')
})

test('E-5: the store path sits next to the audit log', () => {
  // Platform-agnostic: Windows uses backslashes, POSIX uses forward slashes.
  const path = aliasStorePath(join('x', 'data', 'audit.jsonl'))
  assert.equal(path.endsWith(join('data', 'asset-aliases.json')), true)
  assert.equal(path.includes('audit.jsonl'), false)
})

test('E-5: the suggestion block names each candidate and its reason', () => {
  const index = buildAliasIndex(LIST, 0)
  const text = formatAliasSuggestions(findAliasCandidates(index, '192.168.30.3'))
  assert.match(text, /候选资产: /)
  assert.match(text, /k8s-192-168-30-3/)
  assert.match(text, /192\.168\.30\.3/)
  assert.match(text, /\[exact-ip\]/)
})

test('E-5: no candidates ⇒ no suggestion block (an empty list is noise)', () => {
  assert.equal(formatAliasSuggestions([]), null)
})

test('E-5: the suggestion block carries the IP so the model can use it', () => {
  const index = buildAliasIndex(LIST, 0)
  const text = formatAliasSuggestions(findAliasCandidates(index, 'oa-app-01'))
  assert.match(text, /192\.168\.148\.36/)
})
