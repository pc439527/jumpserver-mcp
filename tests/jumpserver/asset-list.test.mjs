/**
 * Asset-list parse / footer / filter / group tests.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  parseAssetList, parseFooter, filterAssets, filterAssetsByGroup,
  resolveGroupKeywords, looksPaged, hasPayloadEvidence, footerComplete,
} from '../../lib/jumpserver/asset-list.js'

const KOKO_FIXTURE = [
  '┌──────────────────────────────────────┐',
  '│ JumpServer · KoKo 终端               │',
  '├──────────────────────────────────────┤',
  '  ID       资产名                IP                平台         节点                 备注',
  '  1        oa-nginx              192.168.79.99     Linux        node1                OA 入口',
  '  2        oa-app-01             192.168.79.101    Linux        node1                OA APP 节点',
  '  3        oa-app-02             192.168.79.102    Linux        node2                OA APP 节点',
  '  4        oa-app-03             192.168.79.103    Linux        node2                OA APP 节点',
  '  5        oa-mobile             192.168.79.100    Linux        node1                泛微移动端',
  '',
  '页码: 1',
  '每页行数: 5',
  '总页数: 1',
  '总数量: 5',
  'Opt> ',
].join('\n')

test('parseFooter reads every KoKo footer field', () => {
  const f = parseFooter(KOKO_FIXTURE)
  assert.equal(f.page, 1)
  assert.equal(f.pageSize, 5)
  assert.equal(f.totalPages, 1)
  assert.equal(f.total, 5)
})

test('parseAssetList: healthy capture parses all five rows and reports the footer', () => {
  const r = parseAssetList(KOKO_FIXTURE)
  assert.equal(r.health, 'ok')
  assert.equal(r.parsedRows, 5)
  assert.equal(r.reportedTotal, 5)
  assert.equal(r.complete, true)
  assert.deepEqual(r.assets.map((a) => a.ip), [
    '192.168.79.99', '192.168.79.101', '192.168.79.102', '192.168.79.103', '192.168.79.100',
  ])
})

test('parseAssetList: filter is applied AFTER parsing (parsedRows is unchanged)', () => {
  const r = parseAssetList(KOKO_FIXTURE, 'oa-app')
  assert.equal(r.parsedRows, 5)
  assert.equal(r.assets.length, 3)
  assert.ok(r.assets.every((a) => a.name.startsWith('oa-app')))
})

test('parseAssetList: bare p echo is INCOMPLETE, not empty', () => {
  const r = parseAssetList('p\nOpt> ')
  assert.equal(r.health, 'ASSET_CAPTURE_INCOMPLETE')
  assert.equal(r.assets.length, 0)
})

test('parseAssetList: KoKo-confirmed empty account is LIST_EMPTY (the only legitimate "0 assets")', () => {
  const r = parseAssetList('页码: 1\n每页行数: 0\n总页数: 1\n总数量: 0\nOpt> ')
  assert.equal(r.health, 'ASSET_LIST_EMPTY')
  assert.equal(r.assets.length, 0)
  assert.equal(r.reportedTotal, 0)
})

test('hasPayloadEvidence: bare echo is NOT a payload', () => {
  assert.equal(hasPayloadEvidence('p\nOpt> '), false)
})

test('footerComplete requires the footer AND a return to the menu prompt', () => {
  assert.equal(footerComplete(KOKO_FIXTURE), true)
  assert.equal(footerComplete('页码: 1\n总数量: 5'), false)
})

test('looksPaged: pager hints collapse the result', () => {
  assert.equal(looksPaged('... Press space to continue (more) ...'), true)
  assert.equal(looksPaged(KOKO_FIXTURE), false)
})

test('filterAssetsByGroup OR-matches every keyword', () => {
  const all = parseAssetList(KOKO_FIXTURE).assets
  const filtered = filterAssetsByGroup(all, ['oa-', 'mobile'])
  assert.equal(filtered.length, 5)
})

test('filterAssetsByGroup requires at least one keyword hit', () => {
  const all = parseAssetList(KOKO_FIXTURE).assets
  assert.equal(filterAssetsByGroup(all, ['nonexistent']).length, 0)
})

test('resolveGroupKeywords: unknown group is null (NOT zero matches)', () => {
  // A known group returns its keywords (case-insensitive match on the name).
  assert.deepEqual(resolveGroupKeywords({ OA: { keywords: ['oa-', 'mobile'] } }, 'oa'), ['oa-', 'mobile'])
  // An unknown group is null, never an empty array — an empty-array would
  // hide the "you misspelt the group name" mistake behind "0 assets".
  assert.equal(resolveGroupKeywords({ OA: { keywords: ['oa-'] } }, 'ESB'), null)
  assert.equal(resolveGroupKeywords({}, 'OA'), null)
})

test('filterAssets is case-insensitive across ip/name/comment', () => {
  const all = parseAssetList(KOKO_FIXTURE).assets
  assert.equal(filterAssets(all, '99').length, 1)
  assert.equal(filterAssets(all, 'MOBILE').length, 1)
  assert.equal(filterAssets(all, '入口').length, 1)
})
