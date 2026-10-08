/**
 * V0.5.3: detector unit tests — the `ID>` + numbered users screen.
 *
 * Conservative by design (see detector.ts), so this file is mostly
 * NEGATIVE coverage: ensure the detector does NOT trip on
 *   - the regular asset shell prompt
 *   - a single-numbered entry (KoKo auto-picks; no ID> would appear)
 *   - the JumpServer menu (numbered asset list + Opt>)
 *   - numbered rows from a probe output like `ss -lntp`
 *
 * Plus positive coverage for the canonical multi-user screen.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { looksLikeAccountSelection } from '../../lib/jumpserver/detector.js'

test('detects the canonical 0-based selection screen', () => {
  const tail = [
    '[Host] 192.168.138.56',
    '[Users]',
    '0) admin',
    '1) ops',
    '2) deploy',
    '',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true)
  assert.deepEqual(result.options.map((o) => o.index), [0, 1, 2])
  assert.deepEqual(result.preview, ['0) admin', '1) ops', '2) deploy'])
})

test('detects the 1-based pipe-table layout seen on the real bastion', () => {
  const tail = [
    '[Host] 192.168.138.56',
    '提示：输入 [jsx-c138056-...] 的账号ID',
    'ID   | 名称     | 用户名',
    '-----|----------|----------',
    '1    | root     | root',
    '2    | 手动输入 | @INPUT',
    '',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true)
  assert.deepEqual(result.options.map((o) => o.index), [1, 2])
  assert.deepEqual(result.options.map((o) => o.label), ['root', '手动输入'])
  assert.deepEqual(result.preview, ['1) root', '2) 手动输入'])
})

test('detects when the screen is followed by trailing output', () => {
  // The detector must be robust to ANSI noise and prompt-suffix whitespace.
  const tail = [
    '   some banner text',
    '[Users]',
    '0) admin',
    '1) ops',
    '2) root',
    'ID> ',
    '', // some trailing empty lines KoKo often paints
    '',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true)
  assert.equal(result.options.length, 3)
})

test('does NOT detect a single-entry list (KoKo auto-picks; no ID> would appear)', () => {
  const tail = [
    '[Users]',
    '0) admin',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, false, 'single-entry "list" must not trigger the account-selection path')
})

test('does NOT detect the JumpServer asset menu (numbered assets + Opt>)', () => {
  const tail = [
    '┌──────────────────────────────────────────┐',
    '│  1) oa-nginx                              │',
    '│  2) oa-app                                │',
    '│  请输入资产名或编号：                       │',
    '└──────────────────────────────────────────┘',
    'Opt> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, false, 'the regular asset menu must NOT look like an account-selection screen')
})

test('does NOT detect a live shell prompt', () => {
  const tail = '[root@oa-app ~]# '
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, false, 'shell prompt must never look like an account-selection screen')
})

test('does NOT detect numbered probe output (no ID> prompt)', () => {
  const tail = [
    'State      Recv-Q Send-Q Local Address:Port   Peer Address:Port',
    'LISTEN     0      128    0.0.0.0:22            0.0.0.0:*',
    'LISTEN     0      511    0.0.0.0:443           0.0.0.0:*',
    '[root@host ~]# ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, false, 'numbered rows in probe output must not trigger selection')
})

test('rejects a numbered list with a gap (index 0 then 2)', () => {
  // KoKo always prints 0..N-1; a gap means we are NOT looking at a real
  // account-selection screen and we MUST not auto-pick an index.
  const tail = [
    '[Users]',
    '0) admin',
    '2) ops',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, false, 'a numbered list with a gap must be rejected — KoKo always emits 0..N-1')
})

test('ignores the prompt when there is no recognisable header (a single dense list still works)', () => {
  const tail = [
    '0) admin',
    '1) ops',
    '2) deploy',
    '3) monitor',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true, 'a dense (>=3 entries) numbered list with ID> must trigger selection')
  assert.equal(result.options.length, 4)
})

test('detects Chinese-style header ([账号] / [用户])', () => {
  const tail = [
    '[账号]',
    '0) 管理员',
    '1) 运维',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true)
  assert.deepEqual(result.preview, ['0) 管理员', '1) 运维'])
})

test('detects the ID> prompt even when KoKo appends a visible cursor glyph', () => {
  // V0.5.3.1: real KoKo PTY appends a visible cursor character (typically
  // `_`) AFTER `ID>` instead of trailing whitespace. The previous `\s*$`
  // anchor rejected this, so the detector missed the screen the entire
  // connector was waiting on. The `ID>` token itself is unique enough in
  // KoKo output that accepting any non-newline suffix is safe.
  const tail = [
    '  ID   | 名称     | 用户名',
    '------+----------+--------',
    '  1   | root     | root',
    '  2   | 手动输入 | @INPUT',
    '',
    '提示：输入资产[jsx-c138056-...]的账号ID',
    '',
    '返回：B/b',
    '',
    'ID> _',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true, 'ID> + cursor glyph must still trigger selection')
  assert.deepEqual(result.options.map((o) => o.index), [1, 2])
  assert.deepEqual(result.options.map((o) => o.label), ['root', '手动输入'])
})

test('detects the ID> prompt when the trailing newline is CR only (normalize gap)', () => {
  // Some terminal variants emit `\r` without `\n` after the prompt. After
  // normalizeNewlines those become `\n`, but on a freshly-fragmented chunk
  // the detector may see the prompt with `\r` still in the tail.
  const tail = [
    '1 | root | root',
    '2 | 手动输入 | @INPUT',
    '',
    'ID> \r',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true)
  assert.equal(result.options.length, 2)
})

test('detects the real KoKo CJK-padded layout (U+3000 column padding, 2026-09-14 capture)', () => {
  // V0.5.3.2: real KoKo on 江苏理士 Linux pads the Chinese columns with
  // full-width spaces (U+3000), not the half-width spaces the previous
  // fixtures used. The previous rowPattern /\s/ silently rejected every
  // such row, so the connector stayed stuck at the `ID>` prompt even
  // though the table was on screen. The fixture is byte-identical to a
  // 192.168.138.56 enter-attempt tail (cleanAnsi'd) — kept verbatim so
  // a future encoding change trips the test loud and clear.
  const tail = [
    '[Host] 192.168.138.56',
    '提示：输入资产[jsx-c138056-应用集群-测试环境01(192.168.138.56)]的账号ID',
    'ID   | 名称     | 用户名',
    '-----+----------+----------',
    '  1   | root\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000 | root',
    '  2   | 手动输入\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000 | @INPUT',
    '',
    '返回：B/b',
    '',
    'ID> ',
  ].join('\n')
  const result = looksLikeAccountSelection(tail)
  assert.equal(result.detected, true, 'CJK-padded KoKo table MUST be detected — otherwise the connector stays stuck at ID>')
  assert.deepEqual(result.options.map((o) => o.index), [1, 2])
  assert.deepEqual(result.options.map((o) => o.label), ['root', '手动输入'])
})