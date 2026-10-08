#!/usr/bin/env node
/**
 * One-shot debug (2026-09-14): feed the real KoKo ID> tail captured from
 * 192.168.138.56 into the production detector and dump every whitespace
 * character's code point so we can confirm whether KoKo uses full-width
 * spaces (U+3000) for CJK column padding — which would break
 * detector.ts:rowPattern because \s excludes U+3000 by default.
 *
 * Usage:
 *   /path/to/node scripts/debug-real-tail.mjs
 */
import { looksLikeAccountSelection } from '../lib/jumpserver/detector.js'

// Real-world tail (last 500 chars) captured by jumpserver_run attempt.
const tail = [
  '提示：输入资产[jsx-c138056-应用集群-测试环境01(192.168.138.56)]的账号ID',
  '',
  '返回：B/b',
  '',
  'ID> ',
].join('\n')

// A more realistic tail: table header + separator + two data rows.
// The literal here uses half-width spaces (the same way the existing
// fixture does), so we can compare: if KoKo actually uses U+3000 in the
// wire bytes, the screen-byte inspector (jumpserver_run error.detail) is
// what matters — see the table dump further below.
const fixtureTail = [
  '提示：输入资产[jsx-c138056-应用集群-测试环境01(192.168.138.56)]的账号ID',
  '',
  '返回：B/b',
  '',
  'ID> ',
].join('\n')

const result = looksLikeAccountSelection(tail)

const charStats = new Map()
for (const ch of tail) {
  const cp = ch.codePointAt(0)
  const key = 'U+' + cp.toString(16).toUpperCase().padStart(4, '0')
  if (!charStats.has(key)) charStats.set(key, { char: ch, codepoint: cp, count: 0 })
  charStats.get(key).count += 1
}
const whitespace = Array.from(charStats.values())
  .filter((s) => /\s/.test(s.char) || s.codepoint === 0x3000)
  .sort((a, b) => b.count - a.count)

process.stdout.write(JSON.stringify({
  detectorVerdict: { detected: result.detected, optionCount: result.options.length, preview: result.preview },
  tailLength: tail.length,
  whitespaceChars: whitespace,
  uniqueCharCount: charStats.size,
}, null, 2) + '\n')