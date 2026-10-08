#!/usr/bin/env node
/**
 * V0.5.3.2 second-round debug (2026-09-14):
 * The connector's first jumpserver_run attempt after the detail-rendering fix
 * still hangs at "asset shell for ... not detected within the enter timeout".
 * detail.tail shows KoKo did paint the ID> table, but detector still returns
 * detected=false. Either:
 *   (a) connector process is still loading the OLD compiled lib/jumpserver/
 *       detector.js (cache from before tsc rebuild) — restart is mandatory
 *       after lib/ changes;
 *   (b) the real KoKo wire bytes use a Unicode whitespace character our
 *       rowPattern still does not accept.
 *
 * This script builds a tail faithful to what detail.tail showed and runs
 * looksLikeAccountSelection against the compiled lib (what the connector
 * *would* see after restart). It also runs a robustness check across the
 * common Unicode whitespace variants.
 */
import { looksLikeAccountSelection } from '../lib/jumpserver/detector.js'

const samples = {
  'real-halfspace': [
    // header separator
    '------+-------+-----',
    // data row, half-width padding (English label "root")
    '  1     | root                                                                       | root                                                                     ',
    // data row, may use U+3000 padding around CJK label
    '  2     | 手动输入                                                                   | @INPUT                                                                   ',
    '',
    '提示：输入资产[jsx-c138056-应用集群-测试环境01(192.168.138.56)]的账号ID',
    '',
    '返回：B/b',
    '',
    'ID> ',
  ].join('\n'),

  'real-cjk-u3000': [
    '------+-------+-----',
    // Simulate KoKo using U+3000 to align CJK columns. Three labels mixed.
    '  1     | root      \u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000 | root',
    '  2     | 手动输入      | @INPUT',
    '',
    '提示：输入资产[jsx-c138056-应用集群-测试环境01(192.168.138.56)]的账号ID',
    '',
    '返回：B/b',
    '',
    'ID> ',
  ].join('\n'),

  'real-mixed': [
    '------+-------+-----',
    '  1     | root                | root',
    // Try a row with U+3000 ONLY in the label-to-pipe padding (Chinese columns)
    '  2     | 手动输入\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000 | @INPUT',
    '',
    '提示：输入资产[jsx-c138056-应用集群-测试环境01(192.168.138.56)]的账号ID',
    '',
    '返回：B/b',
    '',
    'ID> ',
  ].join('\n'),
}

for (const [name, tail] of Object.entries(samples)) {
  const r = looksLikeAccountSelection(tail)

  // Whitespace distribution in the tail — find any non-ASCII whitespace
  // characters (U+3000 / U+2003 / U+2002 etc).
  const wsMap = new Map()
  for (const ch of tail) {
    if (/\s/.test(ch) || ch.codePointAt(0) === 0x3000 || ch.codePointAt(0) >= 0x2000 && ch.codePointAt(0) <= 0x200b) {
      const cp = ch.codePointAt(0)
      const key = 'U+' + cp.toString(16).toUpperCase().padStart(4, '0')
      wsMap.set(key, (wsMap.get(key) ?? 0) + 1)
    }
  }

  process.stdout.write(`--- ${name} ---\n`)
  process.stdout.write(`detected=${r.detected} options=${JSON.stringify(r.options)}\n`)
  process.stdout.write(`whitespace=${JSON.stringify(Object.fromEntries(wsMap))}\n\n`)
}
