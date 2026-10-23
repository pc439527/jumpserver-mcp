/**
 * V0.7.1 (D-1/D-2/D-3): the model-facing output budget.
 *
 * The three rules under test:
 *   D-1  the text handed to the model is capped (default 64 KiB)
 *   D-2  an over-long LINE is folded in the MIDDLE (head + tail survive)
 *   D-3  an over-budget output is spilled to disk and the model is told
 *        how to ask the remote host for the slice it actually wants
 *
 * These tests use the compiled output (lib/), like the rest of the suite.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  applyOutputBudget,
  adviseForCommand,
  byteLength,
  foldOversizedLine,
  nextSpillFileName,
  takeHeadBytes,
  takeTailBytes,
  DEFAULT_MAX_OUTPUT_BYTES,
} from '../../lib/jumpserver/output-budget.js'

test('D-1: output under the budget is passed through unchanged', () => {
  const text = 'hello\nworld\n'
  const r = applyOutputBudget(text, { maxBytes: 1024 })
  assert.equal(r.truncated, false)
  assert.equal(r.text, text)
  assert.equal(r.totalBytes, byteLength(text))
  assert.equal(r.totalLines, 3)
  assert.equal(r.spillPath, null)
})

test('D-1: output over the budget is capped and announced', () => {
  const text = Array.from({ length: 500 }, (_, i) => 'line ' + String(i)).join('\n')
  assert.ok(byteLength(text) > 4096)
  const r = applyOutputBudget(text, { maxBytes: 4096, headLines: 10 })
  assert.equal(r.truncated, true)
  assert.ok(byteLength(r.text) < byteLength(text), 'the shown text must be smaller')
  assert.equal(r.totalLines, 500)
  assert.ok(r.omittedLines > 0, 'the omitted line count must be reported')
  assert.ok(r.text.includes('输出已裁剪'), 'the truncation must be announced in the text')
  assert.ok(r.text.includes('line 0'), 'the head must survive')
  assert.ok(r.text.includes('line 499'), 'the tail must survive')
  assert.notEqual(r.advice, null, 'a truncated output must carry advice')
})

test('D-2: an over-long line is folded in the MIDDLE, head and tail survive', () => {
  const head = 'BEGIN-'.repeat(50)
  const tail = '-END'.repeat(50)
  const line = head + 'X'.repeat(5000) + tail
  const folded = foldOversizedLine(line, 1024)
  assert.ok(byteLength(folded) < byteLength(line))
  assert.ok(folded.startsWith('BEGIN-'), 'the head of the line must survive')
  assert.ok(folded.endsWith('-END'), 'the tail of the line must survive')
  assert.ok(folded.includes('省略'), 'the fold must be marked')
  assert.ok(folded.includes('X'), 'the middle content marker must be there')
})

test('D-2: a long line does not blow the budget on its own', () => {
  const text = 'Z'.repeat(50000)
  const r = applyOutputBudget(text, { maxBytes: 4096, maxLineBytes: 1024 })
  assert.equal(r.truncated, true)
  assert.ok(byteLength(r.text) <= 4096 + 1024, 'the text must stay near the budget')
  assert.ok(r.text.includes('省略'))
})

test('D-2: a normal line is never touched', () => {
  const line = 'short line'
  assert.equal(foldOversizedLine(line, 1024), line)
})

test('D-3: an over-budget output is spilled to disk and the path is reported', () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-budget-'))
  try {
    const text = Array.from({ length: 400 }, (_, i) => 'spill line ' + String(i)).join('\n')
    const r = applyOutputBudget(text, { maxBytes: 2048, headLines: 5, spillDir: dir, spillName: 'output' })
    assert.equal(r.truncated, true)
    assert.notEqual(r.spillPath, null)
    const saved = readFileSync(r.spillPath, 'utf8')
    assert.equal(saved, text, 'the spilled file must hold the FULL output')
    assert.equal(r.spillBytes, byteLength(text))
    assert.ok(r.text.includes(r.spillPath), 'the model must be told where the file is')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-3: a read-only spill directory must NOT fail the command', () => {
  const dir = mkdtempSync(join(tmpdir(), 'js-budget-ro-'))
  try {
    // Make the spill path unwritable: use a FILE as the parent directory, so
    // mkdirSync(recursive) inside it must fail.
    const blocker = join(dir, 'not-a-dir')
    writeFileSync(blocker, 'x')
    const text = Array.from({ length: 400 }, (_, i) => 'x'.repeat(20) + String(i)).join('\n')
    const r = applyOutputBudget(text, { maxBytes: 2048, headLines: 5, spillDir: join(blocker, 'outputs'), spillName: 'output' })
    assert.equal(r.truncated, true)
    assert.equal(r.spillPath, null, 'the spill must fail soft')
    assert.ok(r.text.includes('输出已裁剪'), 'the truncation is still announced')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('D-3: the spill file name is unique (pid + counter, never a fixed name)', () => {
  const a = nextSpillFileName('/tmp', 'output')
  const b = nextSpillFileName('/tmp', 'output')
  assert.notEqual(a, b)
  assert.ok(a.includes(String(process.pid)))
})

test('the advice is tailored to the command that produced the output', () => {
  assert.ok(adviseForCommand('grep -n foo catalina.out').includes('grep'))
  assert.ok(adviseForCommand('tail -f app.log').includes('tail'))
  assert.ok(adviseForCommand('ls -la /var/log').includes('head'))
  assert.ok(adviseForCommand(null).length > 0)
})

test('the default budget is 64 KiB', () => {
  assert.equal(DEFAULT_MAX_OUTPUT_BYTES, 65536)
})

test('takeHeadBytes / takeTailBytes respect the byte budget', () => {
  const text = 'abcdefghij'
  assert.equal(takeHeadBytes(text, 4), 'abcd')
  assert.equal(takeTailBytes(text, 4), 'ghij')
  assert.equal(takeHeadBytes(text, 100), text)
})

test('a multi-byte character is never split in half', () => {
  const text = '中文字'.repeat(10)
  const head = takeHeadBytes(text, 7)
  assert.ok(byteLength(head) <= 7)
  assert.ok(text.startsWith(head))
})
