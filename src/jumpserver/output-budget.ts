/**
 * V0.7.1 (D-1/D-2/D-3): the model-facing OUTPUT BUDGET.
 *
 * WHY THIS EXISTS
 * ---------------
 * A single `grep` on catalina.out produced 91 KB of text. The connector
 * returned all of it, the model paid ~30K tokens for one command, and the
 * useful part (the matching lines) was buried in the middle. The audit
 * showed 7222 records over 44 days, so this was the single largest
 * recurring waste in the connector — not a rare event.
 *
 * THE THREE RULES (D-1 / D-2 / D-3)
 * ---------------------------------
 * D-1  The text handed to the model is capped (default 64 KiB). The CAPTURE
 *      limit stays larger (MAX_CAPTURE_BYTES) on purpose: an over-budget
 *      output must still be available in full so it can be spilled to disk.
 * D-2  A single OVER-LONG LINE is folded in the MIDDLE (head + tail kept,
 *      `[…省略 N 字节…]` in between) — not cut off at the end. Cutting the
 *      end of a line destroys the very information the caller asked for;
 *      a JSON blob or a stack trace loses its payload.
 * D-3  An over-budget output is written to disk and the model is told where
 *      it is, how many lines it has, and what to run INSTEAD (`wc -l`,
 *      `tail -c`) so the next call asks the remote host for the slice it
 *      actually wants.
 *
 * DESIGN RULES
 * ------------
 *  - The budget is applied at the TOOL-RESULT layer, not at capture time.
 *    Truncating at capture time would destroy the output before D-3 could
 *    spill it, and would also make the audit trail lie about what ran.
 *  - Every loss is ANNOUNCED. A silently shortened output is worse than a
 *    long one: the model would conclude the command printed nothing.
 *  - Spilling is best-effort. A read-only data directory must not turn a
 *    successful command into a failure — the budget then folds instead.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/** Default cap for the text handed to the model (64 KiB). */
export const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024

/** Default per-line fold threshold (8 KiB). */
export const DEFAULT_MAX_LINE_BYTES = 8 * 1024

/** Default number of head/tail lines kept when the output does not fit. */
export const DEFAULT_HEAD_LINES = 200

/** Marker inserted where content was removed. */
export const OMITTED_MARKER = '[…省略 '

export interface OutputBudgetOptions {
  /** Cap for the text handed to the model (default 64 KiB). */
  maxBytes?: number
  /** A line longer than this is folded in the middle (default 8 KiB). */
  maxLineBytes?: number
  /** Head/tail line count kept when the output does not fit (default 200). */
  headLines?: number
  /** Directory for the spilled output. null/undefined = fold only, never write. */
  spillDir?: string | null
  /** Base name for the spilled file (a suffix is added for uniqueness). */
  spillName?: string
  /** The command that produced the output — used to tailor the advice. */
  command?: string | null
}

export interface BudgetedOutput {
  /** What the model sees. */
  text: string
  /** True when anything was removed from the text. */
  truncated: boolean
  /** Byte size of the text BEFORE the budget was applied. */
  totalBytes: number
  /** Line count BEFORE the budget was applied. */
  totalLines: number
  /** Line count of `text`. */
  shownLines: number
  /** Lines that were removed. */
  omittedLines: number
  /** Path of the spilled full output, when it was written. */
  spillPath: string | null
  /** Byte size of the spilled file. */
  spillBytes: number | null
  /** Actionable next step for the caller. */
  advice: string | null
}

/** Byte length of a string (UTF-8). */
export function byteLength(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}

/** Longest prefix of `text` that fits into `maxBytes` without splitting a character. */
export function takeHeadBytes(text: string, maxBytes: number): string {
  let bytes = 0
  let out = ''
  for (const ch of text) {
    const size = byteLength(ch)
    if (bytes + size > maxBytes) break
    bytes += size
    out += ch
  }
  return out
}

/** Longest suffix of `text` that fits into `maxBytes` without splitting a character. */
export function takeTailBytes(text: string, maxBytes: number): string {
  let bytes = 0
  let out = ''
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i]!
    const size = byteLength(ch)
    if (bytes + size > maxBytes) break
    bytes += size
    out = ch + out
  }
  return out
}

/**
 * D-2: fold ONE over-long line in the middle.
 *
 * The head and the tail both survive, because a caller reading a long line
 * needs its beginning (what the record is about) AND its end (the error).
 */
export function foldOversizedLine(line: string, maxLineBytes: number): string {
  const total = byteLength(line)
  if (total <= maxLineBytes) return line
  const keep = Math.max(64, Math.floor(maxLineBytes / 2))
  const head = takeHeadBytes(line, keep)
  const tail = takeTailBytes(line, keep)
  const omitted = Math.max(0, total - byteLength(head) - byteLength(tail))
  return head + OMITTED_MARKER + String(omitted) + ' 字节…]' + tail
}

/** Fold every over-long line of a text (D-2). */
export function foldOversizedLines(text: string, maxLineBytes: number): { text: string; folded: boolean } {
  if (maxLineBytes <= 0) return { text, folded: false }
  let folded = false
  const out = text.split('\n').map((line) => {
    const next = foldOversizedLine(line, maxLineBytes)
    if (next !== line) folded = true
    return next
  })
  return { text: out.join('\n'), folded }
}

/**
 * Keep the leading lines of `lines` that fit into `maxBytes` (whole lines
 * only — a line is never cut in half here).
 */
export function takeHeadBytesFromLines(lines: string[], maxBytes: number): string[] {
  const out: string[] = []
  let bytes = 0
  for (const line of lines) {
    const size = byteLength(line) + 1
    if (bytes + size > maxBytes) break
    bytes += size
    out.push(line)
  }
  return out
}

/** Counter for unique spill file names (pid + counter — never a fixed name). */
let spillCounter = 0

/** A unique spill file name for this process. */
export function nextSpillFileName(dir: string, baseName: string): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const safe = baseName.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60)
  spillCounter += 1
  return join(dir, safe + '-' + stamp + '-' + String(process.pid) + '-' + String(spillCounter) + '.log')
}

/**
 * Tailored advice: what to run INSTEAD of asking for the whole output again.
 *
 * The point is to move the slicing to the REMOTE host, where it costs
 * nothing, instead of shipping megabytes over the bastion and paying for
 * them in the model's context.
 */
export function adviseForCommand(command: string | null | undefined): string {
  const cmd = (command ?? '').toLowerCase()
  if (cmd.length === 0) {
    return '输出过长已裁剪：改用 `wc -l` 统计行数、`head -c`/`tail -c` 取片段，或用 `grep -n` 直接定位需要的行。'
  }
  if (/\bgrep\b|\brg\b/.test(cmd)) {
    return '输出过长已裁剪：改用 `grep -c` 先看命中条数、`grep -n -m 50` 限制条数，或加 `| head -n 100` 取片段。'
  }
  if (/\btail\b|\bless\b|\bcat\b|\bjournalctl\b/.test(cmd)) {
    return '输出过长已裁剪：改用 `wc -l` 统计行数、`tail -n 100` 取末尾片段，或 `head -n 100` 取开头片段。'
  }
  if (/\bfind\b|\bls\b|\bdu\b/.test(cmd)) {
    return '输出过长已裁剪：改用 `wc -l` 统计条数、`| head -n 100` 取片段，必要时加 `| sort | uniq -c` 聚合后再看。'
  }
  return '输出过长已裁剪：改用 `wc -l` 统计行数、`head -c`/`tail -c` 取片段，或用 `grep -n` 直接定位需要的行。'
}

/**
 * D-1/D-2/D-3: apply the output budget.
 *
 * Order matters: lines are folded FIRST (so a single huge line cannot blow
 * the budget on its own), then the total size is checked, and only then is
 * the output spilled to disk.
 */
export function applyOutputBudget(text: string, options: OutputBudgetOptions = {}): BudgetedOutput {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_OUTPUT_BYTES
  const maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES
  const headLines = options.headLines ?? DEFAULT_HEAD_LINES
  const rawLines = text.length === 0 ? [] : text.split('\n')
  const totalLines = rawLines.length
  const totalBytes = byteLength(text)

  const folded = foldOversizedLines(text, maxLineBytes)
  const foldedBytes = byteLength(folded.text)

  if (foldedBytes <= maxBytes) {
    return {
      text: folded.text,
      truncated: folded.folded,
      totalBytes,
      totalLines,
      shownLines: totalLines,
      omittedLines: 0,
      spillPath: null,
      spillBytes: null,
      advice: folded.folded ? adviseForCommand(options.command) : null,
    }
  }

  // ---- over budget ------------------------------------------------------
  const lines = folded.text.split('\n')
  const head = lines.slice(0, headLines)
  const tail = lines.length > headLines * 2 ? lines.slice(lines.length - headLines) : []

  // The line-count cut alone does NOT enforce the byte budget: 200 lines of
  // 8 KiB each is 1.6 MB, far past the 64 KiB cap. So the byte budget is
  // enforced here as well, and the head/tail are re-cut to fit.
  const notice: string[] = []
  notice.push(
    '[输出已裁剪：共 ' + String(totalLines) + ' 行 / ' + String(totalBytes) + ' 字节，超过 ' +
    String(maxBytes) + ' 字节上限]',
  )

  const overhead = byteLength(notice.join('\n')) + 64
  let budget = Math.max(0, maxBytes - overhead)
  let headCut = head
  let tailCut = tail

  // Reserve room for the tail first — the END of an output usually holds the
  // error the caller needs, while the head is often a header.
  let tailBytes = byteLength(tailCut.join('\n'))
  if (tailBytes > budget / 2) {
    tailCut = takeHeadBytesFromLines(tailCut, Math.floor(budget / 2))
    tailBytes = byteLength(tailCut.join('\n'))
  }
  let headBytes = byteLength(headCut.join('\n'))
  if (headBytes > budget - tailBytes) {
    headCut = takeHeadBytesFromLines(headCut, Math.max(0, budget - tailBytes))
    headBytes = byteLength(headCut.join('\n'))
  }

  const keptHead = headCut.length
  const keptTail = tailCut.length
  const omittedLines = Math.max(0, lines.length - keptHead - keptTail)

  let spillPath: string | null = null
  let spillBytes: number | null = null
  if (options.spillDir !== undefined && options.spillDir !== null && options.spillDir.length > 0) {
    try {
      mkdirSync(options.spillDir, { recursive: true })
      const file = nextSpillFileName(options.spillDir, options.spillName ?? 'output')
      writeFileSync(file, text, 'utf8')
      spillPath = file
      spillBytes = totalBytes
    } catch {
      // A read-only data directory must not turn a successful command into a
      // failure — fall back to folding, which loses no lines.
      spillPath = null
      spillBytes = null
    }
  }

  if (spillPath !== null) {
    notice.push('[完整输出已落盘：' + spillPath + '（' + String(totalBytes) + ' 字节）]')
  }
  const middle = omittedLines > 0
    ? ['[…省略 ' + String(omittedLines) + ' 行…]']
    : []

  const body = [...headCut, ...middle, ...tailCut]
  return {
    text: [...notice, ...body].join('\n'),
    truncated: true,
    totalBytes,
    totalLines,
    shownLines: body.length,
    omittedLines,
    spillPath,
    spillBytes,
    advice: adviseForCommand(options.command),
  }
}
