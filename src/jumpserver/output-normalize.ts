/**
 * V0.7.1 (D-5): the OUTPUT NORMALIZATION layer.
 *
 * WHY THIS EXISTS
 * ---------------
 * The same fact looks different depending on how the host printed it:
 *
 *   `[::ffff:192.168.1.10]:443`   vs   `192.168.1.10:443`
 *   `2026-10-23T09:12:33+08:00`   vs   `2026-10-23 09:12:33`
 *   `total   512`                vs   `total 512`
 *
 * A diff or a cross-host comparison then reports a difference that is not
 * one. The plan (D-5) asks for a normalization layer that removes this noise.
 *
 * THE ONE RULE THAT MATTERS
 * -------------------------
 * Normalization NEVER rewrites the raw capture. The audit trail and the
 * output the user pasted into a ticket must stay byte-exact — a normalizer
 * that quietly edits facts is worse than no normalizer at all. So this module
 * produces a SECOND view of the text:
 *
 *   - `normalizeForCompare(text)` — the normalized VIEW (used for diffing)
 *   - `summarizeOutput(text)`     — a compact digest (used for overviews)
 *
 * Both are pure functions. The caller decides which view to use.
 *
 * WHAT IS NORMALIZED (and what is NOT)
 * ------------------------------------
 *   IPv4-mapped prefix  `[::ffff:192.168.1.10]:443` -> `192.168.1.10:443`
 *                       A v4 address behind a v6 socket — the SAME address.
 *   Timestamp shape    `2026-10-23T09:12:33.123+08:00` -> `2026-10-23T09:12:33`
 *                       The instant is kept; the sub-second part and the zone
 *                       offset are dropped (two hosts in the same cluster
 *                       usually run in different zones).
 *   Blank runs         `a    b` -> `a b` (runs of spaces/tabs collapse to one)
 *
 *   NOT normalized: the actual VALUES (a different IP stays a different IP),
 *   the line order, the line count, and anything that does not match the
 *   patterns above. A normalizer that changes values would hide real drift.
 */

/** IPv4-mapped IPv6 address: `::ffff:192.168.1.10`. */
const IPV4_MAPPED = /\[?::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/gi

/** An ISO-8601-ish timestamp with a sub-second part and/or a zone offset. */
const TIMESTAMP =
  /(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?/g

export interface NormalizeOptions {
  /** Strip the `::ffff:` prefix from IPv4-mapped addresses (default true). */
  stripIpv4Mapped?: boolean
  /** Collapse runs of spaces/tabs into a single space (default true). */
  compressWhitespace?: boolean
  /** Drop the sub-second part and the zone offset of timestamps (default true). */
  normalizeTimestamps?: boolean
}

/**
 * Strip the IPv4-mapped IPv6 prefix.
 *
 * `::ffff:` marks a v4 address carried in a v6 socket. Both forms denote the
 * SAME host, so a diff between them is noise.
 */
export function stripIpv4MappedPrefix(text: string): string {
  return text.replace(IPV4_MAPPED, '$1')
}

/**
 * Normalize a timestamp to `YYYY-MM-DDTHH:MM:SS`.
 *
 * The date and the wall-clock time survive; the sub-second precision and the
 * zone offset do not. Two hosts in different zones then compare equal when
 * they ran the same job at the same local time.
 */
export function normalizeTimestampText(text: string): string {
  return text.replace(TIMESTAMP, '$1T$2')
}

/**
 * Collapse runs of spaces/tabs into a single space, and trim trailing
 * whitespace. Line breaks are preserved — a line count is a fact.
 */
export function compressBlankRuns(text: string): string {
  return text
    .split('\n')
    .map((line) => line.replace(/[ \t]{2,}/g, ' ').replace(/[ \t]+$/g, ''))
    .join('\n')
}

/**
 * The normalized VIEW of a text — for diffing and cross-host comparison.
 *
 * The input is never modified; a new string is returned.
 */
export function normalizeForCompare(text: string, options: NormalizeOptions = {}): string {
  const stripMapped = options.stripIpv4Mapped ?? true
  const compress = options.compressWhitespace ?? true
  const stamps = options.normalizeTimestamps ?? true
  let out = text
  if (stamps) out = normalizeTimestampText(out)
  if (stripMapped) out = stripIpv4MappedPrefix(out)
  if (compress) out = compressBlankRuns(out)
  return out
}

/**
 * A compact digest of a text, for overviews and for deciding whether an
 * output is worth showing in full.
 *
 * The digest keeps the FIRST and LAST meaningful lines plus a count — the
 * same shape the human reads when they open a log: the beginning says what
 * this is, the end says how it ended.
 */
export function summarizeOutput(text: string, options: { headLines?: number; maxChars?: number } = {}): {
  digest: string
  totalLines: number
  shownLines: number
  omittedLines: number
} {
  const headLines = options.headLines ?? 3
  const maxChars = options.maxChars ?? 1200
  const lines = text.split('\n')
  const meaningful = lines.filter((l) => l.trim().length > 0)
  if (meaningful.length === 0) {
    return { digest: '', totalLines: lines.length, shownLines: 0, omittedLines: 0 }
  }
  const head = meaningful.slice(0, headLines)
  const tail = meaningful.length > headLines * 2 ? meaningful.slice(-headLines) : []
  const middle = meaningful.length - head.length - tail.length
  const parts = [...head]
  if (middle > 0) parts.push('[…省略 ' + String(middle) + ' 行…]')
  parts.push(...tail)
  let digest = parts.join('\n')
  if (digest.length > maxChars) digest = digest.slice(0, maxChars) + '\n[…摘要已截断…]'
  return {
    digest,
    totalLines: lines.length,
    shownLines: head.length + tail.length,
    omittedLines: Math.max(0, middle),
  }
}
