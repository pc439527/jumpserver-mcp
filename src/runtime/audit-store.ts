/**
 * AuditStore (V0.4.0) — replaces "appendFileSync + readFileSync(whole file)
 * once per second" with:
 *
 *   append   asynchronous, serialized through a promise chain (never blocks
 *            the MCP tool call that produced the record)
 *   memory   bounded ring of the most recent N records (console queries the
 *            ring, not the file)
 *   tail     incremental read: only bytes after the last known offset are
 *            read, so a 200k-line JSONL costs nothing per poll
 *
 * The ring is filled EXCLUSIVELY from file reads, so a record can never be
 * duplicated by the writer's own optimistic copy. A poll therefore sees a new
 * record at most one tick later, which is exactly the console's refresh rate.
 */
import { appendFile } from 'node:fs/promises'
import { closeSync, openSync, readSync, renameSync, statSync, existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { aggregateDayMetrics } from './audit-metrics.js'

export const DEFAULT_AUDIT_RING_SIZE = 5000

/** V0.7.1 (D-7): how many days of rotated audit files to keep. */
export const DEFAULT_AUDIT_RETAIN_DAYS = 30

export interface AuditStoreOptions {
  /** Max records kept in memory for console queries (default 5000). */
  ringSize?: number
  log?: (message: string) => void
  /**
   * V0.7.1 (D-7): how many days of rotated files to keep. 0 disables the
   * retention sweep (the rotated files are then kept forever). Default 30.
   */
  retainDays?: number
  /** V0.7.1 (D-7): write a per-day aggregation file next to the audit file. Default true. */
  aggregate?: boolean
}

export interface AuditWindow {
  items: Record<string, unknown>[]
  /** Total records seen by this process (ring may hold fewer). */
  total: number
  /** True when the ring dropped older records. */
  windowed: boolean
}

/**
 * V0.5.10: one page of the audit stream, addressed by ABSOLUTE index. A
 * record's absolute index is the count of records this process had already
 * seen when it was parsed, so it stays stable across ring eviction: ring slot 0
 * is always absolute index `dropped`. A cursor therefore never needs to know
 * how much memory the ring still holds.
 */
export interface AuditPage {
  items: Record<string, unknown>[]
  /** Total records seen by this process (ring may hold fewer). */
  total: number
  /** Absolute index of the last item in this batch; equals `sinceIndex` when there are no new records. */
  nextIndex: number
  /** True when the ring dropped older records (`firstIndex` > 0). */
  windowed: boolean
  /** Absolute index of the oldest record still available (== records dropped). */
  firstIndex: number
}

export interface AuditArchiveResult {
  /** Path of the rotated file, or null when there was nothing to rotate / it failed. */
  archivedPath: string | null
  /** Records this process had seen before the rotation was attempted. */
  records: number
  /** Size of the archived file in bytes. */
  bytes: number
}

/**
 * V0.7.1 (D-7): the outcome of one day-boundary rotation.
 */
export interface AuditRotationResult {
  /** True when a rotation actually happened. */
  rotated: boolean
  /** The day that was closed out (YYYY-MM-DD). */
  day: string | null
  /** Path of the rotated daily file. */
  path: string | null
  /** Path of the daily aggregation file. */
  metricsPath: string | null
  /** Files removed by the retention sweep. */
  pruned: string[]
}

/** The day key of an audit record (UTC, YYYY-MM-DD). */
export function auditDayOf(record: Record<string, unknown>): string {
  const ts = String(record['timestamp'] ?? '')
  return ts.length >= 10 ? ts.slice(0, 10) : ''
}

/** File name of the rotated daily audit file. */
export function dailyAuditFileName(dir: string, day: string): string {
  return join(dir, 'audit-' + day + '.jsonl')
}

/** File name of the daily aggregation file. */
export function dailyMetricsFileName(dir: string, day: string): string {
  return join(dir, 'audit-metrics-' + day + '.json')
}

export class AuditStore {
  private readonly ring: Record<string, unknown>[] = []
  private readonly ringSize: number
  private readonly log: (message: string) => void
  private readonly retainDays: number
  private readonly aggregate: boolean
  private offset = 0
  private remainder = ''
  private totalSeen = 0
  private dropped = 0
  private chain: Promise<void> = Promise.resolve()

  constructor(
    private readonly file: string,
    options: AuditStoreOptions = {},
  ) {
    this.ringSize = Math.max(100, Math.floor(options.ringSize ?? DEFAULT_AUDIT_RING_SIZE))
    this.log = options.log ?? (() => undefined)
    this.retainDays = Math.max(0, Math.floor(options.retainDays ?? DEFAULT_AUDIT_RETAIN_DAYS))
    this.aggregate = options.aggregate ?? true
  }

  /** Queue one record for asynchronous, order-preserving append. */
  append(record: unknown): void {
    let line: string
    try {
      line = JSON.stringify(record) + '\n'
    } catch {
      return
    }
    this.chain = this.chain
      .then(() => appendFile(this.file, line, 'utf8'))
      .catch((error) => {
        this.log('audit append failed: ' + (error instanceof Error ? error.message : String(error)))
      })
  }

  /** Resolve once every queued append has been flushed to disk. Test seam. */
  flush(): Promise<void> {
    return this.chain
  }

  /** Read only the bytes appended since the last refresh (bounded, sync). */
  refresh(): void {
    let size: number
    try {
      size = statSync(this.file).size
    } catch {
      return
    }
    if (size < this.offset) {
      // Truncated / rotated / re-created: restart from the beginning.
      this.offset = 0
      this.remainder = ''
    }
    if (size === this.offset) return
    const length = size - this.offset
    let text: string
    try {
      const fd = openSync(this.file, 'r')
      try {
        const buf = Buffer.allocUnsafe(length)
        readSync(fd, buf, 0, length, this.offset)
        text = buf.toString('utf8')
      } finally {
        closeSync(fd)
      }
    } catch (error) {
      this.log('audit tail failed: ' + (error instanceof Error ? error.message : String(error)))
      return
    }
    this.offset = size
    const lines = (this.remainder + text).split('\n')
    this.remainder = lines.pop() ?? ''
    for (const line of lines) {
      if (line.trim().length === 0) continue
      try {
        const parsed = JSON.parse(line) as Record<string, unknown>
        this.push(parsed)
      } catch {
        /* a torn/truncated JSON line is skipped — the rest still parses */
      }
    }
  }

  private push(record: Record<string, unknown>): void {
    this.ring.push(record)
    this.totalSeen += 1
    while (this.ring.length > this.ringSize) {
      this.ring.shift()
      this.dropped += 1
    }
  }

  /**
   * V0.5.10: refresh, then return the records whose ABSOLUTE index is greater
   * than `sinceIndex`, capped at `limit` (oldest first). O(limit): only the
   * requested slice of the ring is copied, never the whole buffer. Records the
   * ring has already evicted cannot be returned — the caller detects that with
   * `sinceIndex + 1 < firstIndex`.
   */
  page(sinceIndex: number, limit: number): AuditPage {
    this.refresh()
    // -1 (or a non-finite cursor) means "from the very beginning": do NOT clamp
    // negatives to 0, or the caller would skip absolute index 0.
    const since = Number.isFinite(sinceIndex) ? Math.floor(sinceIndex) : -1
    const cap = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : this.ringSize
    // Ring slot 0 is absolute index `dropped`; anything older is gone for good.
    const startAbs = Math.max(since + 1, this.dropped)
    const lastAbs = this.totalSeen - 1
    let items: Record<string, unknown>[] = []
    if (startAbs <= lastAbs) {
      const offset = startAbs - this.dropped
      items = this.ring.slice(offset, offset + cap)
    }
    return {
      items,
      total: this.totalSeen,
      nextIndex: items.length > 0 ? startAbs + items.length - 1 : since,
      windowed: this.dropped > 0,
      firstIndex: this.dropped,
    }
  }

  /**
   * V0.5.10: rotate the live audit file.
   *   1. flush every queued append, so a record in flight is never orphaned;
   *   2. atomically rename the file to `<name>.<UTC stamp>.jsonl` in the SAME
   *      directory (a same-directory rename is atomic — no partial file, no copy);
   *   3. reset the tail offset / remainder / ring so the next refresh starts
   *      clean on the brand-new (initially absent) file.
   *
   * The rotated file is never deleted. A missing file is not an error: it
   * reports 0 archived records. Every failure is reported, never thrown.
   */
  async archive(): Promise<AuditArchiveResult> {
    try {
      await this.chain
    } catch {
      /* a failed append must not block the rotation */
    }
    // Bring totalSeen up to date with the file first: a caller that never read
    // the stream would otherwise archive a file full of records and report 0.
    this.refresh()
    let bytes: number
    try {
      bytes = statSync(this.file).size
    } catch {
      return { archivedPath: null, records: 0, bytes: 0 }
    }
    const records = this.totalSeen
    // ISO UTC, with the Windows-hostile ':' and '.' replaced so the name is a
    // valid filename on every platform.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    const archivedPath = this.file.replace(/\.jsonl$/i, '') + '.' + stamp + '.jsonl'
    try {
      renameSync(this.file, archivedPath)
    } catch (error) {
      this.log('audit archive failed: ' + (error instanceof Error ? error.message : String(error)))
      return { archivedPath: null, records: 0, bytes: 0 }
    }
    this.offset = 0
    this.remainder = ''
    this.ring.length = 0
    this.dropped = 0
    this.totalSeen = 0
    return { archivedPath, records, bytes }
  }

  /** Refresh, then return the in-memory window (newest last). */
  window(): AuditWindow {
    this.refresh()
    return { items: this.ring, total: this.totalSeen, windowed: this.dropped > 0 }
  }

  /** Refresh-independent read for one-off callers (jumpserver_audit). */
  list(): Record<string, unknown>[] {
    this.refresh()
    return [...this.ring]
  }

  /**
   * V0.7.1 (D-7): rotate the live audit file on a DAY boundary.
   *
   * Why by day: the audit file is append-only and grew without bound — the
   * real one held 7235 records over 44 days. A single file that keeps growing
   * is a file nobody reads; a file per day is a file you can open, diff and
   * delete.
   *
   * The rotation:
   *   1. flush every queued append (no record may be orphaned);
   *   2. if the live file is empty, there is nothing to rotate;
   *   3. rename the live file to `audit-<day>.jsonl` in the SAME directory
   *      (atomic — no copy, no partial file);
   *   4. write `audit-metrics-<day>.json` — the day's aggregate (D-8 model),
   *      so a month of history costs kilobytes;
   *   5. sweep the directory and delete daily files older than `retainDays`.
   *
   * Everything is best-effort: a failed rotation is reported, never thrown.
   * The audit sink must not be able to break a tool call.
   */
  async rotateForDay(day: string): Promise<AuditRotationResult> {
    const none: AuditRotationResult = { rotated: false, day: null, path: null, metricsPath: null, pruned: [] }
    try {
      await this.chain
    } catch {
      /* a failed append must not block the rotation */
    }
    let bytes: number
    try {
      bytes = statSync(this.file).size
    } catch {
      return none
    }
    if (bytes === 0) return none

    const dir = dirname(this.file)
    const target = dailyAuditFileName(dir, day)
    try {
      renameSync(this.file, target)
    } catch (error) {
      this.log('audit day rotation failed: ' + (error instanceof Error ? error.message : String(error)))
      return none
    }
    // The tail offset no longer refers to the live file (it was renamed away).
    this.offset = 0
    this.remainder = ''

    let metricsPath: string | null = null
    if (this.aggregate) {
      try {
        const records = readJsonlRecords(target)
        const metrics = aggregateDayMetrics(day, records)
        const file = dailyMetricsFileName(dir, day)
        writeFileSync(file, JSON.stringify(metrics, null, 2), 'utf8')
        metricsPath = file
      } catch (error) {
        this.log('audit daily metrics failed: ' + (error instanceof Error ? error.message : String(error)))
      }
    }

    const pruned = this.pruneOldDays(dir, day)
    return { rotated: true, day, path: target, metricsPath, pruned }
  }

  /**
   * V0.7.1 (D-7): delete the daily files older than the retention window.
   *
   * Only files this rotation scheme created are touched — `audit-<day>.jsonl`
   * and `audit-metrics-<day>.json`. The manual `archive()` files
   * (`audit.<stamp>.jsonl`) and the live file are NEVER deleted: the manual
   * archive is an explicit operator action and must not vanish behind a
   * retention sweep.
   */
  private pruneOldDays(dir: string, today: string): string[] {
    const retainDays = this.retainDays
    if (retainDays <= 0) return []
    const removed: string[] = []
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return []
    }
    for (const name of names) {
      const match = /^audit-(?:metrics-)?(\d{4}-\d{2}-\d{2})(?:\.jsonl|\.json)$/.exec(name)
      if (match === null) continue
      const day = match[1]!
      if (day >= today) continue
      const age = daysBetween(day, today)
      if (age <= retainDays) continue
      const file = join(dir, name)
      try {
        unlinkSync(file)
        removed.push(file)
      } catch (error) {
        this.log('audit prune failed: ' + (error instanceof Error ? error.message : String(error)))
      }
    }
    return removed
  }
}

/** Read every JSON record of a JSONL file (best effort). */
export function readJsonlRecords(file: string): Record<string, unknown>[] {
  let text: string
  try {
    text = readFileSync(file, 'utf8')
  } catch {
    return []
  }
  const out: Record<string, unknown>[] = []
  for (const line of text.split('\n')) {
    if (line.trim().length === 0) continue
    try {
      out.push(JSON.parse(line) as Record<string, unknown>)
    } catch {
      /* a torn line is skipped */
    }
  }
  return out
}

/** Whole days between two YYYY-MM-DD keys (b - a). */
export function daysBetween(a: string, b: string): number {
  const ta = Date.parse(a + 'T00:00:00Z')
  const tb = Date.parse(b + 'T00:00:00Z')
  if (Number.isNaN(ta) || Number.isNaN(tb)) return 0
  return Math.round((tb - ta) / 86400000)
}
