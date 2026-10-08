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
import { closeSync, openSync, readSync, renameSync, statSync } from 'node:fs'

export const DEFAULT_AUDIT_RING_SIZE = 5000

export interface AuditStoreOptions {
  /** Max records kept in memory for console queries (default 5000). */
  ringSize?: number
  log?: (message: string) => void
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

export class AuditStore {
  private readonly ring: Record<string, unknown>[] = []
  private readonly ringSize: number
  private readonly log: (message: string) => void
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
}
