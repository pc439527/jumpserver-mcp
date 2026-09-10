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
import { closeSync, openSync, readSync, statSync } from 'node:fs'

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
