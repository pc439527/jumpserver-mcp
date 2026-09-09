/** ANSI escape stripping: CSI, OSC, and C1 control sequences. */
const ANSI_PATTERN =
  /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][AB0]|\x1b[@-Z\\-_]/g

/** Normalize CRLF/CR to LF. */
export function normalizeNewlines(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

/** Strip ANSI escapes then normalize newlines. */
export function cleanAnsi(text: string): string {
  return normalizeNewlines(text.replace(ANSI_PATTERN, ''))
}

/** Bounded line-buffer for one operation's captured stdout (1 MiB cap). */
export class OutputBuffer {
  private chunks: string[] = []
  private total = 0
  truncated = false

  constructor(private readonly limit: number) {}

  push(chunk: string): void {
    const text = cleanAnsi(chunk)
    if (text.length === 0) return
    this.chunks.push(text)
    this.total += text.length
    while (this.total > this.limit && this.chunks.length > 0) {
      this.truncated = true
      const head = this.chunks[0]!
      if (this.total - head.length >= this.limit) {
        this.total -= head.length
        this.chunks.shift()
      } else {
        const drop = this.total - this.limit
        this.chunks[0] = head.slice(drop)
        this.total -= drop
        break
      }
    }
  }

  peek(): string {
    return this.chunks.join('')
  }

  take(): { text: string; truncated: boolean } {
    const text = this.chunks.join('')
    this.clear()
    return { text, truncated: this.truncated }
  }

  clear(): void {
    this.chunks = []
    this.total = 0
    this.truncated = false
  }

  get size(): number {
    return this.total
  }
}

/**
 * Waits for a marker pattern across arbitrarily fragmented data chunks.
 * Matching is incremental on a bounded tail; once matched it stays matched
 * until reset. Feed the SAME chunks through buffer.push() to capture output.
 */
export class MarkerWatcher {
  private tail = ''
  private done = false
  readonly buffer: OutputBuffer

  constructor(
    private readonly marker: string,
    limit: number,
  ) {
    this.buffer = new OutputBuffer(limit)
  }

  /** Feed one raw chunk; returns true on the tick the marker becomes visible. */
  push(chunk: string): boolean {
    const text = cleanAnsi(chunk)
    this.buffer.push(chunk)
    if (this.done) return false
    this.tail = (this.tail + text).slice(-(this.marker.length + 4096))
    if (this.tail.includes(this.marker)) this.done = true
    return this.done
  }

  matched(): boolean {
    return this.done
  }

  reset(): void {
    this.tail = ''
    this.done = false
    this.buffer.clear()
  }
}

/** Remove every line that contains needle (our own markers) from text. */
export function stripMarkerLines(text: string, needle: string): string {
  return text
    .split('\n')
    .filter((line) => !line.includes(needle))
    .join('\n')
}
