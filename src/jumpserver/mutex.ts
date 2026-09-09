/** Single-session serial queue: connect/enter/exec/leave all run one at a time. */
export class SessionMutex {
  private tail: Promise<unknown> = Promise.resolve()

  /**
   * Enqueue fn behind every previous operation. If signal aborts while
   * WAITING for the queue, the queued call is dropped (never executed).
   */
  async run<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    let release!: () => void
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const prev = this.tail
    this.tail = gate
    await prev
    if (signal?.aborted === true) {
      release()
      throw new Error('ABORTED')
    }
    try {
      return await fn()
    } finally {
      release()
    }
  }
}
