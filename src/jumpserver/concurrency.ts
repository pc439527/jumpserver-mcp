/**
 * Bounded-concurrency helpers (V0.4.1).
 *
 * A multi-target survey (inspect / topology / compare / baseline) visits many
 * hosts. Sequential is the safe default, but on a large estate it is slow.
 * These helpers let a caller raise concurrency up to a hard ceiling while
 * keeping the failure semantics identical to the sequential path:
 *
 *  - the RESULT ORDER always matches the INPUT ORDER (callers index results),
 *  - one item's failure never aborts its siblings (the task returns its own
 *    error value, exactly like the sequential loop would),
 *  - the whole run aborts promptly when the signal fires.
 *
 * Nothing here touches the bastion; it only schedules async work.
 */
import { AbortRequestedError } from '../jumpserver/errors.js'

export interface MapOptions {
  /** 1..ceiling; values < 1 are treated as 1. */
  concurrency: number
  signal?: AbortSignal
}

/**
 * Map `items` through `worker` with bounded concurrency, preserving input
 * order. `worker` is expected to resolve to a per-item value (including a
 * per-item error value) — a thrown error rejects the whole call, so callers
 * that want per-item isolation must catch inside the worker.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  worker: (item: T, index: number) => Promise<R>,
  options: MapOptions,
): Promise<R[]> {
  const limit = Math.max(1, Math.floor(options.concurrency))
  const results = new Array<R>(items.length)
  if (items.length === 0) return results
  let next = 0
  let aborted = false
  const runOne = async (): Promise<void> => {
    for (;;) {
      if (options.signal?.aborted === true) {
        aborted = true
        return
      }
      const index = next
      next += 1
      if (index >= items.length) return
      results[index] = await worker(items[index]!, index)
    }
  }
  const workers: Array<Promise<void>> = []
  for (let i = 0; i < Math.min(limit, items.length); i += 1) workers.push(runOne())
  await Promise.all(workers)
  if (aborted) throw new AbortRequestedError()
  return results
}

/**
 * V0.4.1 session-pool gate: at most `size` concurrent holders. Used to cap
 * simultaneous bastion sessions independent of how many batches run.
 */
export class Semaphore {
  private available: number
  private readonly waiters: Array<() => void> = []

  constructor(size: number) {
    this.available = Math.max(1, Math.floor(size))
  }

  get capacity(): number {
    return this.available + this.waiters.length
  }

  async acquire(): Promise<() => void> {
    if (this.available > 0) {
      this.available -= 1
      return this.releaser()
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve))
    return this.releaser()
  }

  private releaser(): () => void {
    let released = false
    return () => {
      if (released) return
      released = true
      const next = this.waiters.shift()
      if (next !== undefined) {
        next()
      } else {
        this.available += 1
      }
    }
  }
}
