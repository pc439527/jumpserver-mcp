/**
 * V0.5.2 — MCP progress notifications for multi-target work.
 *
 * A survey over 20 hosts with the `full` profile can stay silent for minutes:
 * the model sees one pending tool call and the user sees nothing at all. The
 * MCP spec already carries the fix — the client may attach a `progressToken`
 * to the request, and the server may answer with `notifications/progress`.
 *
 * Deliberately defensive about the shape of `extra`:
 *
 *  - A client that did NOT ask for progress (no `progressToken`) gets a no-op
 *    reporter, so no notification is ever sent uninvited.
 *  - `sendNotification` is probed rather than assumed; an older host that does
 *    not expose it degrades to the no-op instead of throwing mid-survey.
 *  - Notifications are fire-and-forget. Progress is a courtesy, and a failed
 *    report must never fail the tool call that is doing real work.
 */

/** Report one step. Safe to call unconditionally — it may be a no-op. */
export interface ProgressReporter {
  (progress: number, total: number, message: string): void
}

const NOOP: ProgressReporter = () => undefined

interface ProgressCapable {
  _meta?: { progressToken?: string | number }
  sendNotification?: (notification: unknown) => unknown
}

/**
 * Build a reporter from the MCP handler's `extra`.
 *
 * Typed as `unknown` on purpose: this runs against whatever the SDK handed
 * us, and the two fields it needs are optional in every protocol revision.
 */
export function progressReporter(extra: unknown): ProgressReporter {
  if (extra === null || typeof extra !== 'object') return NOOP
  const capable = extra as ProgressCapable
  const token = capable._meta?.progressToken
  if (token === undefined || token === null) return NOOP
  const send = capable.sendNotification
  if (typeof send !== 'function') return NOOP

  return (progress, total, message) => {
    try {
      void Promise.resolve(
        send.call(extra, {
          method: 'notifications/progress',
          params: { progressToken: token, progress, total, message },
        }),
      ).catch(() => undefined)
    } catch {
      /* progress is a courtesy — never let it break the tool call */
    }
  }
}
