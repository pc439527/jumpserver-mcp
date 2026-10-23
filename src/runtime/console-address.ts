/**
 * V0.7.2 (E-4): the console address must not BREAK when a process dies.
 *
 * The failure this fixes (N-15): the handover URL was
 * `http://127.0.0.1:8765/?inst=<pid>`. The pid is the identity of ONE MCP
 * process. Measured on this workspace: the owner of port 8765 changed THREE
 * times inside 25 minutes (each MCP process restart takes the address over).
 * A URL pinned to the old pid then named an instance that no longer existed,
 * and the preview panel reported 「暂无数据」 — which looked like a rendering
 * bug and was actually a dead pointer.
 *
 * The pin STAYS. It is what keeps an operator inside their OWN terminal
 * instead of a stranger's (the V0.5.8 identity fix), and that identity
 * problem is worse than the staleness problem:
 *
 *  - Without the pin, two conversations share one address and the operator
 *    sees somebody else's session, with buttons that act on it.
 *  - With a stale pin, the operator sees an empty frame — confusing, but
 *    harmless and obvious.
 *
 * So the fix is not "remove the pin" but "make the pin heal": a pin that no
 * longer resolves redirects to the live console and says which instance died.
 *
 * Two properties this module guarantees:
 *
 *  1. **The published address never depends on the instance list.** The pin
 *     is always this process's own pid — the one thing known to be true at
 *     mint time. Deriving "should I pin?" from the list of live instances
 *     would introduce a race: a second conversation starting a millisecond
 *     later would change the answer, and the URL already handed out would
 *     point at the wrong console. That race is worse than the bug it fixes.
 *
 *  2. **A dead pin heals.** `isPinLive` decides whether the pin still
 *     resolves; `stalePinFallback` produces the address to redirect to.
 */

/** The minimal shape of a live console instance. */
export interface ConsoleInstanceLike {
  pid: number
  port: number
  role: string
}

export type ConsoleAddressReason =
  /** Legacy mode: the token is in the URL, one address per process. */
  | 'legacy'
  /** Stable mode: the shared address, pinned to this process. */
  | 'stable-pinned'

export interface ConsoleAddress {
  /** The URL to hand to the model / the operator. */
  url: string | null
  /** True when the URL pins a specific process. */
  pinned: boolean
  /** The pinned pid, when pinned. */
  pinnedPid: number | null
  /** Why this shape was chosen. */
  reason: ConsoleAddressReason
}

/**
 * Decide the address to publish.
 *
 * @param viewerUrl      the stable address of this workspace's console
 * @param selfPid        this process's pid
 * @param stableAddress  false in legacy mode (token in the URL, one port per process)
 */
export function consoleAddressFor(
  viewerUrl: string | null,
  selfPid: number,
  stableAddress: boolean,
): ConsoleAddress {
  if (viewerUrl === null) {
    return { url: null, pinned: false, pinnedPid: null, reason: 'legacy' }
  }
  if (!stableAddress) {
    // Legacy: the token already identifies the process. Adding ?inst= would
    // be a second, contradicting identity on the same URL.
    return { url: viewerUrl, pinned: false, pinnedPid: null, reason: 'legacy' }
  }
  const sep = viewerUrl.includes('?') ? '&' : '?'
  return {
    url: viewerUrl + sep + 'inst=' + String(selfPid),
    pinned: true,
    pinnedPid: selfPid,
    reason: 'stable-pinned',
  }
}

/**
 * Is a `?inst=` pin still pointing at something alive?
 *
 * Returns true when the pin is USABLE (it names this process, or a live
 * instance). Returns false when it names a pid that no longer exists — the
 * stale case the page has to heal from.
 *
 * A pin that names an unknown pid is NOT an error: the caller redirects to
 * the live console, because "the instance you asked for is gone" is
 * information, not a failure.
 */
export function isPinLive(openPid: number | null, selfPid: number, instances: ConsoleInstanceLike[]): boolean {
  if (openPid === null || !Number.isFinite(openPid) || openPid <= 0) return false
  if (openPid === selfPid) return true
  return instances.some((item) => item.pid === openPid)
}

/**
 * The URL a stale pin should fall back to.
 *
 * When `?inst=` names a dead process, the browser is sent to the bare stable
 * address: the current owner's console, which is alive. The `?gone=` marker
 * is carried along so the page can still tell the operator WHY the instance
 * they expected is not there — a silent redirect would look like a different
 * console had replaced it.
 */
export function stalePinFallback(viewerUrl: string | null, openPid: number | null): string | null {
  if (viewerUrl === null) return null
  if (openPid === null || !Number.isFinite(openPid) || openPid <= 0) return viewerUrl
  const sep = viewerUrl.includes('?') ? '&' : '?'
  return viewerUrl + sep + 'gone=' + String(Math.trunc(openPid))
}
