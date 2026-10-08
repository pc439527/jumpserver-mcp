/**
 * V0.5.9: console tab visibility — pure logic, no IO, no side effects.
 *
 * These are UI VISIBILITY switches, not permission switches. Hiding a tab
 * removes its nav button, its section and its client-side polling; it does NOT
 * loosen or tighten access control. Every /api/* route of the console stays
 * behind its own protection (per-process access token + same-origin checks),
 * and the audit trail keeps being written to disk regardless of whether the
 * `audit` tab is rendered. A hidden tab is hidden from the operator's own UI,
 * nothing more.
 *
 * V0.5.13 added a SECOND preference layer (the console's own store, written by
 * the switches in the 设置 tab) on top of config.json. Both layers, and the
 * precedence between them, live here so the nav rendering, the section
 * rendering, the hash router and the settings UI can never disagree:
 * the router reuses `isConsoleTabVisible()`, which is defined in terms of
 * `resolveConsoleTabs()`.
 */
import { ALWAYS_ON_CONSOLE_TABS, CONSOLE_TAB_IDS, type ConsoleTabId } from '../config/types.js'

/**
 * The tabs that should be shown, in navigation order.
 *
 * Two layers of preference, in this order:
 *   1. `configured` — config.json `auditViewer.tabs`. An explicit `true` OR
 *      `false` wins: the operator's own file outranks a click in the browser,
 *      and the UI marks such a tab as locked so nobody wonders why the switch
 *      does nothing.
 *   2. `local` — the console's own store (`console-prefs.json`), written by the
 *      switches in the 设置 tab (V0.5.13).
 *   3. default — visible.
 *
 * `settings` is always kept, whatever either layer says: it is the console's
 * only explanation and diagnostics entry point AND the page that documents
 * these very switches, so a console without it is a console with no way back.
 * The rule is applied HERE, unconditionally, rather than trusting callers to
 * respect it, so no preference can produce a console without a settings tab.
 */
export function resolveConsoleTabs(
  configured?: Partial<Record<ConsoleTabId, boolean>>,
  local?: Partial<Record<ConsoleTabId, boolean>>,
): ConsoleTabId[] {
  const visible: ConsoleTabId[] = []
  for (const id of CONSOLE_TAB_IDS) {
    if (ALWAYS_ON_CONSOLE_TABS.includes(id)) {
      visible.push(id)
      continue
    }
    const pinned = configured?.[id]
    if (pinned === false) continue
    if (pinned === true) {
      visible.push(id)
      continue
    }
    if (local?.[id] === false) continue
    visible.push(id)
  }
  return visible
}

/** Which layer decided one tab's visibility. */
export type ConsoleTabSource = 'always' | 'config' | 'local' | 'default'

/**
 * Where a tab's current visibility comes from. The 设置 tab renders a locked,
 * non-interactive row for `config` and `always`, so a switch that cannot win is
 * never offered as if it could.
 */
export function consoleTabSource(
  id: ConsoleTabId,
  configured?: Partial<Record<ConsoleTabId, boolean>>,
  local?: Partial<Record<ConsoleTabId, boolean>>,
): ConsoleTabSource {
  if (ALWAYS_ON_CONSOLE_TABS.includes(id)) return 'always'
  if (configured?.[id] !== undefined) return 'config'
  if (local?.[id] !== undefined) return 'local'
  return 'default'
}

/** The source of every tab, keyed by id — one lookup for the whole nav. */
export function consoleTabSources(
  configured?: Partial<Record<ConsoleTabId, boolean>>,
  local?: Partial<Record<ConsoleTabId, boolean>>,
): Record<ConsoleTabId, ConsoleTabSource> {
  const out = {} as Record<ConsoleTabId, ConsoleTabSource>
  for (const id of CONSOLE_TAB_IDS) out[id] = consoleTabSource(id, configured, local)
  return out
}

/**
 * Whether one tab is visible. Defined as membership in `resolveConsoleTabs()`
 * so the hash router and the section renderer share a single judgement — a
 * hidden tab can never be reached by typing its hash, because the router and
 * the renderer ask this same question.
 */
export function isConsoleTabVisible(
  id: ConsoleTabId,
  configured?: Partial<Record<ConsoleTabId, boolean>>,
  local?: Partial<Record<ConsoleTabId, boolean>>,
): boolean {
  return resolveConsoleTabs(configured, local).includes(id)
}

/**
 * Which tab a request for `requested` should actually land on.
 *
 * The request (a URL hash, usually) is honoured only when it names a VISIBLE
 * tab; otherwise the first visible tab is used. This is what keeps an unknown
 * hash (`#nonsense`) and the hash of a hidden tab from carrying the operator
 * to a section that is not rendered. The list cannot be empty in practice
 * (`settings` is always in it), but the `'terminal'` fallback is kept as the
 * belt-and-braces answer for callers that pass a list they built themselves.
 */
export function pickLandingTab(requested: string, visible: readonly ConsoleTabId[]): ConsoleTabId {
  if (visible.length === 0) return 'terminal'
  if ((visible as readonly string[]).includes(requested)) return requested as ConsoleTabId
  return visible[0] ?? 'terminal'
}
