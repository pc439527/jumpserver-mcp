/**
 * V0.5.13: console tab visibility preferences written by the console itself.
 *
 * WHY A SECOND STORE. `config.json` already has `auditViewer.tabs` and it
 * remains the authority — but config.json belongs to the operator: the
 * connector form rewrites it, re-binding can restore an older copy, and the
 * file is not always writable. The field request was "switch the tabs off IN
 * THE SETTINGS TAB", so the console needs a place of its own to persist a
 * click. Keeping it separate is also what makes the precedence explainable
 * instead of a mystery: two layers, one rule.
 *
 * PRECEDENCE (implemented in resolveConsoleTabs):
 *   1. an explicit true/false in config.json `auditViewer.tabs` — wins, and is
 *      reported to the UI as locked rather than silently overridden;
 *   2. this file — the switches in the 设置 tab;
 *   3. default: visible.
 * `settings` can never be hidden by either layer (see ALWAYS_ON_CONSOLE_TABS).
 *
 * Reads NEVER throw: a corrupt file is reported through integrity() and simply
 * reads as "nothing hidden", because a broken UI preference must not take the
 * console down. Writes REFUSE to run while the on-disk file is corrupt, exactly
 * like ProfileStore — the operator has to look at it, not have it replaced.
 *
 * Zero dependencies (node:fs / node:os / node:path). No secret is ever stored
 * here: the file is a list of tab ids.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { ALWAYS_ON_CONSOLE_TABS, CONSOLE_TAB_IDS, type ConsoleTabId } from '../config/types.js'

const FILE_VERSION = 1

export interface ConsolePrefsOptions {
  /** Defaults to ~/.workbuddy/jumpserver-mcp/console-prefs.json */
  filePath?: string
  log?: (message: string) => void
}

export interface ConsolePrefsFile {
  version: number
  hiddenTabs: ConsoleTabId[]
}

export interface ConsolePrefsIntegrity {
  broken: boolean
  message: string | null
}

/** Structured write outcome — the console renders `error` instead of guessing. */
export type ConsolePrefsWriteResult = { ok: true } | { ok: false; error: string }

export function defaultConsolePrefsFilePath(): string {
  return join(homedir(), '.workbuddy', 'jumpserver-mcp', 'console-prefs.json')
}

/** A display path for the 设置 tab; never an absolute machine path in the UI. */
export function consolePrefsPathHint(): string {
  return '~/.workbuddy/jumpserver-mcp/console-prefs.json'
}

export class ConsolePrefsStore {
  private readonly filePath: string
  private readonly log: (message: string) => void
  private broken = false
  private brokenMessage: string | null = null

  constructor(options: ConsolePrefsOptions = {}) {
    this.filePath = options.filePath ?? defaultConsolePrefsFilePath()
    this.log = options.log ?? (() => undefined)
  }

  /** The hidden ids, in CONSOLE_TAB_IDS order. Never throws. */
  hidden(): ConsoleTabId[] {
    const file = this.load()
    return CONSOLE_TAB_IDS.filter((id) => file.hiddenTabs.includes(id))
  }

  /**
   * The local layer, in the shape resolveConsoleTabs consumes:
   * `{ stats: false }` for every hidden tab. An EMPTY object (not undefined)
   * for "the operator has not touched anything", so callers never have to
   * distinguish "no preference" from "empty preference file".
   */
  visibility(): Partial<Record<ConsoleTabId, boolean>> {
    const out: Partial<Record<ConsoleTabId, boolean>> = {}
    for (const id of this.hidden()) out[id] = false
    return out
  }

  integrity(): ConsolePrefsIntegrity {
    this.load()
    return { broken: this.broken, message: this.brokenMessage }
  }

  /**
   * Persist one tab's visibility. `settings` (and any other always-on tab) is
   * refused rather than accepted-and-ignored, so the UI can never end up
   * showing a switch whose effect is silently discarded.
   */
  setHidden(id: string, hidden: boolean): ConsolePrefsWriteResult {
    if (!(CONSOLE_TAB_IDS as readonly string[]).includes(id)) {
      return { ok: false, error: 'INVALID_ARGUMENT' }
    }
    if (ALWAYS_ON_CONSOLE_TABS.includes(id as ConsoleTabId)) {
      return { ok: false, error: 'TAB_ALWAYS_VISIBLE' }
    }
    const file = this.load()
    if (this.broken) return { ok: false, error: 'PREFS_FILE_UNREADABLE' }
    const tab = id as ConsoleTabId
    const next = hidden
      ? CONSOLE_TAB_IDS.filter((candidate) => candidate === tab || file.hiddenTabs.includes(candidate))
      : file.hiddenTabs.filter((candidate) => candidate !== tab)
    try {
      this.write({ version: FILE_VERSION, hiddenTabs: next })
    } catch {
      return { ok: false, error: 'PREFS_WRITE_FAILED' }
    }
    return { ok: true }
  }

  private load(): ConsolePrefsFile {
    const wasBroken = this.broken
    this.broken = false
    this.brokenMessage = null
    const file = this.parse()
    if (this.broken && !wasBroken) {
      this.log('console preferences unusable: ' + (this.brokenMessage ?? 'unknown reason'))
    }
    return file
  }

  /**
   * Tolerant read. A missing or empty file is "nothing hidden"; anything
   * unreadable, non-JSON or structurally wrong sets the broken flag and yields
   * the same empty result, so a bad file degrades to defaults instead of
   * throwing inside a page render.
   */
  private parse(): ConsolePrefsFile {
    const empty: ConsolePrefsFile = { version: FILE_VERSION, hiddenTabs: [] }
    if (!existsSync(this.filePath)) return empty
    let raw: string
    try {
      raw = readFileSync(this.filePath, 'utf8')
    } catch {
      this.markBroken('file could not be read')
      return empty
    }
    if (raw.trim().length === 0) return empty
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      this.markBroken('file is not valid JSON')
      return empty
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      this.markBroken('file has an unexpected structure')
      return empty
    }
    const rawTabs = (parsed as { hiddenTabs?: unknown }).hiddenTabs
    if (rawTabs !== undefined && !Array.isArray(rawTabs)) {
      this.markBroken('hiddenTabs is not an array')
      return empty
    }
    // Unknown ids are dropped rather than reported: the tab table is code and
    // may legitimately shrink, and a stale id must not brick the console.
    const hiddenTabs = (rawTabs ?? []).filter(
      (value): value is ConsoleTabId => typeof value === 'string' && (CONSOLE_TAB_IDS as readonly string[]).includes(value),
    )
    return { version: FILE_VERSION, hiddenTabs: CONSOLE_TAB_IDS.filter((id) => hiddenTabs.includes(id)) }
  }

  private markBroken(message: string): void {
    this.broken = true
    this.brokenMessage = message
  }

  /** Atomic write: full content to `<file>.tmp`, then rename over the target. */
  private write(file: ConsolePrefsFile): void {
    mkdirSync(dirname(this.filePath), { recursive: true })
    const temp = this.filePath + '.tmp'
    try {
      writeFileSync(temp, JSON.stringify(file, null, 2), 'utf8')
      renameSync(temp, this.filePath)
    } catch (error) {
      try {
        if (existsSync(temp)) unlinkSync(temp)
      } catch {
        /* ignore */
      }
      throw error
    }
  }
}
