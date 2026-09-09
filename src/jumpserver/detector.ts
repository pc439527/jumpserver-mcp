import { cleanAnsi } from './output-buffer.js'

/** What the current screen looks like, per a bounded normalized tail. */
export type ScreenState = 'JUMPSERVER_MENU' | 'ASSET_SHELL' | undefined

const SHELL_PROMPT_PATTERN = /(?:^|\n)\[?[a-zA-Z0-9_.-]+(?:@[a-zA-Z0-9_.-]+)?[ :~\/\\][^\n]*[$#] ?$/m
const NUMBERED_LINE_PATTERN = /(?:^|\n)\s*\d+[.)]\s+\S/m
const BOX_PATTERN = /[\u2500-\u257F]/u

/** True when the tail looks like a real shell prompt (asset shell). */
function looksLikeShellPrompt(tail: string): boolean {
  // Only inspect the last ~600 chars; a prompt is the final line.
  const window = tail.slice(-600)
  const lines = window.split('\n').filter((l) => l.trim().length > 0)
  if (lines.length === 0) return false
  const last = lines[lines.length - 1]!.trimEnd()
  if (last.length === 0 || last.length > 260) return false
  // Prompt ends with '$' / '#' (bash family). Root '# ' also fine.
  if (!/[$#] ?$/.test(last)) return false
  return SHELL_PROMPT_PATTERN.test('\n' + window)
}

/** True when the tail shows a JumpServer/KoKo terminal menu. */
function looksLikeMenu(tail: string): boolean {
  const lower = tail.toLowerCase()
  const box = BOX_PATTERN.test(tail)
  const numbered = NUMBERED_LINE_PATTERN.test(tail)
  const idleHint = /idle\s*timeout/i.test(lower)
  const chineseMenu = /请输入|编号|资产名|菜单|选择|回车|退出/i.test(tail)
  const hostPrompt = /\b(?:input|search|connect)\b/i.test(lower)
  const exitHint = /(?:^|\n)\s*(?:\[?\s*0\s*\]?\s*)?(?:\(?exit\)?|退出)\s*(?:菜单|menu)?/i.test(tail)
  const koko = /koko|jumpserver|堡垒机|Opt[>#]\s/iy.test(tail) || /(?:^|\n)\s*(?:Opt|\[[A-Za-z0-9._-]+\])\s*[>#]\s/.test(tail)

  // Require a combination to avoid single-string false positives.
  const scores = [box, numbered, idleHint, chineseMenu].filter(Boolean).length
  if (scores >= 2) return true
  if (box && chineseMenu) return true
  if (box && exitHint) return true
  if (numbered && idleHint) return true
  if (box && (koko || hostPrompt)) return true
  return false
}

/**
 * Heavy-screen detector: keeps a bounded normalized tail and answers
 * 'JUMPSERVER_MENU' vs 'ASSET_SHELL' vs unknown. Unbiased to any single
 * string; shell-prompt detection runs FIRST so a live shell never reads as
 * a menu.
 */
export class ScreenDetector {
  private tail = ''

  constructor(private readonly maxTail = 8192) {}

  push(chunk: string): void {
    this.tail = (this.tail + cleanAnsi(chunk)).slice(-this.maxTail)
  }

  detect(): ScreenState {
    if (looksLikeShellPrompt(this.tail)) return 'ASSET_SHELL'
    if (looksLikeMenu(this.tail)) return 'JUMPSERVER_MENU'
    return undefined
  }

  /** Debug aid: last N normalized chars, for fixture capture. */
  tailPreview(n = 400): string {
    return this.tail.slice(-n)
  }

  reset(): void {
    this.tail = ''
  }
}
