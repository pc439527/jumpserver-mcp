/**
 * V0.7.2 (E-5): the asset alias reverse-lookup cache.
 *
 * The problem (N-17): the asset list and the asset the operator means are
 * not the same string. On this workspace the authorized assets carry names
 * like `s113181_BI节点2` while the people who own them say `BI-02`, and the
 * list shows an IP whose asset name is a DIFFERENT machine. Four ESB
 * environments had four such systematic mismatches.
 *
 * The consequence was brutal in practice: `jumpserver_run` with a target the
 * operator named returned `ASSET_NOT_FOUND` — a bare "no such asset" — while
 * the asset was right there in the list under a different label. The model
 * had no way to close the loop, so it either guessed (and guessed wrong) or
 * asked the user to paste the exact string.
 *
 * The fix has two halves:
 *
 *  1. **A cache of the last known listing**, persisted to disk so it
 *     survives a connector restart. KoKo's `p` output is the ground truth
 *     about what this account may use; keeping it means "what CAN I run on"
 *     is answerable without another PTY round-trip.
 *
 *  2. **A reverse lookup** from any alias the operator might use — an IP, a
 *     partial name, a name with different separators/case — back to the
 *     asset row it means. When a target does not resolve, the error names
 *     the closest candidates instead of shrugging.
 *
 * The matching is deliberately CONSERVATIVE. It is a suggestion channel, not
 * an auto-correct channel: the tool never silently rewrites a target. An
 * operator who typed `BI-02` and got `s113181_BI节点2` executed against a
 * different machine without noticing — that is worse than a clear error.
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { AssetEntry } from '../jumpserver/asset-list.js'

/** One cached asset, with the aliases it answers to. */
export interface AliasRecord {
  /** The asset's display name as KoKo printed it. */
  name: string
  /** The IP column, when the row had one. */
  ip: string | null
  /** The platform column (pipe layout). */
  platform: string | null
  /** The node/location column (pipe layout). */
  node: string | null
  /** The comment column (whitespace layout). */
  comment: string | null
  /** Lowercased name — the primary lookup key. */
  nameKey: string
  /** The IP as a lookup key. */
  ipKey: string | null
}

/** Why a candidate was proposed. */
export type AliasMatchKind =
  /** The alias equals the asset name (case-insensitive). */
  | 'exact-name'
  /** The alias equals the asset IP. */
  | 'exact-ip'
  /** The asset name contains the alias, or the alias contains the name. */
  | 'name-substring'
  /** The alias matches after separators/case are normalized away. */
  | 'normalized'
  /** The alias shares a long enough prefix with the name. */
  | 'prefix'

export interface AliasCandidate {
  name: string
  ip: string | null
  kind: AliasMatchKind
  /** 0..1 — how close the match is. Higher is better. */
  score: number
}

export interface AliasIndex {
  /** When the listing was captured. */
  updatedAt: number
  /** How many assets are indexed. */
  count: number
  records: AliasRecord[]
}

/** Normalize an alias for comparison: lowercase, collapse separators. */
export function normalizeAlias(value: string): string {
  return value
    .toLowerCase()
    .replace(/[\s_\-.]+/g, '')
    .trim()
}

/** Build the lookup records for a listing. */
export function buildAliasIndex(assets: AssetEntry[], updatedAt: number): AliasIndex {
  const records: AliasRecord[] = assets.map((asset) => ({
    name: asset.name,
    ip: asset.ip,
    platform: asset.platform,
    node: asset.node,
    comment: asset.comment,
    nameKey: normalizeAlias(asset.name),
    ipKey: asset.ip === null || asset.ip.length === 0 ? null : asset.ip.trim().toLowerCase(),
  }))
  return { updatedAt, count: records.length, records }
}

/**
 * Find the assets an alias most plausibly means.
 *
 * The scoring is deliberately explainable — each candidate carries the KIND
 * of match, so the error message can say WHY it proposed that asset. A
 * score without a reason is not actionable, and an unranked list of 134
 * assets is not either.
 */
export function findAliasCandidates(index: AliasIndex, alias: string, limit = 5): AliasCandidate[] {
  const term = alias.trim()
  if (term.length === 0 || index.records.length === 0) return []
  const lower = term.toLowerCase()
  const termNorm = normalizeAlias(term)
  const out: AliasCandidate[] = []

  for (const record of index.records) {
    if (record.ipKey !== null && record.ipKey === lower) {
      out.push({ name: record.name, ip: record.ip, kind: 'exact-ip', score: 1 })
      continue
    }
    if (record.nameKey === termNorm) {
      out.push({ name: record.name, ip: record.ip, kind: 'exact-name', score: 0.99 })
      continue
    }
    if (record.nameKey.length > 0 && record.nameKey.includes(termNorm)) {
      // The alias is a fragment of the asset name ("bi02" ⊂ "s113181bi节点2").
      const ratio = termNorm.length / record.nameKey.length
      out.push({ name: record.name, ip: record.ip, kind: 'name-substring', score: 0.5 + ratio * 0.3 })
      continue
    }
    if (termNorm.length > 0 && termNorm.includes(record.nameKey) && record.nameKey.length > 0) {
      const ratio = record.nameKey.length / termNorm.length
      out.push({ name: record.name, ip: record.ip, kind: 'name-substring', score: 0.45 + ratio * 0.3 })
      continue
    }
    // Prefix match: at least 4 normalized characters in common. Shorter
    // prefixes match too much to be a suggestion ("oa" would match dozens).
    const prefixLen = commonPrefixLength(record.nameKey, termNorm)
    if (prefixLen >= 4) {
      out.push({ name: record.name, ip: record.ip, kind: 'prefix', score: 0.3 + (prefixLen / Math.max(record.nameKey.length, termNorm.length)) * 0.3 })
      continue
    }
    if (record.nameKey === termNorm && record.nameKey.length > 0) {
      out.push({ name: record.name, ip: record.ip, kind: 'normalized', score: 0.9 })
    }
  }

  out.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name))
  return out.slice(0, limit)
}

function commonPrefixLength(a: string, b: string): number {
  const max = Math.min(a.length, b.length)
  let i = 0
  while (i < max && a[i] === b[i]) i += 1
  return i
}

/**
 * The persisted cache.
 *
 * On disk so a connector restart does not lose the ground truth about the
 * account's assets. Writes are atomic-ish (write to a temp file, then
 * rename) so a crash mid-write cannot leave a truncated JSON behind — a
 * corrupt cache must never be able to break the tools.
 */
export class AliasStore {
  private readonly path: string
  private index: AliasIndex = { updatedAt: 0, count: 0, records: [] }

  constructor(path: string) {
    this.path = path
    this.load()
  }

  private load(): void {
    try {
      const raw = JSON.parse(readFileSync(this.path, 'utf8')) as Partial<AliasIndex>
      if (raw !== null && typeof raw === 'object' && Array.isArray(raw.records)) {
        this.index = {
          updatedAt: Number(raw.updatedAt ?? 0),
          count: Number(raw.count ?? raw.records.length),
          records: raw.records as AliasRecord[],
        }
      }
    } catch {
      // A missing or corrupt cache is not an error: the listing is a cache,
      // and the authoritative source is KoKo itself.
      this.index = { updatedAt: 0, count: 0, records: [] }
    }
  }

  /** Replace the cache with a fresh listing and persist it. */
  update(assets: AssetEntry[], updatedAt: number = Date.now()): AliasIndex {
    this.index = buildAliasIndex(assets, updatedAt)
    this.persist()
    return this.index
  }

  private persist(): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true })
      // Write to a temp file and rename: rename is atomic on the same
      // volume, so a reader never sees a half-written file, and a crash
      // mid-write cannot leave a corrupt cache behind.
      const tmp = this.path + '.tmp'
      writeFileSync(tmp, JSON.stringify(this.index), 'utf8')
      renameSync(tmp, this.path)
    } catch {
      // A cache that cannot be written is a degraded convenience, not a
      // failure: the in-memory index still serves this process.
    }
  }

  get(): AliasIndex {
    return this.index
  }

  /** The candidates for an alias (empty when the cache is cold). */
  candidates(alias: string, limit = 5): AliasCandidate[] {
    return findAliasCandidates(this.index, alias, limit)
  }

  clear(): void {
    this.index = { updatedAt: 0, count: 0, records: [] }
  }
}

/** The cache path next to the audit log. */
export function aliasStorePath(auditPath: string): string {
  return join(dirname(auditPath), 'asset-aliases.json')
}

/**
 * The suggestion block for a failed target.
 *
 * Returns null when there is nothing worth saying — an empty list in the
 * error message is noise that makes the real cause harder to see.
 */
export function formatAliasSuggestions(candidates: AliasCandidate[]): string | null {
  if (candidates.length === 0) return null
  const lines = candidates.map((c) => {
    const ip = c.ip !== null && c.ip.length > 0 ? ' (' + c.ip + ')' : ''
    return c.name + ip + ' [' + c.kind + ']'
  })
  return '候选资产: ' + lines.join('; ')
}
