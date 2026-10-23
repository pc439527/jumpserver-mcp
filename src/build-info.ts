/**
 * The build fingerprint — the answer to "did my change actually ship?".
 *
 * The symptom this exists for (N-14): the connector was edited, the code was
 * rebuilt, and the behaviour did not change. Every diagnosis then started
 * with the same unanswerable question — *which* build is running? The only
 * signals available were the mtime of `lib/` (which can be OLDER than the
 * commit that produced it, because `lib/` is a gitignore artifact) and
 * `package.json`'s version (which moves only when someone remembers to bump
 * it in two places). Neither tells you which commit is live.
 *
 * So the build writes its own identity next to the artifact:
 *
 *   lib/build-info.json
 *     { version, commit, commitShort, builtAt, dirty, node, features }
 *
 * and the runtime reads it and publishes it through `jumpserver_status`. The
 * comparison "is the running build the one I just made?" becomes one glance at
 * a commit hash instead of a forensic session.
 *
 * Two rules keep this honest:
 *
 *  1. The file lives NEXT TO the code it describes (`lib/build-info.json`,
 *     written after `tsc`). It is never a separate artifact that can drift
 *     from the binary — copying `lib/` copies the fingerprint with it.
 *
 *  2. A missing or malformed file is NOT an error. A build made before this
 *     feature existed (or a package assembled by hand) simply has no
 *     fingerprint, and the runtime says so (`buildFingerprint: unknown`)
 *     rather than refusing to start.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * The feature bitmap.
 *
 * Each entry is a stable capability name; the runtime maps it to a bit so a
 * caller can ask "does this build have X?" with a single integer. Names are
 * append-only — renaming one silently breaks every recorded fingerprint, so
 * a retired capability keeps its name and stops being set.
 */
export const BUILD_FEATURES = [
  /** Output budget on the result layer (D-1/D-2/D-3). */
  'output-budget',
  /** Normalized comparison view (D-5). */
  'output-normalize',
  /** Audit records carry errorCode / riskRuleId (D-6). */
  'audit-observability',
  /** Day-rotated audit files + daily metrics (D-7). */
  'audit-rotation',
  /** Readiness verdict in `jumpserver_status` / `--doctor` (D-9). */
  'readiness',
  /** Timeout guardrail for dangerous / unknown commands (D-10). */
  'guardrail',
  /** Alias reverse-lookup cache for asset names (E-5). */
  'asset-alias-cache',
  /** Console handover self-heals when the pinned instance died (E-4). */
  'console-handover-heal',
] as const

export type BuildFeature = (typeof BUILD_FEATURES)[number]

/**
 * The bit assigned to each feature. The index in BUILD_FEATURES is the
 * contract: appending a feature shifts nothing, removing one shifts
 * everything after it (which is why removal is not allowed).
 */
const FEATURE_BITS: Record<BuildFeature, number> = BUILD_FEATURES.reduce((acc, name, index) => {
  acc[name] = 1 << index
  return acc
}, {} as Record<BuildFeature, number>)

export function featureBit(name: BuildFeature): number {
  return FEATURE_BITS[name] ?? 0
}

/** The whole bitmap: every known capability present. */
export const ALL_FEATURES_MASK = BUILD_FEATURES.reduce((mask, name) => mask | FEATURE_BITS[name], 0)

export interface BuildInfo {
  /** The version string from package.json at build time. */
  version: string
  /** The full commit hash, or 'unknown'. */
  commit: string
  /** The short commit hash, or 'unknown'. */
  commitShort: string
  /** ISO timestamp of the build. */
  builtAt: string
  /** True when the tree had uncommitted changes at build time. */
  dirty: boolean
  /** The Node major version used for the build. */
  node: string
  /** The capability names this build carries. */
  features: string[]
  /** The capability bitmap (see featureBit). */
  featureMask: number
}

/** The fingerprint as reported when there is no build-info.json. */
export const UNKNOWN_BUILD: BuildInfo = {
  version: '0.0.0',
  commit: 'unknown',
  commitShort: 'unknown',
  builtAt: 'unknown',
  dirty: false,
  node: 'unknown',
  features: [],
  featureMask: 0,
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

/**
 * Parse a build-info.json payload. Every field is validated independently:
 * a partially broken file must still yield the fields that ARE readable, and
 * only the broken ones fall back to 'unknown'. Failing the whole file would
 * lose the commit hash — exactly the one field you need — because of a
 * typo in an unrelated one.
 */
export function parseBuildInfo(raw: unknown): BuildInfo {
  if (!isRecord(raw)) return { ...UNKNOWN_BUILD }
  const version = typeof raw.version === 'string' && raw.version.length > 0 ? raw.version : 'unknown'
  const commit = typeof raw.commit === 'string' && raw.commit.length > 0 ? raw.commit : 'unknown'
  const commitShort =
    typeof raw.commitShort === 'string' && raw.commitShort.length > 0 ? raw.commitShort : commit.slice(0, 7)
  const builtAt = typeof raw.builtAt === 'string' && raw.builtAt.length > 0 ? raw.builtAt : 'unknown'
  const dirty = raw.dirty === true
  const node = typeof raw.node === 'string' && raw.node.length > 0 ? raw.node : 'unknown'
  const features = Array.isArray(raw.features)
    ? raw.features.filter((f): f is string => typeof f === 'string')
    : []
  let featureMask = 0
  for (const name of features) {
    if ((BUILD_FEATURES as readonly string[]).includes(name)) {
      featureMask |= FEATURE_BITS[name as BuildFeature]
    }
  }
  return { version, commit, commitShort, builtAt, dirty, node, features, featureMask }
}

/**
 * Read the fingerprint that sits next to the running code.
 *
 * `lib/build-info.json` lives in the same directory as `lib/server.js`, so
 * resolving it relative to this module finds the fingerprint of the build
 * that is actually running — not of some other checkout.
 */
export function readBuildInfo(): BuildInfo {
  try {
    const here = dirname(fileURLToPath(import.meta.url))
    const raw = readFileSync(join(here, 'build-info.json'), 'utf8')
    return parseBuildInfo(JSON.parse(raw))
  } catch {
    return { ...UNKNOWN_BUILD }
  }
}

/** One line for humans: "0.7.1 @ f2cba62 (built 2026-10-23T12:20:00Z)". */
export function formatBuildInfo(info: BuildInfo): string {
  const flags = info.dirty ? ' +dirty' : ''
  return `${info.version} @ ${info.commitShort}${flags} (built ${info.builtAt})`
}
