#!/usr/bin/env node
/**
 * write-build-info.mjs — stamp the build with its own identity (E-2).
 *
 * Run AFTER `tsc -p tsconfig.json`. It writes `lib/build-info.json` next to
 * the compiled code, so the fingerprint and the artifact can never drift
 * apart: copy `lib/` and you copy both.
 *
 * What goes in:
 *   version      package.json version at build time
 *   commit       full git hash of HEAD
 *   commitShort  short hash
 *   dirty        true when the worktree had uncommitted changes
 *   builtAt      ISO timestamp
 *   node         the Node major that ran the build
 *   features     the capability names this build carries
 *
 * The feature list is derived from the SOURCE, not hardcoded: each capability
 * is a marker file under `src/`. If the marker exists, the capability is in.
 * That way a capability can never be claimed by a build that does not have
 * the code behind it — the usual way a feature bitmap rots.
 *
 * Read-only with respect to git: it never commits, never checks out, never
 * touches the index. It only READS `git rev-parse` / `git status`.
 *
 *   node scripts/write-build-info.mjs            # uses lib/ as the target
 *   node scripts/write-build-info.mjs --out x.json
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function parseArgs(argv) {
  const out = { out: join(ROOT, 'lib', 'build-info.json') }
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--out') out.out = resolve(argv[++i])
  }
  return out
}

/**
 * Capability markers: a feature name is present iff its source file exists.
 * The marker file is the feature's implementation, so this cannot lie.
 */
const FEATURE_MARKERS = [
  ['output-budget', 'src/jumpserver/output-budget.ts'],
  ['output-normalize', 'src/jumpserver/output-normalize.ts'],
  ['audit-observability', 'src/runtime/audit-metrics.ts'],
  ['audit-rotation', 'src/runtime/audit-store.ts'],
  ['readiness', 'src/runtime/readiness.ts'],
  ['guardrail', 'src/security/guardrail.ts'],
  ['asset-alias-cache', 'src/runtime/asset-alias-store.ts'],
  ['console-handover-heal', 'src/runtime/console-address.ts'],
]

function git(args) {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return null
  }
}

const args = parseArgs(process.argv.slice(2))

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const commit = git(['rev-parse', 'HEAD'])
const commitShort = git(['rev-parse', '--short', 'HEAD'])
const status = git(['status', '--porcelain'])
const dirty = status !== null && status.length > 0

const features = FEATURE_MARKERS.filter(([, rel]) => existsSync(join(ROOT, rel))).map(([name]) => name)

const payload = {
  version: typeof pkg.version === 'string' ? pkg.version : '0.0.0',
  commit: commit ?? 'unknown',
  commitShort: commitShort ?? (commit ? commit.slice(0, 7) : 'unknown'),
  builtAt: new Date().toISOString(),
  dirty,
  node: process.versions.node.split('.')[0] ?? 'unknown',
  features,
}

mkdirSync(dirname(args.out), { recursive: true })
writeFileSync(args.out, JSON.stringify(payload, null, 2) + '\n', 'utf8')

console.log(
  `[build-info] ${payload.version} @ ${payload.commitShort}${dirty ? ' (dirty)' : ''} -> ${args.out}`,
)
console.log(`[build-info] features: ${features.join(', ') || '(none)'}`)
