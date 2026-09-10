/**
 * Baseline store (V0.4.1) — drift detection across time.
 *
 * A baseline is a named snapshot of a target's state, captured from the fixed
 * inspect probes and persisted as JSON under data/baselines/. A later
 * baseline_compare re-inspects the same targets and reports what changed:
 * new/removed listening ports, load/disk shifts, new processes, etc.
 *
 * Storage is a plain JSON file per baseline so it can be diffed, archived or
 * committed by the operator. Reads are tolerant: a corrupt file is reported as
 * a hard error (never silently treated as "no change").
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { JumpServerError } from '../jumpserver/errors.js'

export interface BaselineHost {
  target: string
  hostname: string | null
  reachable: boolean
  error: string | null
  os: string | null
  kernel: string | null
  cores: number | null
  memoryTotalMb: number | null
  memoryUsedPct: number | null
  load: number[] | null
  disks: Array<{ mount: string; usePct: number | null }>
  listening: Array<{ port: number; process: string | null }>
  services: string[]
  roles: string[]
}

export interface Baseline {
  name: string
  createdAt: string
  profile: string
  targets: string[]
  hosts: BaselineHost[]
}

/** Safe baseline name: a filename component, no traversal, no separators. */
export function isValidBaselineName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)
}

export class BaselineStore {
  constructor(private readonly dir: string) {}

  private pathFor(name: string): string {
    if (!isValidBaselineName(name)) {
      throw new JumpServerError('INVALID_ARGUMENT', 'invalid baseline name "' + name + '" (use letters/digits/._-, max 64 chars)')
    }
    return join(this.dir, name + '.json')
  }

  save(baseline: Baseline): string {
    if (!isValidBaselineName(baseline.name)) {
      throw new JumpServerError('INVALID_ARGUMENT', 'invalid baseline name "' + baseline.name + '"')
    }
    mkdirSync(this.dir, { recursive: true })
    const path = this.pathFor(baseline.name)
    writeFileSync(path, JSON.stringify(baseline, null, 2), 'utf8')
    return path
  }

  load(name: string): Baseline {
    const path = this.pathFor(name)
    if (!existsSync(path)) {
      const known = this.list()
      throw new JumpServerError(
        'UNKNOWN_BASELINE',
        'unknown baseline "' + name + '"' + (known.length > 0 ? '; saved: ' + known.join(', ') : '; no baselines saved yet'),
      )
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(readFileSync(path, 'utf8'))
    } catch (error) {
      throw new JumpServerError('UNKNOWN_BASELINE', 'baseline "' + name + '" is unreadable: ' + (error instanceof Error ? error.message : String(error)))
    }
    const baseline = parsed as Baseline
    if (typeof baseline !== 'object' || baseline === null || !Array.isArray(baseline.hosts)) {
      throw new JumpServerError('UNKNOWN_BASELINE', 'baseline "' + name + '" is malformed (no hosts[])')
    }
    return baseline
  }

  /** Saved baseline names, sorted. */
  list(): string[] {
    if (!existsSync(this.dir)) return []
    return readdirSync(this.dir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.slice(0, -5))
      .filter((n) => isValidBaselineName(n))
      .sort()
  }
}

export interface DriftField {
  field: string
  before: string
  after: string
}

export interface HostDrift {
  target: string
  status: 'changed' | 'unchanged' | 'added' | 'removed' | 'unreachable'
  changes: DriftField[]
}

export interface DriftResult {
  baseline: string
  createdAt: string
  comparedAt: string
  hosts: HostDrift[]
  changed: number
  unchanged: number
  unreachable: number
}

function fmt(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (Array.isArray(value)) return '[' + value.join(', ') + ']'
  return String(value)
}

/** Compare two baseline host snapshots; only REAL differences are reported. */
export function diffHost(before: BaselineHost, after: BaselineHost): HostDrift {
  if (!after.reachable) {
    return { target: after.target, status: 'unreachable', changes: [{ field: 'reachable', before: fmt(before.reachable), after: fmt(false) }] }
  }
  const changes: DriftField[] = []
  const scalar: Array<[string, unknown, unknown]> = [
    ['hostname', before.hostname, after.hostname],
    ['os', before.os, after.os],
    ['kernel', before.kernel, after.kernel],
    ['cores', before.cores, after.cores],
    ['memoryTotalMb', before.memoryTotalMb, after.memoryTotalMb],
  ]
  for (const [field, b, a] of scalar) {
    if (fmt(b) !== fmt(a)) changes.push({ field, before: fmt(b), after: fmt(a) })
  }
  // Load average: report only a material shift (> 25% of the before value, or
  // 0 -> non-zero), so routine jitter does not spam the drift report.
  if (fmt(before.load) !== fmt(after.load)) {
    const b1 = before.load?.[0]
    const a1 = after.load?.[0]
    if (b1 === undefined || a1 === undefined || Math.abs(a1 - b1) > Math.max(0.5, b1 * 0.25)) {
      changes.push({ field: 'load', before: fmt(before.load), after: fmt(after.load) })
    }
  }
  // Memory used %: report only a shift of >= 10 points.
  if (fmt(before.memoryUsedPct) !== fmt(after.memoryUsedPct)) {
    const b = before.memoryUsedPct
    const a = after.memoryUsedPct
    if (b === null || a === null || Math.abs(a - b) >= 10) {
      changes.push({ field: 'memoryUsedPct', before: fmt(b), after: fmt(a) })
    }
  }

  const diskDrift = diffNamed(before.disks, after.disks, (d) => d.mount, (d) => String(d.usePct))
  for (const change of diskDrift) changes.push(change)

  const listenDrift = diffNamed(before.listening, after.listening, (l) => String(l.port), (l) => l.process ?? '?')
  for (const change of listenDrift) changes.push(change)

  const serviceDrift = diffSet(before.services, after.services, 'services')
  for (const change of serviceDrift) changes.push(change)

  const roleDrift = diffSet(before.roles, after.roles, 'roles')
  for (const change of roleDrift) changes.push(change)

  return { target: after.target, status: changes.length > 0 ? 'changed' : 'unchanged', changes }
}

function diffNamed<T>(before: T[], after: T[], key: (item: T) => string, value: (item: T) => string): DriftField[] {
  const bmap = new Map(before.map((i) => [key(i), value(i)]))
  const amap = new Map(after.map((i) => [key(i), value(i)]))
  const out: DriftField[] = []
  for (const [k, v] of bmap) {
    if (!amap.has(k)) out.push({ field: 'removed', before: k + '=' + v, after: '-' })
    else if (amap.get(k) !== v) out.push({ field: 'changed', before: k + '=' + v, after: k + '=' + amap.get(k) })
  }
  for (const [k, v] of amap) {
    if (!bmap.has(k)) out.push({ field: 'added', before: '-', after: k + '=' + v })
  }
  return out
}

function diffSet(before: string[], after: string[], label: string): DriftField[] {
  const bset = new Set(before)
  const aset = new Set(after)
  const added = after.filter((x) => !bset.has(x))
  const removed = before.filter((x) => !aset.has(x))
  const out: DriftField[] = []
  if (added.length > 0) out.push({ field: label + '.added', before: '-', after: added.join(', ') })
  if (removed.length > 0) out.push({ field: label + '.removed', before: removed.join(', '), after: '-' })
  return out
}

/** Compare a whole baseline against a fresh set of host snapshots. */
export function diffBaseline(baseline: Baseline, current: BaselineHost[], comparedAt: string): DriftResult {
  const byTarget = new Map(baseline.hosts.map((h) => [h.target, h]))
  const hosts: HostDrift[] = []
  for (const host of current) {
    const before = byTarget.get(host.target)
    if (before === undefined) {
      hosts.push({ target: host.target, status: 'added', changes: [{ field: 'target', before: '-', after: 'new' }] })
      continue
    }
    hosts.push(diffHost(before, host))
  }
  // Baselines hosts that were not re-checked are reported as removed.
  const seen = new Set(current.map((h) => h.target))
  for (const host of baseline.hosts) {
    if (!seen.has(host.target)) {
      hosts.push({ target: host.target, status: 'removed', changes: [{ field: 'target', before: 'present', after: 'not-checked' }] })
    }
  }
  return {
    baseline: baseline.name,
    createdAt: baseline.createdAt,
    comparedAt,
    hosts,
    changed: hosts.filter((h) => h.status === 'changed').length,
    unchanged: hosts.filter((h) => h.status === 'unchanged').length,
    unreachable: hosts.filter((h) => h.status === 'unreachable').length,
  }
}
