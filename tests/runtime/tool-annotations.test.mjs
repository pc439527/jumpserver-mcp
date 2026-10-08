/**
 * The tool table is a CONTRACT, and this test freezes it.
 *
 * Why it exists: `jumpserver_baseline_capture` advertised `readOnlyHint: true`
 * while writing `data/baselines/<name>.json`, and half the tools published no
 * annotations at all. Nothing failed, because nothing checked — the host simply
 * had to assume the worst about every call. That is the same class of defect
 * V0.4.3 fixed for `jumpserver_status` (a side effect hidden behind a
 * read-only label), which returned because the fix was a point patch rather
 * than a mechanism.
 *
 * What is frozen, and what is not:
 *  - FROZEN: whether a tool claims to be read-only, whether it claims to be
 *    destructive, and whether it claims to be idempotent. These are promises
 *    made to the host, exactly as `risk` in the classifier corpus is a safety
 *    promise.
 *  - NOT frozen: titles, descriptions and schema wording. Those are prose.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { openServer, repoRoot } from '../helpers/mcp.mjs'

/**
 * The expected annotation for every tool, including the two that only register
 * when `requireArm` is on. Keeping them here (rather than deriving them from
 * the source) is the point: a change to a tool's published promise has to be
 * made twice, on purpose, with this comment in the way.
 */
const EXPECTED = {
  // ---- read-only: touches the bastion, changes nothing ----------------
  jumpserver_status: { readOnlyHint: true },
  jumpserver_assets: { readOnlyHint: true },
  jumpserver_snapshot: { readOnlyHint: true },
  jumpserver_audit: { readOnlyHint: true },
  jumpserver_inspect: { readOnlyHint: true },
  jumpserver_topology: { readOnlyHint: true },
  jumpserver_profile_run: { readOnlyHint: true },
  jumpserver_compare: { readOnlyHint: true },
  jumpserver_baseline_compare: { readOnlyHint: true },
  jumpserver_job_read: { readOnlyHint: true },
  jumpserver_jobs: { readOnlyHint: true },

  // ---- can change the remote host -------------------------------------
  jumpserver_exec: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  jumpserver_run: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  jumpserver_batch: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  jumpserver_job_start: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  jumpserver_job_stop: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  jumpserver_interrupt: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },

  // ---- session / connector lifecycle: reversible, no remote change ----
  jumpserver_connect: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
  jumpserver_enter: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
  jumpserver_leave: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
  jumpserver_close: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },

  // ---- side effects that are neither remote nor idempotent ------------
  jumpserver_console_rotate_token: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  // Writes data/baselines/<name>.json — the regression this test exists for.
  jumpserver_baseline_capture: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  jumpserver_arm: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  jumpserver_disarm: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
}

/** The 23 tools registered without `requireArm`; arm/disarm are conditional. */
const CONDITIONAL = ['jumpserver_arm', 'jumpserver_disarm']
const ALWAYS_REGISTERED = Object.keys(EXPECTED).filter((n) => !CONDITIONAL.includes(n))

/**
 * Tools that WRITE something, anywhere. A tool on this list that claims
 * `readOnlyHint: true` is a lie told to the host, which is the whole point.
 */
const WRITES = [
  'jumpserver_baseline_capture', // data/baselines/<name>.json
  'jumpserver_console_rotate_token', // revokes the live token
  'jumpserver_exec', 'jumpserver_run', 'jumpserver_batch', // remote state
  'jumpserver_job_start', 'jumpserver_job_stop', 'jumpserver_interrupt',
  'jumpserver_connect', 'jumpserver_enter', 'jumpserver_leave', 'jumpserver_close',
  'jumpserver_arm', 'jumpserver_disarm',
]

const ANNOTATION_KEYS = new Set(['title', 'readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'])

function tempConfig(contents) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-annot-'))
  const path = join(dir, 'config.json')
  writeFileSync(path, JSON.stringify(contents), 'utf8')
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

test('every registered tool declares annotations', async () => {
  const config = tempConfig({ auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    const missing = server.tools.filter((t) => t.annotations === undefined || t.annotations === null).map((t) => t.name)
    assert.deepEqual(missing, [], 'tools with no annotations: ' + missing.join(', '))
  } finally {
    server.close()
    config.cleanup()
  }
})

test('the registered tool set matches the expectation table exactly (no unregistered additions)', async () => {
  const config = tempConfig({ auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    const registered = server.tools.map((t) => t.name).sort()
    assert.deepEqual(
      registered,
      [...ALWAYS_REGISTERED].sort(),
      'a tool was added or removed without updating this contract test',
    )
  } finally {
    server.close()
    config.cleanup()
  }
})

test('annotation values match the expectation table', async () => {
  const config = tempConfig({ auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    for (const tool of server.tools) {
      const expected = EXPECTED[tool.name]
      assert.ok(expected !== undefined, 'no expectation for ' + tool.name)
      assert.deepEqual(tool.annotations, expected, 'annotation drift on ' + tool.name)
    }
  } finally {
    server.close()
    config.cleanup()
  }
})

test('no tool that writes anything claims to be read-only', async () => {
  const config = tempConfig({ auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    const liars = server.tools
      .filter((t) => WRITES.includes(t.name) && t.annotations?.readOnlyHint === true)
      .map((t) => t.name)
    assert.deepEqual(liars, [], 'these tools write but advertise readOnlyHint:true: ' + liars.join(', '))
    // And the converse sanity check: the WRITES list is not stale.
    const registeredNames = new Set(server.tools.map((t) => t.name))
    const stale = WRITES.filter((n) => !registeredNames.has(n) && !CONDITIONAL.includes(n))
    assert.deepEqual(stale, [], 'WRITES references tools that no longer exist: ' + stale.join(', '))
  } finally {
    server.close()
    config.cleanup()
  }
})

test('every annotation key is one the MCP spec defines', async () => {
  const config = tempConfig({ auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    for (const tool of server.tools) {
      for (const key of Object.keys(tool.annotations ?? {})) {
        assert.ok(ANNOTATION_KEYS.has(key), 'unknown annotation key "' + key + '" on ' + tool.name)
      }
    }
  } finally {
    server.close()
    config.cleanup()
  }
})

test('requireArm:true registers the arm/disarm pair with annotations too', async () => {
  const config = tempConfig({ requireArm: true, auditViewer: { enabled: false } })
  const server = await openServer({ configPath: config.path })
  try {
    const names = server.tools.map((t) => t.name)
    assert.ok(names.includes('jumpserver_arm'), 'jumpserver_arm should be registered when requireArm is true')
    assert.ok(names.includes('jumpserver_disarm'), 'jumpserver_disarm should be registered when requireArm is true')
    assert.equal(server.tools.length, Object.keys(EXPECTED).length)
    for (const tool of server.tools) {
      assert.deepEqual(tool.annotations, EXPECTED[tool.name], 'annotation drift on ' + tool.name)
    }
  } finally {
    server.close()
    config.cleanup()
  }
})

test('the README tool table matches the registered tools', async () => {
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8')
  const lines = readme.split('\n')
  const headerIndex = lines.findIndex((l) => l.startsWith('## Tools ('))
  assert.ok(headerIndex >= 0, 'README has no "## Tools (N)" section')

  const declared = Number(/^## Tools \((\d+)\)/.exec(lines[headerIndex])[1])
  const rows = []
  for (let i = headerIndex + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith('## ')) break
    const match = /^\|\s*`(jumpserver_[a-z_]+)`/.exec(lines[i])
    if (match !== null) rows.push(match[1])
  }

  assert.equal(rows.length, declared, 'the "## Tools (N)" count disagrees with the number of table rows')
  assert.deepEqual(rows.sort(), [...ALWAYS_REGISTERED].sort(),
    'the README tool table has drifted from the registered tools')
  assert.equal(declared, ALWAYS_REGISTERED.length)
})
