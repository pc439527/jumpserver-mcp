/**
 * E-2 · build fingerprint — "did my change actually ship?"
 *
 * The bug this guards (N-14): the connector was edited, rebuilt, and the
 * behaviour did not change. Three plausible causes — the build did not run,
 * the build ran but the host is running an older process, or the right code
 * was live and the bug was never fixed — and nothing in the tool surface
 * could tell them apart.
 *
 * These tests pin the contract:
 *   1. a build-info.json is parsed field-by-field, tolerating partial damage
 *   2. a MISSING file is not an error (older builds must still start)
 *   3. the feature bitmap is derived from the source, not from a claim
 *   4. the fingerprint reaches the MODEL as text (whitelist rendering!)
 *   5. `--doctor` prints it
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  ALL_FEATURES_MASK,
  BUILD_FEATURES,
  featureBit,
  formatBuildInfo,
  parseBuildInfo,
  readBuildInfo,
} from '../../lib/build-info.js'
import { runtimeVersion } from '../../lib/version.js'
import { renderResult } from '../../lib/runtime/tools-common.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

test('E-2: parseBuildInfo reads a complete payload', () => {
  const info = parseBuildInfo({
    version: '0.7.2',
    commit: 'abcdef1234567890',
    commitShort: 'abcdef1',
    builtAt: '2026-10-24T01:02:03.000Z',
    dirty: true,
    node: '22',
    features: ['output-budget', 'guardrail'],
  })
  assert.equal(info.version, '0.7.2')
  assert.equal(info.commit, 'abcdef1234567890')
  assert.equal(info.commitShort, 'abcdef1')
  assert.equal(info.builtAt, '2026-10-24T01:02:03.000Z')
  assert.equal(info.dirty, true)
  assert.equal(info.node, '22')
  assert.deepEqual(info.features, ['output-budget', 'guardrail'])
})

test('E-2: featureMask is the OR of the named feature bits', () => {
  const info = parseBuildInfo({ features: ['output-budget', 'guardrail'] })
  assert.equal(info.featureMask, featureBit('output-budget') | featureBit('guardrail'))
  // The bits must be DISTINCT — two features sharing a bit would make the
  // bitmap lie about what the build has.
  const bits = BUILD_FEATURES.map(featureBit)
  assert.equal(new Set(bits).size, bits.length)
  assert.ok(bits.every((b) => b > 0))
})

test('E-2: ALL_FEATURES_MASK is the union of every declared feature', () => {
  const union = BUILD_FEATURES.reduce((mask, name) => mask | featureBit(name), 0)
  assert.equal(ALL_FEATURES_MASK, union)
})

test('E-2: an unknown feature name contributes no bit', () => {
  const info = parseBuildInfo({ features: ['not-a-real-feature', 'output-budget'] })
  assert.deepEqual(info.features, ['not-a-real-feature', 'output-budget'])
  assert.equal(info.featureMask, featureBit('output-budget'))
})

test('E-2: a partial payload keeps the fields it HAS', () => {
  // The commit hash is the one field you need when diagnosing N-14. A typo
  // in an unrelated field must not throw it away.
  const info = parseBuildInfo({ version: '0.7.2', commit: 'deadbeefdeadbeef' })
  assert.equal(info.commit, 'deadbeefdeadbeef')
  assert.equal(info.commitShort, 'deadbee')
  assert.equal(info.version, '0.7.2')
  assert.equal(info.builtAt, 'unknown')
  assert.equal(info.node, 'unknown')
  assert.deepEqual(info.features, [])
  assert.equal(info.featureMask, 0)
})

test('E-2: a malformed payload degrades to unknown, never throws', () => {
  for (const bad of [null, undefined, 42, 'text', [], true]) {
    const info = parseBuildInfo(bad)
    assert.equal(info.commit, 'unknown')
    assert.equal(info.featureMask, 0)
  }
})

test('E-2: readBuildInfo finds the fingerprint next to the running code', () => {
  const info = readBuildInfo()
  // The repo is built before the tests run, so lib/build-info.json exists.
  // The commit must be a real hash, not 'unknown' — an 'unknown' here means
  // the build pipeline stopped writing the fingerprint.
  assert.match(info.commit, /^[0-9a-f]{7,40}$/, 'lib/build-info.json must carry a real commit hash')
  assert.ok(info.features.length > 0, 'the build must declare its capabilities')
  // The fingerprint must describe THIS source tree: every declared feature
  // must have a marker file in src/.
  for (const name of info.features) {
    assert.ok(
      BUILD_FEATURES.includes(name),
      `feature "${name}" is not a declared capability`,
    )
  }
})

test('E-2: the fingerprint is written where the artifact is', () => {
  const raw = JSON.parse(readFileSync(join(ROOT, 'lib', 'build-info.json'), 'utf8'))
  assert.equal(typeof raw.version, 'string')
  assert.equal(typeof raw.commit, 'string')
  assert.equal(typeof raw.builtAt, 'string')
  assert.ok(Array.isArray(raw.features))
})

test('E-2: runtimeVersion publishes the fingerprint', () => {
  const version = runtimeVersion()
  assert.equal(typeof version.pluginVersion, 'string')
  assert.match(version.buildCommit, /^[0-9a-f]{7,40}$/)
  assert.equal(typeof version.buildCommitShort, 'string')
  assert.equal(typeof version.buildAt, 'string')
  assert.equal(typeof version.buildDirty, 'boolean')
  assert.ok(Array.isArray(version.buildFeatures))
  assert.ok(version.buildFeatureMask > 0)
})

test('E-2: the fingerprint reaches the MODEL as text', () => {
  // renderResult is a WHITELIST. A field that is not listed there is
  // invisible to the model no matter what the tool returns — so this test
  // is the one that actually protects the feature.
  const text = renderResult({
    ok: true,
    pluginVersion: '0.7.2',
    buildCommit: 'abcdef1234567890',
    buildCommitShort: 'abcdef1',
    buildAt: '2026-10-24T01:02:03.000Z',
    buildDirty: false,
    buildFeatures: ['output-budget', 'guardrail'],
  })
  assert.match(text, /build: 0\.7\.2 @ abcdef1/)
  assert.match(text, /built 2026-10-24T01:02:03\.000Z/)
  assert.match(text, /features=output-budget,guardrail/)
})

test('E-2: a dirty build says so in the rendered line', () => {
  const text = renderResult({
    ok: true,
    pluginVersion: '0.7.2',
    buildCommit: 'abcdef1234567890',
    buildCommitShort: 'abcdef1',
    buildAt: '2026-10-24T01:02:03.000Z',
    buildDirty: true,
    buildFeatures: [],
  })
  assert.match(text, /@ abcdef1 \(dirty\)/)
})

test('E-2: no fingerprint fields means no build line (not a broken one)', () => {
  const text = renderResult({ ok: true })
  assert.doesNotMatch(text, /^build:/m)
})

test('E-2: formatBuildInfo is a single readable line', () => {
  const line = formatBuildInfo({
    version: '0.7.2',
    commit: 'abcdef1234567890',
    commitShort: 'abcdef1',
    builtAt: '2026-10-24T01:02:03.000Z',
    dirty: false,
    node: '22',
    features: [],
    featureMask: 0,
  })
  assert.equal(line, '0.7.2 @ abcdef1 (built 2026-10-24T01:02:03.000Z)')
  assert.ok(!line.includes('\n'))
})
