/**
 * `--doctor` contract (V0.5.2).
 *
 * The doctor is the answer to "the connector does not work and I cannot see
 * why". Its value is entirely in being TRUSTWORTHY and SAFE, so those are what
 * this file freezes:
 *
 *  - trustworthy: it must not throw on the exact inputs it exists to diagnose
 *    (no config at all, broken JSON, a schema violation), and it must attribute
 *    a failure to the layer that actually caused it;
 *  - safe: it must never print a credential value, and it must not BIND the
 *    console port, because a diagnostic that breaks the thing it inspects is
 *    worse than no diagnostic.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { checkCompiledToolSurface, formatConfigError, renderDoctor, runDoctor, wantsDoctor } from '../../lib/runtime/doctor.js'
import { MISSING_CONFIG } from '../helpers/mcp.mjs'

/** Same four keys the connector form injects, blanked. */
const BLANK = {
  JUMPSERVER_HOST: '',
  JUMPSERVER_PORT: '',
  JUMPSERVER_USERNAME: '',
  JUMPSERVER_PASSWORD: '',
}

/** No test may touch the network: the console probe is always injected. */
const NO_PORT = async () => 'free'

/**
 * V0.5.12: every run is pinned to an account store that does not exist.
 * ProfileStore resolves under the developer's home, so without this the "no
 * configuration at all" fixture reads whatever bastion accounts this machine
 * has saved — the selected account then supplies host / username / credential,
 * the connection reads as complete, and a correct doctor goes red. Tests that
 * WANT an account pass their own `profilesPath`.
 */
const NO_ACCOUNTS = join(tmpdir(), 'jumpserver-mcp-doctor-no-such-profiles.json')
const doctor = (options = {}) => runDoctor({ profilesPath: NO_ACCOUNTS, ...options })

function tempConfig(contents) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-doctor-'))
  const path = join(dir, 'config.json')
  writeFileSync(path, contents, 'utf8')
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

function checkNamed(report, name) {
  const found = report.checks.find((c) => c.name === name)
  assert.notEqual(found, undefined, 'expected a check named ' + name)
  return found
}

test('wantsDoctor recognises the flag and nothing else', () => {
  assert.equal(wantsDoctor(['--doctor']), true)
  assert.equal(wantsDoctor(['-doctor']), true)
  assert.equal(wantsDoctor([]), false)
  assert.equal(wantsDoctor(['--help']), false)
  assert.equal(wantsDoctor(['--doctorx']), false)
})

test('formatConfigError turns zod issues into path: message, and passes other errors through', () => {
  const zodLike = {
    issues: [
      { path: ['port'], message: 'Expected number, received string' },
      { path: [], message: 'Required' },
      { path: ['auditViewer', 'port'], message: 'Number must be less than or equal to 65535' },
    ],
  }
  assert.equal(
    formatConfigError(zodLike),
    'port: Expected number, received string; Required; auditViewer.port: Number must be less than or equal to 65535',
  )
  assert.equal(formatConfigError(new Error('plain failure')), 'plain failure')
  assert.equal(formatConfigError('a string'), 'a string')
})

test('no configuration at all: reports what is missing instead of throwing', async () => {
  const report = await doctor({ env: { ...BLANK, JUMPSERVER_MCP_CONFIG: MISSING_CONFIG }, probePort: NO_PORT })
  assert.equal(report.exitCode, 1, 'an unusable connection must be a non-zero exit')

  const connection = checkNamed(report, 'connection')
  assert.equal(connection.status, 'fail')
  assert.match(connection.detail, /missing host \/ username/)
  // The fix must be as actionable as the startup message it mirrors.
  assert.ok(connection.fix.includes('JUMPSERVER_HOST'), 'the fix must name the environment keys')
  assert.ok(connection.fix.includes('连接器'), 'the fix must point at the connector form')

  assert.equal(checkNamed(report, 'credential').status, 'warn')
  assert.equal(checkNamed(report, 'config file').status, 'ok', 'a MISSING config file is not a failure')
  assert.equal(checkNamed(report, 'ssh2 transport').status, 'ok')
})

test('a connection supplied through the environment reads as usable', async () => {
  const report = await doctor({
    env: {
      ...BLANK,
      JUMPSERVER_MCP_CONFIG: MISSING_CONFIG,
      JUMPSERVER_HOST: '10.20.30.40',
      JUMPSERVER_USERNAME: 'probe',
      JUMPSERVER_PASSWORD: 'PASSWORD-VALUE-MUST-NOT-APPEAR',
    },
    probePort: NO_PORT,
  })
  assert.equal(report.exitCode, 0, 'a complete connection must exit 0')

  const connection = checkNamed(report, 'connection')
  assert.equal(connection.status, 'ok')
  assert.ok(connection.detail.includes('10.20.30.40'), 'the resolved host must be shown')
  assert.ok(connection.detail.includes('from env'), 'the source layer must be shown')

  const credential = checkNamed(report, 'credential')
  assert.equal(credential.status, 'ok')
  assert.ok(credential.detail.includes('JUMPSERVER_PASSWORD'), 'the credential SOURCE must be named')

  // The whole point of the redaction rule: the report is safe to paste into a
  // ticket. If the value ever reaches stdout the doctor becomes a leak.
  assert.ok(
    !renderDoctor(report).includes('PASSWORD-VALUE-MUST-NOT-APPEAR'),
    'the doctor must never render a credential value',
  )
})

test('a missing credential is a warning, not a failure (the connection itself is fine)', async () => {
  const report = await doctor({
    env: { ...BLANK, JUMPSERVER_MCP_CONFIG: MISSING_CONFIG, JUMPSERVER_HOST: 'h', JUMPSERVER_USERNAME: 'u' },
    probePort: NO_PORT,
  })
  assert.equal(checkNamed(report, 'connection').status, 'ok')
  assert.equal(checkNamed(report, 'credential').status, 'warn')
  assert.equal(report.exitCode, 0, 'a warning must not fail the run — warns are advisory')
})

test('invalid JSON names the syntax problem and stops evaluating downstream checks', async () => {
  const config = tempConfig('{ not json')
  try {
    const report = await doctor({ env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path }, probePort: NO_PORT })
    assert.equal(report.exitCode, 1)
    const file = checkNamed(report, 'config file')
    assert.equal(file.status, 'fail')
    assert.match(file.detail, /not valid JSON/)
    assert.equal(checkNamed(report, 'connection').detail, 'not evaluated — the config file must be fixed first')
  } finally {
    config.cleanup()
  }
})

test('a schema violation is reported as readable text, not a zod dump', async () => {
  const config = tempConfig('{"port":"not-a-port"}')
  try {
    const report = await doctor({ env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path }, probePort: NO_PORT })
    assert.equal(report.exitCode, 1)
    const file = checkNamed(report, 'config file')
    assert.equal(file.status, 'fail')
    assert.match(file.detail, /valid JSON but invalid/)
    // The translated form an operator can act on.
    assert.match(file.detail, /port: Expected number, received string/)
    // ...and NOT the raw issue objects.
    assert.ok(!file.detail.includes('"code"'), 'the raw zod issue objects must not be forwarded')
    assert.ok(!file.detail.includes('invalid_type'), 'the raw zod issue code must not be forwarded')
  } finally {
    config.cleanup()
  }
})

test('a bad JUMPSERVER_* variable is blamed on the environment, not on config.json', async () => {
  const config = tempConfig('{"host":"1.2.3.4","username":"u"}')
  try {
    const report = await doctor({
      env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path, JUMPSERVER_PORT: 'not-a-port' },
      probePort: NO_PORT,
    })
    const envCheck = checkNamed(report, 'connector env')
    assert.equal(envCheck.status, 'fail')
    assert.match(envCheck.detail, /JUMPSERVER_PORT/)
    // config.json is fine; saying otherwise would send the operator to the wrong file.
    assert.equal(checkNamed(report, 'config file').status, 'ok')
  } finally {
    config.cleanup()
  }
})

test('the console probe is asked about the configured port and its answer is reported', async () => {
  const config = tempConfig('{"host":"1.2.3.4","username":"u","auditViewer":{"port":9911}}')
  const asked = []
  try {
    const report = await doctor({
      env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path },
      probePort: async (port) => {
        asked.push(port)
        return 'listening'
      },
    })
    assert.deepEqual(asked, [9911], 'the probe must be asked about the CONFIGURED port')
    const console_ = checkNamed(report, 'ops console')
    assert.equal(console_.status, 'ok', 'an occupied port is expected, not a failure')
    assert.match(console_.detail, /9911/)
  } finally {
    config.cleanup()
  }
})

test('a disabled console is not probed at all', async () => {
  const config = tempConfig('{"host":"1.2.3.4","username":"u","auditViewer":{"enabled":false}}')
  let probed = false
  try {
    const report = await doctor({
      env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path },
      probePort: async () => {
        probed = true
        return 'free'
      },
    })
    assert.equal(probed, false, 'a disabled console must not be probed')
    assert.match(checkNamed(report, 'ops console').detail, /disabled/)
  } finally {
    config.cleanup()
  }
})

test('the risk judge is reported as disabled until it is switched on', async () => {
  const config = tempConfig(
    JSON.stringify({ host: 'h', port: 2222, username: 'u', permissionMode: 'AUTO' }),
  )
  try {
    const report = await doctor({ env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path }, probePort: NO_PORT })
    const judge = checkNamed(report, 'risk judge')
    assert.equal(judge.status, 'ok')
    assert.match(judge.detail, /disabled/)
  } finally {
    config.cleanup()
  }
})

test('the risk judge names the layer supplying its key and never prints the value', async () => {
  const config = tempConfig(
    JSON.stringify({
      host: 'h',
      port: 2222,
      username: 'u',
      permissionMode: 'AUTO',
      riskJudge: { enabled: true, apiKeyEnv: 'TYPESAFE_API_KEY', apiKeyFile: '' },
    }),
  )
  try {
    const report = await doctor({
      env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path, TYPESAFE_API_KEY: 'JEV-KEY-MUST-NOT-APPEAR' },
      probePort: NO_PORT,
    })
    const judge = checkNamed(report, 'risk judge')
    assert.equal(judge.status, 'ok')
    assert.match(judge.detail, /env TYPESAFE_API_KEY/)
    assert.ok(
      !renderDoctor(report).includes('JEV-KEY-MUST-NOT-APPEAR'),
      'the doctor must never render the judge key',
    )
  } finally {
    config.cleanup()
  }
})

test('an enabled risk judge with no reachable key is a warning with a fix', async () => {
  const config = tempConfig(
    JSON.stringify({
      host: 'h',
      port: 2222,
      username: 'u',
      permissionMode: 'AUTO',
      riskJudge: { enabled: true, apiKeyEnv: 'TYPESAFE_API_KEY', apiKeyFile: '' },
    }),
  )
  try {
    const report = await doctor({ env: { ...BLANK, JUMPSERVER_MCP_CONFIG: config.path }, probePort: NO_PORT })
    const judge = checkNamed(report, 'risk judge')
    assert.equal(judge.status, 'warn', 'a missing key must warn, not fail — the gate does not depend on it')
    assert.ok(judge.fix.includes('TYPESAFE_API_KEY'), 'the fix must name the variable to set')
    assert.equal(report.exitCode, 0)
  } finally {
    config.cleanup()
  }
})

test('renderDoctor produces one line per check plus a verdict', async () => {
  const report = await doctor({ env: { ...BLANK, JUMPSERVER_MCP_CONFIG: MISSING_CONFIG }, probePort: NO_PORT })
  const text = renderDoctor(report)
  for (const check of report.checks) {
    assert.ok(text.includes(check.name + ':'), 'every check must appear in the rendered report')
  }
  assert.match(text, /Result: /)
  assert.ok(text.includes('FAIL'), 'the failed check must be visible')
})

/**
 * V0.5.12: the account layer is the THIRD source of host / username /
 * credential, and it outranks both config.json and the injected credential.
 * The doctor used to inspect only the two config layers, so on a machine with
 * a healthy account selected it printed "credential: NOT found in any layer"
 * and sent the operator to fill a password that was never going to be used.
 */
function seededAccountStore(secret) {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-doctor-acct-'))
  const profilesPath = join(dir, 'profiles.json')
  writeFileSync(
    profilesPath,
    JSON.stringify({
      version: 1,
      activeProfileId: 'p1',
      profiles: [
        {
          id: 'p1',
          label: '生产维护账号',
          host: '10.9.9.9',
          port: 2222,
          username: 'ops',
          secret,
          createdAt: 1,
          updatedAt: 1,
        },
      ],
    }),
    'utf8',
  )
  return { profilesPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

test('a selected account is named as the source of host, username AND credential', async () => {
  const store = seededAccountStore({ kind: 'vault', token: 'v1:TOKEN-MUST-NOT-APPEAR:x:y' })
  try {
    const report = await runDoctor({
      env: { ...BLANK, JUMPSERVER_MCP_CONFIG: MISSING_CONFIG },
      probePort: NO_PORT,
      profilesPath: store.profilesPath,
    })
    assert.equal(report.exitCode, 0, 'a selected account completes an otherwise empty connection')

    const connection = checkNamed(report, 'connection')
    assert.equal(connection.status, 'ok')
    assert.ok(connection.detail.includes('10.9.9.9'), 'the account host must be reported, not config.json')
    assert.ok(connection.detail.includes('生产维护账号'), 'the account must be named')

    const credential = checkNamed(report, 'credential')
    assert.equal(credential.status, 'ok')
    assert.ok(credential.detail.includes('生产维护账号'))
    // Reading the store must not turn a redacted view into a leak.
    assert.ok(
      !renderDoctor(report).includes('TOKEN-MUST-NOT-APPEAR'),
      'the doctor must never render a stored token',
    )
  } finally {
    store.cleanup()
  }
})

test('a selected account with no stored password warns, and says which account', async () => {
  const store = seededAccountStore({ kind: 'none' })
  try {
    const report = await runDoctor({
      env: { ...BLANK, JUMPSERVER_MCP_CONFIG: MISSING_CONFIG },
      probePort: NO_PORT,
      profilesPath: store.profilesPath,
    })
    const credential = checkNamed(report, 'credential')
    assert.equal(credential.status, 'warn', 'no password anywhere is still only advisory')
    assert.match(credential.detail, /生产维护账号/, 'the warning must name the account that has no password')
    assert.match(credential.detail, /no password saved/)
  } finally {
    store.cleanup()
  }
})

test('V0.6.1 (B-4): the compiled tool surface is checked, and a stale build is called STALE', async () => {
  const report = await doctor({
    env: { ...BLANK, JUMPSERVER_MCP_CONFIG: MISSING_CONFIG },
    probePort: NO_PORT,
  })
  const surface = checkNamed(report, 'tool surface')
  // The repository's own lib/ is the build under test here, so the check must
  // pass in CI — and it must be an 'ok', not a silent skip.
  assert.equal(surface.status, 'ok', 'the tool surface check must pass on a fresh build: ' + surface.detail)
  assert.match(surface.detail, /publishes all 23 always-on tools/)
})

test('V0.6.1 (B-4): a missing tool name is reported as a stale build, with the fix', () => {
  // The checker reads the COMPILED files, so the failure is exercised against
  // a tree whose lib/ carries none of the tool names — the state a source
  // edit without a rebuild leaves behind.
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-doctor-lib-'))
  try {
    const libDir = join(dir, 'lib')
    mkdirSync(libDir, { recursive: true })
    writeFileSync(join(libDir, 'server.js'), '// an old build with almost nothing in it\n', 'utf8')
    const result = checkCompiledToolSurface(dir)
    assert.equal(result.status, 'fail')
    assert.match(result.detail, /STALE/)
    assert.match(result.detail, /jumpserver_status/)
    assert.match(String(result.fix), /npm run build/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('V0.6.1 (B-4): an unbuilt tree is reported as "never built", not as a stale build', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-doctor-nolib-'))
  try {
    const result = checkCompiledToolSurface(dir)
    assert.equal(result.status, 'fail')
    assert.match(result.detail, /never been built/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
