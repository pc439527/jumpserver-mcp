/**
 * V0.5.11 — a selected account must change the WHOLE identity, not just the password.
 *
 * The defect this freezes: `resolvePassword()` honoured the active profile while
 * `getConfig()` kept returning the host / port / username from config.json — so
 * the console showed the account and claimed "the next tool call reconnects with
 * it", but SSH still logged in with the OLD identity and only swapped the
 * secret. A second account with a different login name could therefore never
 * authenticate.
 *
 * These cases run the REAL `createRuntime()` — no stand-ins for the profile
 * store, the vault or the config merge, because the bug lived exactly in how
 * those three meet. Every call is pointed at throwaway directories through
 * USERPROFILE / HOME, so vault.key and profiles.json are created under
 * os.tmpdir(); the user's real ~/.workbuddy is never read or written.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createRuntime } from '../../lib/runtime/runtime.js'

/** Every env key these tests may touch, so the caller's process is left intact. */
const CONTROLLED_ENV = [
  'USERPROFILE',
  'HOME',
  'JUMPSERVER_MCP_CONFIG',
  'JUMPSERVER_MCP_SESSION',
  'JUMPSERVER_HOST',
  'JUMPSERVER_PORT',
  'JUMPSERVER_USERNAME',
  'JUMPSERVER_PASSWORD',
]

/** Apply a connector env for one test; returns a restore() that puts it all back. */
function setEnv(values) {
  const saved = new Map()
  for (const key of CONTROLLED_ENV) {
    saved.set(key, Object.prototype.hasOwnProperty.call(process.env, key) ? process.env[key] : undefined)
    delete process.env[key]
  }
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null) process.env[key] = String(value)
  }
  return () => {
    for (const key of CONTROLLED_ENV) {
      const prev = saved.get(key)
      if (prev === undefined) delete process.env[key]
      else process.env[key] = prev
    }
  }
}

function tempDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix))
}

/**
 * Boot the real runtime against throwaway config + home directories. The ops
 * console is switched off (these tests are about the connection tuple, not
 * ports) and the audit sink goes to the same temp dir.
 */
function bootRuntime({ config = {}, env = {}, home } = {}) {
  const dir = tempDir('jumpserver-acct-rt-')
  const homeDir = home ?? tempDir('jumpserver-acct-home-')
  const configPath = join(dir, 'config.json')
  writeFileSync(
    configPath,
    JSON.stringify({ auditViewer: { enabled: false }, auditPath: join(dir, 'audit.jsonl'), ...config }),
    'utf8',
  )
  const restoreEnv = setEnv({
    JUMPSERVER_MCP_CONFIG: configPath,
    USERPROFILE: homeDir,
    HOME: homeDir,
    ...env,
  })
  const rt = createRuntime()
  return {
    rt,
    home: homeDir,
    dir,
    profilesPath: join(homeDir, '.workbuddy', 'jumpserver-mcp', 'profiles.json'),
    close: () => {
      try {
        rt.dispose()
      } finally {
        restoreEnv()
      }
    },
  }
}

test('with no active account, the connection still comes from config.json', () => {
  const b = bootRuntime({
    config: { host: 'cfg-host.example', username: 'cfg-user', port: 2200 },
    env: { JUMPSERVER_PASSWORD: 'env-sentinel-do-not-log' },
  })
  try {
    const cfg = b.rt.getConfig()
    assert.equal(cfg.host, 'cfg-host.example', 'no account selected => config.json wins')
    assert.equal(cfg.username, 'cfg-user')
    assert.equal(cfg.port, 2200)
    assert.deepEqual([...b.rt.configProblems()], [])

    const view = b.rt.connection()
    assert.deepEqual(view.host, { value: 'cfg-host.example', source: 'config' })
    assert.deepEqual(view.username, { value: 'cfg-user', source: 'config' })
    assert.equal(view.password.source, 'env')
    assert.equal(view.complete, true)
  } finally {
    b.close()
  }
})

test('a selected account overrides host / port / username and reports source=profile', () => {
  const ACCOUNT_SECRET = 'acct-secret-sentinel-do-not-log'
  const CONNECTOR_SECRET = 'env-sentinel-do-not-log'
  const b = bootRuntime({
    config: { host: 'cfg-host.example', username: 'cfg-user', port: 2200 },
    env: { JUMPSERVER_PASSWORD: CONNECTOR_SECRET },
  })
  try {
    assert.deepEqual(
      b.rt.saveAccount({
        label: '维护账号',
        host: 'acct-host.example',
        port: 2201,
        username: 'acct-user',
        password: ACCOUNT_SECRET,
      }),
      { ok: true },
    )
    const id = b.rt.accounts().profiles[0].id
    assert.deepEqual(b.rt.switchAccount(id), { ok: true })

    // The identity — not just the credential — must now follow the account.
    const cfg = b.rt.getConfig()
    assert.equal(cfg.host, 'acct-host.example', 'the account host must reach the connection layer')
    assert.equal(cfg.port, 2201)
    assert.equal(cfg.username, 'acct-user', 'a different login name must reach the connection layer')

    const view = b.rt.connection()
    assert.deepEqual(view.host, { value: 'acct-host.example', source: 'profile' })
    assert.deepEqual(view.port, { value: '2201', source: 'profile' })
    assert.deepEqual(view.username, { value: 'acct-user', source: 'profile' })
    assert.equal(view.complete, true)

    // The credential resolves to the ACCOUNT's secret, ahead of the connector's.
    assert.equal(b.rt.resolvePassword(), ACCOUNT_SECRET)

    // The password view names the account but never a credential value.
    assert.equal(view.password.source, 'profile')
    assert.equal(view.password.present, true)
    assert.equal(view.password.via, '维护账号')
    const text = JSON.stringify(view)
    assert.equal(text.includes(ACCOUNT_SECRET), false, 'the view must not leak the account secret')
    assert.equal(text.includes(CONNECTOR_SECRET), false, 'the view must not leak the connector secret')
    assert.equal(text.includes('v1:'), false, 'the view must not leak vault ciphertext')
  } finally {
    b.close()
  }
})

test('a selected account completes a connection that config.json and ENV leave blank', () => {
  const b = bootRuntime({ config: {} }) // no host / username anywhere
  try {
    assert.deepEqual([...b.rt.configProblems()], ['host', 'username'], 'starts out incomplete')

    assert.equal(
      b.rt.saveAccount({ label: '仅账号', host: 'acct-host.example', port: 2222, username: 'acct-user' }).ok,
      true,
    )
    const id = b.rt.accounts().profiles[0].id
    assert.deepEqual(b.rt.switchAccount(id), { ok: true })

    assert.deepEqual([...b.rt.configProblems()], [], 'the account alone makes the connection complete')
    assert.equal(b.rt.connection().complete, true)
  } finally {
    b.close()
  }
})

test('saving under an unknown id is PROFILE_NOT_FOUND, not a store failure', () => {
  const b = bootRuntime({ config: { host: 'cfg-host.example', username: 'cfg-user' } })
  try {
    const res = b.rt.saveAccount({ id: 'no-such-id', label: 'x', host: 'h.example', port: 2222, username: 'u' })
    assert.deepEqual(res, { ok: false, error: 'PROFILE_NOT_FOUND' })
    assert.notEqual(res.error, 'PROFILES_FILE_UNREADABLE', 'a missing id is not a corrupt file')
  } finally {
    b.close()
  }
})

test('a corrupt profiles file is reported by category and left untouched', () => {
  const b = bootRuntime({ config: { host: 'cfg-host.example', username: 'cfg-user' } })
  try {
    const CORRUPT = '{ this is not valid json'
    mkdirSync(dirname(b.profilesPath), { recursive: true })
    writeFileSync(b.profilesPath, CORRUPT, 'utf8')

    assert.deepEqual(
      b.rt.saveAccount({ id: 'anything', label: 'x', host: 'h.example', port: 2222, username: 'u' }),
      { ok: false, error: 'PROFILES_FILE_UNREADABLE' },
    )
    assert.deepEqual(b.rt.saveAccount({ label: 'x', host: 'h.example', port: 2222, username: 'u' }), {
      ok: false,
      error: 'PROFILES_FILE_UNREADABLE',
    })
    assert.deepEqual(b.rt.removeAccount('anything'), { ok: false, error: 'PROFILES_FILE_UNREADABLE' })
    assert.equal(b.rt.accounts().integrity.broken, true)

    assert.equal(
      readFileSync(b.profilesPath, 'utf8'),
      CORRUPT,
      'the store must never rewrite a file the operator may still recover',
    )
  } finally {
    b.close()
  }
})

test('switching to an unknown id fails without tearing down live sessions', () => {
  const b = bootRuntime({ config: { host: 'cfg-host.example', username: 'cfg-user' } })
  try {
    b.rt.saveAccount({ label: '维护', host: 'acct-host.example', port: 2222, username: 'acct-user' })
    const id = b.rt.accounts().profiles[0].id
    assert.deepEqual(b.rt.switchAccount(id), { ok: true })

    let disposed = 0
    let cleared = 0
    b.rt.registry.dispose = () => {
      disposed += 1
    }
    b.rt.assets.clear = () => {
      cleared += 1
    }
    b.rt.grants.arm('conv-1', 'persistent')

    assert.deepEqual(b.rt.switchAccount('does-not-exist'), { ok: false, error: 'PROFILE_NOT_FOUND' })
    assert.equal(disposed, 0, 'a failed switch must not dispose sessions')
    assert.equal(cleared, 0, 'a failed switch must not clear the asset cache')
    assert.equal(b.rt.grants.isGranted('conv-1'), true, 'a failed switch must not revoke the grant')
  } finally {
    b.close()
  }
})

test('a successful switch does drop the conversation grant', () => {
  const b = bootRuntime({ config: { host: 'cfg-host.example', username: 'cfg-user' } })
  try {
    b.rt.saveAccount({ label: '维护', host: 'acct-host.example', port: 2222, username: 'acct-user' })
    const id = b.rt.accounts().profiles[0].id
    b.rt.grants.arm('conv-1', 'persistent')
    assert.equal(b.rt.grants.isGranted('conv-1'), true)

    assert.deepEqual(b.rt.switchAccount(id), { ok: true })
    // The approval was given while this process pointed at the OLD identity; the
    // switch must not carry it over to the account the user never approved.
    assert.equal(b.rt.grants.isGranted('conv-1'), false)
  } finally {
    b.close()
  }
})
