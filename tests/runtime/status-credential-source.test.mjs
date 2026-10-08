/**
 * V0.5.11: the connector always KNEW which bastion account was in effect — the
 * console's 设置 tab showed it — but the MODEL did not. `jumpserver_status`
 * carried no credential-source field, so "现在用的是哪个堡垒机账号？" was
 * unanswerable from a tool result. This file freezes both halves of the fix:
 *
 *  1. server.ts must PUT the source on the payload. Read end-to-end over real
 *     MCP stdio against the compiled lib/server.js — the only vantage point
 *     that sees exactly what the host/model sees.
 *  2. tools-common.ts renderResult() is a WHITELIST, so a payload field stays
 *     invisible unless it is explicitly listed there. Read at unit level
 *     against the compiled lib/runtime/tools-common.js: the projection is a
 *     pure string function, so a full server boot would only re-test the
 *     harness, not the rule under test.
 *
 * Hermetic HOME: ProfileStore / CredentialVault default under ~/.workbuddy.
 * Every spawned server is pointed at a throwaway USERPROFILE/HOME so the
 * developer's real account store can neither leak into these assertions nor be
 * written to.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MISSING_CONFIG, openServer } from '../helpers/mcp.mjs'
import { renderResult } from '../../lib/runtime/tools-common.js'
import { CredentialVault } from '../../lib/security/credential-vault.js'

/** A value that must never reach a model-facing byte. */
const SENTINEL_PASSWORD = 'SENTINEL_STATUS_PW_DO_NOT_LEAK'
const PROFILE_LABEL = '生产维护'
const PROFILE_PASSWORD = 'SENTINEL_PROFILE_PW_DO_NOT_LEAK'

function tempHome() {
  const dir = mkdtempSync(join(tmpdir(), 'jumpserver-mcp-home-'))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

/** Point the child process's ~ at a throwaway directory. */
function isolatedEnv(homeDir, extra = {}) {
  return { USERPROFILE: homeDir, HOME: homeDir, ...extra }
}

/**
 * Seed an ACTIVE multi-account profile in the throwaway HOME. The secret is
 * stored the only way the runtime can read it back: encrypted by the very
 * CredentialVault class the server uses, under a key file in that HOME.
 */
function seedActiveProfile(homeDir, { label, host, port, username, password }) {
  const storeDir = join(homeDir, '.workbuddy', 'jumpserver-mcp')
  mkdirSync(storeDir, { recursive: true })
  const keyPath = join(storeDir, 'vault.key')
  writeFileSync(keyPath, randomBytes(32))
  const token = new CredentialVault({ keyPath }).encrypt(password)
  const file = {
    version: 1,
    activeProfileId: 'p1',
    profiles: [
      { id: 'p1', label, host, port, username, secret: { kind: 'vault', token }, createdAt: 1, updatedAt: 1 },
    ],
  }
  writeFileSync(join(storeDir, 'profiles.json'), JSON.stringify(file, null, 2), 'utf8')
}

test('an env-supplied credential is reported by source and layer, never by value', async () => {
  const home = tempHome()
  const server = await openServer({
    configPath: MISSING_CONFIG,
    env: isolatedEnv(home.dir, {
      JUMPSERVER_HOST: '203.0.113.9',
      JUMPSERVER_USERNAME: 'probe',
      JUMPSERVER_PASSWORD: SENTINEL_PASSWORD,
    }),
  })
  try {
    const { text } = await server.call('jumpserver_status')
    assert.match(
      text,
      /^credential: from env（环境变量 JUMPSERVER_PASSWORD）$/m,
      'status must name the credential layer; got:\n' + text,
    )
    assert.match(
      text,
      /^connection host: from env \/ username: from env$/m,
      'host and username sources must be stated separately; got:\n' + text,
    )
  } finally {
    server.close()
    home.cleanup()
  }
})

test('a profile-supplied credential is reported with its account label', async () => {
  const home = tempHome()
  seedActiveProfile(home.dir, {
    label: PROFILE_LABEL,
    host: '203.0.113.7',
    port: 2222,
    username: 'maintainer',
    password: PROFILE_PASSWORD,
  })
  const server = await openServer({
    configPath: MISSING_CONFIG,
    env: isolatedEnv(home.dir, {
      // The active profile outranks the connector-injected credential — this is
      // the multi-account feature in one assertion.
      JUMPSERVER_HOST: '203.0.113.9',
      JUMPSERVER_USERNAME: 'probe',
      JUMPSERVER_PASSWORD: SENTINEL_PASSWORD,
    }),
  })
  try {
    const { result, text } = await server.call('jumpserver_status')
    assert.match(
      text,
      new RegExp('^credential: from profile（账号：' + PROFILE_LABEL + '）$', 'm'),
      'a profile credential must name the selected account; got:\n' + text,
    )
    assert.ok(!text.includes(PROFILE_PASSWORD), 'the profile password must never be rendered')
    assert.ok(!JSON.stringify(result).includes(PROFILE_PASSWORD), 'the profile password must not appear in the raw tool result')
  } finally {
    server.close()
    home.cleanup()
  }
})

test('the sentinel password survives no part of the end-to-end payload', async () => {
  const home = tempHome()
  const server = await openServer({
    configPath: MISSING_CONFIG,
    env: isolatedEnv(home.dir, {
      JUMPSERVER_HOST: '203.0.113.9',
      JUMPSERVER_USERNAME: 'probe',
      JUMPSERVER_PASSWORD: SENTINEL_PASSWORD,
    }),
  })
  try {
    const { result, text } = await server.call('jumpserver_status')
    assert.ok(text.includes('credential: from env'), 'the source line must be present for this test to be meaningful')
    assert.ok(!text.includes(SENTINEL_PASSWORD), 'the password value must never reach the model-facing text')
    const raw = JSON.stringify(result)
    assert.ok(!raw.includes(SENTINEL_PASSWORD), 'the password value must not appear in the raw tool result')
    assert.ok(!raw.includes('v1:'), 'no ciphertext-shaped token (v1:) may appear anywhere in the result')
  } finally {
    server.close()
    home.cleanup()
  }
})

test('renderResult is a whitelist: the source renders only when present', () => {
  const withSource = renderResult({
    ok: true,
    credentialSource: 'profile',
    credentialSourceDetail: '账号：' + PROFILE_LABEL,
    hostSource: 'config',
    usernameSource: 'profile',
  })
  assert.match(withSource, /^credential: from profile（账号：生产维护）$/m)
  assert.match(withSource, /^connection host: from config \/ username: from profile$/m)

  // A value with NO source field must not gain one — and must not print the
  // literal string "undefined" where a field would have been.
  const withoutSource = renderResult({ ok: true, state: 'DISCONNECTED' })
  assert.ok(!withoutSource.includes('credential:'), 'no source field means no credential line')
  assert.ok(!withoutSource.includes('connection host:'), 'no host/username source means no connection-source line')
  assert.ok(!withoutSource.includes('undefined'), 'a missing field must never render "undefined"')

  // An empty detail must not leave an empty pair of parentheses.
  const bareSource = renderResult({ ok: true, credentialSource: 'config' })
  assert.match(bareSource, /^credential: from config$/m)
  assert.ok(!bareSource.includes('（）'), 'an absent detail must not render empty parentheses')
})
