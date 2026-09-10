/**
 * V0.5.0 configuration layers: connector ENV > config.json > defaults.
 *
 * Before this version config.json was mandatory — `createRuntime()` threw when
 * the file was missing — and the only connection value reachable from the
 * environment was the password. These tests pin the new contract: host / port
 * / username may arrive from the WorkBuddy connector form, config.json stays
 * fully supported, and a value that is still missing is refused with an error
 * that tells the operator where to fix it.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { ConfigIncompleteError, parseConfig } from '../../lib/config/schema.js'
import { ENV_KEYS, readEnvConnection, sourceOf } from '../../lib/config/env.js'

const MINIMAL = { host: 'jump.example.com', username: 'IT00123' }

test('the ENV key names are the documented contract', () => {
  assert.equal(ENV_KEYS.host, 'JUMPSERVER_HOST')
  assert.equal(ENV_KEYS.port, 'JUMPSERVER_PORT')
  assert.equal(ENV_KEYS.username, 'JUMPSERVER_USERNAME')
  assert.equal(ENV_KEYS.password, 'JUMPSERVER_PASSWORD')
})

/* ------------------------------------------------------------- merging */

test('parseConfig accepts an empty config when ENV supplies host + username', () => {
  const cfg = parseConfig({}, { host: 'jump.example.com', username: 'IT00123' })
  assert.equal(cfg.host, 'jump.example.com')
  assert.equal(cfg.username, 'IT00123')
  assert.equal(cfg.port, 2222, 'port falls back to the JumpServer default')
})

test('config.json alone still works (an existing deployment is untouched)', () => {
  const cfg = parseConfig(MINIMAL)
  assert.equal(cfg.host, 'jump.example.com')
  assert.equal(cfg.username, 'IT00123')
  assert.equal(cfg.port, 2222)
})

test('ENV overrides config.json for host / port / username', () => {
  const cfg = parseConfig(
    { host: 'file.example.com', port: 2200, username: 'fromfile' },
    { host: 'env.example.com', port: 2222, username: 'fromenv' },
  )
  assert.equal(cfg.host, 'env.example.com')
  assert.equal(cfg.port, 2222)
  assert.equal(cfg.username, 'fromenv')
})

test('a partially overridden view keeps the file value for untouched fields', () => {
  const cfg = parseConfig({ host: 'file.example.com', port: 2200, username: 'fromfile' }, { host: 'env.example.com' })
  assert.equal(cfg.host, 'env.example.com')
  assert.equal(cfg.port, 2200, 'port still comes from config.json')
  assert.equal(cfg.username, 'fromfile')
})

test('policy settings are never taken from the environment', () => {
  const cfg = parseConfig({ ...MINIMAL, permissionMode: 'FULL_ACCESS' }, { host: 'env.example.com' })
  assert.equal(cfg.permissionMode, 'FULL_ACCESS')
  assert.equal(cfg.host, 'env.example.com')
})

/* ---------------------------------------------------------- validation */

test('a missing host or username is refused with actionable instructions', () => {
  assert.throws(() => parseConfig({}, {}), (err) => {
    assert.ok(err instanceof ConfigIncompleteError)
    assert.deepEqual([...err.missing], ['host', 'username'])
    assert.match(err.message, /JUMPSERVER_HOST/, 'names the connector environment key')
    assert.match(err.message, /config\.json/, 'names the file fallback')
    return true
  })
})

test('only the missing field is reported', () => {
  assert.throws(() => parseConfig({ host: 'jump.example.com' }, {}), (err) => {
    assert.ok(err instanceof ConfigIncompleteError)
    assert.deepEqual([...err.missing], ['username'])
    return true
  })
})

test('an empty-string host counts as missing, not as a value', () => {
  assert.throws(() => parseConfig({ host: '', username: 'u' }, {}), ConfigIncompleteError)
})

/* ------------------------------------------------------------ password */

test('the ENV password never leaks into the config object', () => {
  const cfg = parseConfig({}, { ...MINIMAL, password: 'hunter2' })
  assert.equal(cfg.password, undefined, 'the injected credential must stay out of the config object')
})

test('config.json keeps its own literal password', () => {
  const cfg = parseConfig({ ...MINIMAL, password: 'fromFile' })
  assert.equal(cfg.password, 'fromFile')
})

/* --------------------------------------------------------- env reading */

test('readEnvConnection ignores blank values and parses the port', () => {
  const out = readEnvConnection({
    JUMPSERVER_HOST: '  jump.example.com  ',
    JUMPSERVER_PORT: '2222',
    JUMPSERVER_USERNAME: '   ',
    JUMPSERVER_PASSWORD: '',
  })
  assert.equal(out.host, 'jump.example.com')
  assert.equal(out.port, 2222)
  assert.equal(out.username, undefined, 'a blank username must not shadow config.json')
  assert.equal(out.password, undefined, 'an empty password is "not set"')
})

test('readEnvConnection refuses a non-numeric or out-of-range port', () => {
  assert.throws(() => readEnvConnection({ JUMPSERVER_PORT: 'abc' }), /JUMPSERVER_PORT/)
  assert.throws(() => readEnvConnection({ JUMPSERVER_PORT: '70000' }), /JUMPSERVER_PORT/)
  assert.throws(() => readEnvConnection({ JUMPSERVER_PORT: '0' }), /JUMPSERVER_PORT/)
})

test('readEnvConnection returns nothing when no connector values are present', () => {
  const out = readEnvConnection({})
  assert.deepEqual(out, {})
})

test('the password is not trimmed (whitespace can be part of a credential)', () => {
  const out = readEnvConnection({ JUMPSERVER_PASSWORD: ' pw ' })
  assert.equal(out.password, ' pw ')
})

/* -------------------------------------------------------- provenance */

test('sourceOf reports which layer won', () => {
  assert.equal(sourceOf('file', 'env'), 'env')
  assert.equal(sourceOf('file', undefined), 'config')
  assert.equal(sourceOf(undefined, undefined), 'default')
})
