#!/usr/bin/env node
/**
 * Pre-submission validator for the WorkBuddy connector package in connector/.
 *
 * Catches the failures that get a connector rejected on review, plus the ones
 * that only surface at a customer's machine after install:
 *   - missing / malformed manifest files
 *   - ${VAR} placeholders that do not match token-schema field keys
 *     (case-sensitive; a mismatch silently injects an empty credential)
 *   - minWorkbuddyVersion too low for the features actually used
 *   - credentials hardcoded anywhere in the package
 *   - a typo in the npm package name referenced by mcp.json
 *
 * Run: npm run validate:connector
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const pkgDir = join(root, 'connector')

const failures = []
const warnings = []
const notes = []

function fail(msg) {
  failures.push(msg)
}
function warn(msg) {
  warnings.push(msg)
}
function note(msg) {
  notes.push(msg)
}

function readJson(path) {
  if (!existsSync(path)) {
    fail(`missing file: ${relative(root, path)}`)
    return null
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    fail(`${relative(root, path)} is not valid JSON: ${error.message}`)
    return null
  }
}

/** Every ${VAR} reference in a JSON value, at any depth. */
function collectPlaceholders(value, found = new Set()) {
  if (typeof value === 'string') {
    for (const m of value.matchAll(/\$\{([A-Za-z0-9_]+)\}/g)) found.add(m[1])
  } else if (Array.isArray(value)) {
    for (const item of value) collectPlaceholders(item, found)
  } else if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) collectPlaceholders(item, found)
  }
  return found
}

/** Resume.schema: the version map from the official docs. */
const FEATURE_MIN_VERSION = {
  'mcp.runtime': '5.0.0',
  'mcp.staticEnv': '5.0.0',
  'mcp.preAuth': '5.0.0',
  'mcp.cwd': '4.22.15',
  'mcp.disabledTools': '4.22.15',
  'meta.auth_mode.token': '4.23.0',
  'meta.examples': '4.24.0',
}

function versionRank(v) {
  return String(v)
    .split('.')
    .map((n) => Number.parseInt(n, 10) || 0)
    .reduce((acc, n) => acc * 1000 + n, 0)
}

function compareVersions(a, b) {
  const ra = versionRank(a)
  const rb = versionRank(b)
  return ra === rb ? 0 : ra > rb ? 1 : -1
}

// ---------------------------------------------------------------- structure

if (!existsSync(pkgDir)) {
  fail('connector/ directory does not exist')
  console.log(JSON.stringify({ ok: false, failures, warnings, notes }, null, 2))
  process.exit(1)
}

const meta = readJson(join(pkgDir, 'connector-meta.json'))
const mcp = readJson(join(pkgDir, 'mcp.json'))
const schema = readJson(join(pkgDir, 'token-schema.json'))

if (!existsSync(join(pkgDir, 'icon.svg'))) {
  const alt = ['icon.png', 'icon.jpg'].find((f) => existsSync(join(pkgDir, f)))
  if (!alt) fail('missing icon: icon.svg (or icon.png / icon.jpg) is required')
  else warn(`using ${alt}; SVG is the recommended icon format`)
}

// ------------------------------------------------------------ connector-meta

if (meta) {
  for (const field of ['name', 'name_en', 'description', 'description_zh', 'description_en', 'source']) {
    if (typeof meta[field] !== 'string' || meta[field].length === 0) {
      fail(`connector-meta.json: required field "${field}" is missing or empty`)
    }
  }
  if (typeof meta.source === 'string' && !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(meta.source)) {
    fail(`connector-meta.json: source "${meta.source}" must be kebab-case (lowercase letters, digits, hyphens)`)
  }
  if (meta.type !== undefined && !['mcp', 'cli', 'skill-only'].includes(meta.type)) {
    fail(`connector-meta.json: type "${meta.type}" must be mcp, cli or skill-only`)
  }
  if (!Array.isArray(meta.examples_zh) || meta.examples_zh.length === 0) {
    fail('connector-meta.json: examples_zh must be a non-empty array')
  }
  if (!Array.isArray(meta.examples_en) || meta.examples_en.length === 0) {
    fail('connector-meta.json: examples_en must be a non-empty array')
  }
  if (meta.version === undefined) {
    warn('connector-meta.json: version is recommended (semver, incremented on each update)')
  }
}

// ------------------------------------------------------------------ mcp.json

let usedFeatures = new Set()
let placeholders = new Set()

if (mcp) {
  const servers = mcp.mcpServers
  if (servers === null || typeof servers !== 'object' || Array.isArray(servers)) {
    fail('mcp.json: top-level "mcpServers" object is required')
  } else {
    const names = Object.keys(servers)
    if (names.length === 0) fail('mcp.json: mcpServers is empty')
    if (names.length > 1) fail(`mcp.json: exactly one MCP server is allowed, found ${names.length} (${names.join(', ')})`)

    for (const name of names) {
      const server = servers[name]
      if (server === null || typeof server !== 'object') {
        fail(`mcp.json: server "${name}" must be an object`)
        continue
      }
      const type = server.type ?? (server.command ? 'stdio' : undefined)
      if (!['stdio', 'sse', 'streamableHttp'].includes(type)) {
        fail(`mcp.json: server "${name}" type must be stdio, sse or streamableHttp (got ${JSON.stringify(server.type)})`)
      }
      if (type === 'stdio' && (typeof server.command !== 'string' || server.command.length === 0)) {
        fail(`mcp.json: stdio server "${name}" requires a "command"`)
      }
      if ((type === 'sse' || type === 'streamableHttp') && typeof server.url === 'string') {
        if (!server.url.startsWith('https://')) {
          fail(`mcp.json: remote server "${name}" url must use HTTPS in production (got ${server.url})`)
        }
      }
      if (server.runtime !== undefined) usedFeatures.add('mcp.runtime')
      if (server.staticEnv !== undefined || server.staticHeaders !== undefined) usedFeatures.add('mcp.staticEnv')
      if (server.preAuth !== undefined) usedFeatures.add('mcp.preAuth')
      if (server.cwd !== undefined) usedFeatures.add('mcp.cwd')
      if (server.disabledTools !== undefined) usedFeatures.add('mcp.disabledTools')

      placeholders = collectPlaceholders(server)

      // Convention check: the npm package the connector will launch must exist
      // and match this repo's package name.
      if (Array.isArray(server.args)) {
        const npmish = server.args.find((a) => typeof a === 'string' && /^[@a-z0-9].*/.test(a) && !a.startsWith('-'))
        const own = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
        if (npmish && npmish !== own.name) {
          warn(`mcp.json launches "${npmish}" but this repo publishes "${own.name}" — confirm that is intended`)
        }
      }
    }
  }
}

// -------------------------------------------------------- token-schema match

if (meta?.auth_mode === 'token') {
  usedFeatures.add('meta.auth_mode.token')
  if (!schema) {
    fail('auth_mode is "token" but token-schema.json is missing')
  }
}

if (schema) {
  usedFeatures.add('meta.auth_mode.token')

  if (typeof schema.title !== 'string' || schema.title.length === 0) {
    fail('token-schema.json: title is required')
  }
  if (typeof schema.description !== 'string' || schema.description.length === 0) {
    fail('token-schema.json: description is required (it is what reassures the user about credential storage)')
  }
  if (!Array.isArray(schema.fields) || schema.fields.length === 0) {
    fail('token-schema.json: fields must be a non-empty array')
  } else {
    const keys = []
    for (const [i, field] of schema.fields.entries()) {
      const at = `token-schema.json: fields[${i}]`
      if (typeof field.key !== 'string' || field.key.length === 0) {
        fail(`${at}.key is required`)
        continue
      }
      keys.push(field.key)
      if (typeof field.label !== 'string' || field.label.length === 0) fail(`${at}.label is required`)
      if (!['text', 'password'].includes(field.type)) fail(`${at}.type must be "text" or "password" (got ${JSON.stringify(field.type)})`)
      if (typeof field.required !== 'boolean') fail(`${at}.required must be a boolean`)
      if (/_TOKEN$|_KEY$|_SECRET$|PASSWORD$/i.test(field.key) && field.type !== 'password') {
        fail(`${at} ("${field.key}") looks like a credential but type is "${field.type}" — use "password"`)
      }
    }

    const dupes = keys.filter((k, i) => keys.indexOf(k) !== i)
    if (dupes.length > 0) fail(`token-schema.json: duplicate field keys: ${[...new Set(dupes)].join(', ')}`)

    // The single most common submission bug: a placeholder that does not match
    // a field key (case-sensitively) injects nothing, and the server fails later
    // with a confusing auth error instead of a clear config error.
    const schemaKeys = new Set(keys)
    const unmatched = [...placeholders].filter((p) => !schemaKeys.has(p))
    const unused = [...schemaKeys].filter((k) => !placeholders.has(k))
    if (unmatched.length > 0) {
      fail(
        `mcp.json references ${unmatched.map((p) => '${' + p + '}').join(', ')} but token-schema.json has no such field key ` +
          `(keys: ${keys.join(', ')}) — placeholder names must match exactly, case-sensitively`,
      )
    }
    if (unused.length > 0) {
      fail(
        `token-schema.json declares ${unused.join(', ')} but mcp.json never references ` +
          `${unused.map((k) => '${' + k + '}').join(', ')} — the form would collect a value that is never injected`,
      )
    }
    notes.push(`${placeholders.size} placeholder(s) matched against ${keys.length} form field(s): ${[...placeholders].join(', ')}`)
  }
}

// ------------------------------------------------------------ version gating

if (meta && usedFeatures.size > 0) {
  let required = '0.0.0'
  let requiredBy = ''
  for (const feature of usedFeatures) {
    const min = FEATURE_MIN_VERSION[feature]
    if (min && compareVersions(min, required) > 0) {
      required = min
      requiredBy = feature
    }
  }
  const declared = meta.minWorkbuddyVersion
  if (declared === undefined) {
    fail(
      `connector-meta.json: minWorkbuddyVersion is required when using newer fields ` +
        `(needs >= ${required} because of ${requiredBy})`,
    )
  } else if (compareVersions(declared, required) < 0) {
    fail(
      `connector-meta.json: minWorkbuddyVersion "${declared}" is too low — ` +
        `${requiredBy} requires >= ${required} (use the highest of all used features)`,
    )
  } else {
    notes.push(`minWorkbuddyVersion "${declared}" covers required ${required} (${requiredBy})`)
  }
}

// ------------------------------------------------------- credential leakage

/**
 * Hardcoded-credential scan.
 *
 * JSON is walked structurally and only a key that IS a credential name is
 * inspected. Matching prose instead ("label_en": "Password", "type": "password")
 * is a false positive, and a validator that cries wolf gets switched off —
 * which is worse than not having one.
 *
 * Everything else (markdown, svg, yaml) is scanned line-wise for an assignment
 * to a credential-shaped key whose value does not look like a documented
 * placeholder.
 */
const CRED_KEY = /^(password|passwd|pwd|secret|client_?secret|access_?token|refresh_?token|api_?key|apikey|token|credential)$/i
const PLACEHOLDER_VALUE = /^(\$\{[A-Za-z0-9_]+\}|<[^>]*>|your[-_ ].*|xxx+|\*+|\.{3}|)$/i

/** A value carrying CJK characters is documentation, not a live secret. */
function looksLikeDoc(value) {
  return PLACEHOLDER_VALUE.test(value) || /[^\u0000-\u007f]/.test(value)
}

function scanJsonSecrets(node, relPath, trail) {
  if (node === null || typeof node !== 'object') return
  if (Array.isArray(node)) {
    node.forEach((item, i) => scanJsonSecrets(item, relPath, `${trail}[${i}]`))
    return
  }
  for (const [key, value] of Object.entries(node)) {
    const at = trail ? `${trail}.${key}` : key
    if (typeof value === 'string') {
      if (CRED_KEY.test(key) && value.trim().length >= 6 && !looksLikeDoc(value.trim())) {
        fail(`${relPath}: ${at} holds what looks like a hardcoded credential — use a \${VAR} reference`)
      } else if (CRED_KEY.test(key) && value.trim().length > 0 && !looksLikeDoc(value.trim())) {
        note(`${relPath}: ${at} is set but short — confirm it is not a real credential`)
      }
    } else {
      scanJsonSecrets(value, relPath, at)
    }
  }
}

function scanTextSecrets(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      scanTextSecrets(full)
      continue
    }
    const rel = relative(root, full)
    const dot = entry.lastIndexOf('.')
    const ext = dot >= 0 ? entry.slice(dot) : ''

    if (ext === '.json') {
      try {
        scanJsonSecrets(JSON.parse(readFileSync(full, 'utf8')), rel, '')
      } catch {
        warn(`${rel} could not be parsed for the credential scan`)
      }
      continue
    }
    if (!['.md', '.svg', '.yml', '.yaml'].includes(ext)) continue

    for (const [i, line] of readFileSync(full, 'utf8').split('\n').entries()) {
      const m = line.match(/(?:^|[\s"'])([A-Za-z_]*(?:password|secret|token|api_?key)[A-Za-z_]*)\s*[:=]\s*["']?([^"'\s,}]+)["']?/i)
      if (!m) continue
      if (looksLikeDoc(m[2]) || /\$\{/.test(line)) continue
      fail(`${rel}:${i + 1} appears to hardcode a credential: ${line.trim().slice(0, 80)}`)
    }
  }
}

scanTextSecrets(pkgDir)

// ------------------------------------------------------------------- skills/

const skillsDir = join(pkgDir, 'skills')
if (!existsSync(skillsDir)) {
  warn('connector/skills/ is absent — optional for MCP (tool descriptions cover it) but recommended')
} else {
  const found = readdirSync(skillsDir).filter((d) => existsSync(join(skillsDir, d, 'SKILL.md')))
  if (found.length === 0) warn('connector/skills/ exists but contains no {skill-name}/SKILL.md')
  else notes.push(`skills: ${found.join(', ')}`)
}

// ---------------------------------------------------------- desensitisation

/**
 * The package ships to every user's machine, so anything identifying THIS
 * machine must never be in it: absolute install paths, the local user/host
 * name, real internal addresses.
 *
 * Two deliberate non-findings:
 *   - `~/…` is the correct way to name a user-owned path and is allowed;
 *     only a *resolved* home path (/Users/x, /home/x, C:\…) is machine-specific.
 *   - Documentation IPs (RFC 5737: 192.0.2/24, 198.51.100/24, 203.0.113/24)
 *     are exactly what an example should use.
 */
// The lookbehind is load-bearing: without it "https:/" matches the drive-letter
// branch on "s:/" and every URL in the package becomes a false positive.
const ABS_PATH = /(?<![A-Za-z0-9])[A-Za-z]:[\\/]|\\\\[A-Za-z0-9._-]+[\\/]|\/(?:Users|home)\/[A-Za-z0-9._-]+\//

const DOC_IP = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/
const PRIVATE_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b/g
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g

/** Identity of the machine running this validator — nothing here may ship. */
const LOCAL_IDENTITY = [
  os.userInfo().username,
  os.hostname(),
  os.hostname().split('.')[0],
  process.env.USERNAME,
  process.env.USER,
  process.env.COMPUTERNAME,
  process.env.USERDOMAIN,
]
  .filter((t) => typeof t === 'string' && t.length >= 4)
  .map((t) => ({ raw: t, re: new RegExp(`\\b${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i') }))

const ALLOWED_FILES = /^(connector-meta\.json|mcp\.json|cli\.json|token-schema\.json|icon\.(svg|png|jpg)|skills\/[A-Za-z0-9._-]+\/(SKILL\.md|[A-Za-z0-9._/-]+))$/

function scanPackageFiles() {
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      if (statSync(full).isDirectory()) {
        walk(full)
        continue
      }
      const rel = relative(pkgDir, full).split('\\').join('/')

      if (!ALLOWED_FILES.test(rel)) {
        fail(`package contains an unexpected file: ${rel} — only connector-meta.json / mcp.json / cli.json / token-schema.json / icon.* / skills/{name}/** may ship`)
      }

      let text
      try {
        text = readFileSync(full, 'utf8')
      } catch {
        continue
      }
      for (const [i, line] of text.split('\n').entries()) {
        const at = `${relative(root, full)}:${i + 1}`
        if (ABS_PATH.test(line)) {
          fail(`${at} contains a machine-specific absolute path — the docs forbid hardcoding install paths: ${line.trim().slice(0, 90)}`)
        }
        for (const ip of line.match(PRIVATE_IP) ?? []) {
          if (!DOC_IP.test(ip)) warn(`${at} references a private/internal address (${ip}) — use a documentation range (192.0.2.x / 198.51.100.x / 203.0.113.x) or a hostname in examples`)
        }
        for (const token of LOCAL_IDENTITY) {
          if (token.re.test(line)) fail(`${at} leaks this machine's identity ("${token.raw}") — remove before submitting: ${line.trim().slice(0, 90)}`)
        }
        for (const mail of line.match(EMAIL) ?? []) {
          if (!/@example\.(com|org|net)$/i.test(mail)) warn(`${at} contains an email address (${mail}) — confirm this is intended for public release`)
        }
      }
    }
  }
  walk(pkgDir)
}

if (existsSync(pkgDir)) scanPackageFiles()

// -------------------------------------------------------------------- report

const report = {
  ok: failures.length === 0,
  failures,
  warnings,
  notes,
}

console.log(JSON.stringify(report, null, 2))
process.exit(failures.length === 0 ? 0 : 1)
