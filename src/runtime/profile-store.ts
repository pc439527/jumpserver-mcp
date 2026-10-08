/**
 * ProfileStore — several JumpServer login profiles persisted on this machine.
 *
 * One connector used to carry exactly one login (injected by the host form as
 * environment variables). Operators routinely keep more than one account —
 * a day-to-day one and a maintenance one — so this store keeps a list of
 * named profiles plus a pointer to the active one.
 *
 * Invariants that matter for security:
 *  - a password is NEVER written to disk in the clear; it goes through
 *    CredentialVault and only the opaque token is stored;
 *  - every read-facing shape this module exports (ProfileView) is redacted:
 *    it carries `hasSecret`, never the token and never the plaintext.
 *    resolvePassword() is the single deliberate exception and exists only for
 *    the connection layer;
 *  - a corrupt profiles file is reported (integrity().broken) and left on disk
 *    untouched — writes refuse to run rather than silently replace data the
 *    operator might still recover.
 *
 * Persistence is synchronous and atomic (write `<file>.tmp`, then rename over
 * the target), which the store's synchronous API makes the natural choice:
 * Node's single thread already serializes these calls, and the value is
 * durable by the time a method returns.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { CredentialVault } from '../security/credential-vault.js'

/** How a profile's password is stored. `none` = no password saved. */
export type StoredProfileSecret = { kind: 'vault'; token: string } | { kind: 'none' }

export interface StoredProfile {
  /** Stable identifier, generated at creation, never reused or mutated. */
  id: string
  /** Display name, e.g. "生产维护账号". */
  label: string
  host: string
  port: number
  username: string
  /** Credential reference — the token, never the plaintext. */
  secret: StoredProfileSecret
  createdAt: number
  updatedAt: number
}

export interface ProfileFile {
  version: 1
  activeProfileId: string | null
  profiles: StoredProfile[]
}

/** Redacted view handed to callers that must never see a secret. */
export interface ProfileView {
  id: string
  label: string
  host: string
  port: number
  username: string
  hasSecret: boolean
  createdAt: number
  updatedAt: number
  active: boolean
}

export interface ProfileIntegrity {
  broken: boolean
  message: string | null
}

export interface ProfileStoreOptions {
  filePath?: string
  vault?: CredentialVault
  log?: (message: string) => void
}

export interface ProfileUpsertInput {
  /** Omit to create a new profile; supply to update an existing one. */
  id?: string
  label: string
  host: string
  port: number
  username: string
  /**
   * string  = store this password (encrypted)
   * null    = explicitly forget the stored password
   * omitted = keep whatever is already stored (none for a new profile)
   */
  password?: string | null
}

/** Default profiles file, alongside the vault key. */
export function defaultProfileFilePath(): string {
  return join(homedir(), '.workbuddy', 'jumpserver-mcp', 'profiles.json')
}

function emptyProfileFile(): ProfileFile {
  return { version: 1, activeProfileId: null, profiles: [] }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseSecret(value: unknown): StoredProfileSecret | null {
  if (!isRecord(value)) return null
  if (value['kind'] === 'none') return { kind: 'none' }
  const token = value['token']
  if (value['kind'] === 'vault' && typeof token === 'string' && token.length > 0) {
    return { kind: 'vault', token }
  }
  return null
}

function parseProfile(value: unknown): StoredProfile | null {
  if (!isRecord(value)) return null
  const { id, label, host, username, port, createdAt, updatedAt } = value
  const secret = parseSecret(value['secret'])
  if (typeof id !== 'string' || id.length === 0) return null
  if (typeof label !== 'string') return null
  if (typeof host !== 'string') return null
  if (typeof username !== 'string') return null
  if (typeof port !== 'number' || !Number.isInteger(port) || port <= 0 || port > 65535) return null
  if (typeof createdAt !== 'number' || typeof updatedAt !== 'number') return null
  if (secret === null) return null
  return { id, label, host, port, username, secret, createdAt, updatedAt }
}

/** Whitelist the shape: unknown fields (e.g. a stray plaintext password) are dropped. */
function parseProfileFile(value: unknown): ProfileFile | null {
  if (!isRecord(value)) return null
  if (value['version'] !== 1) return null
  const rawActive = value['activeProfileId']
  const activeProfileId = rawActive === undefined || rawActive === null ? null : typeof rawActive === 'string' ? rawActive : undefined
  if (activeProfileId === undefined) return null
  const rawProfiles = value['profiles']
  if (!Array.isArray(rawProfiles)) return null
  const profiles: StoredProfile[] = []
  const seen = new Set<string>()
  for (const item of rawProfiles) {
    const profile = parseProfile(item)
    if (profile === null) return null
    if (seen.has(profile.id)) return null
    seen.add(profile.id)
    profiles.push(profile)
  }
  const active = activeProfileId !== null && seen.has(activeProfileId) ? activeProfileId : null
  return { version: 1, activeProfileId: active, profiles }
}

function toView(profile: StoredProfile, activeProfileId: string | null): ProfileView {
  return {
    id: profile.id,
    label: profile.label,
    host: profile.host,
    port: profile.port,
    username: profile.username,
    hasSecret: profile.secret.kind === 'vault',
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
    active: activeProfileId !== null && activeProfileId === profile.id,
  }
}

export class ProfileStore {
  private readonly filePath: string
  private readonly vault: CredentialVault
  private readonly log: (message: string) => void
  private broken = false
  private brokenMessage: string | null = null

  constructor(options: ProfileStoreOptions = {}) {
    this.filePath = options.filePath ?? defaultProfileFilePath()
    this.vault = options.vault ?? new CredentialVault()
    this.log = options.log ?? (() => undefined)
  }

  /** Redacted views of every profile, in file order. */
  list(): ProfileView[] {
    const file = this.loadFile()
    return file.profiles.map((profile) => toView(profile, file.activeProfileId))
  }

  /** The active profile as a redacted view, or null when nothing is active. */
  getActive(): ProfileView | null {
    const file = this.loadFile()
    if (file.activeProfileId === null) return null
    const profile = file.profiles.find((p) => p.id === file.activeProfileId)
    return profile === undefined ? null : toView(profile, file.activeProfileId)
  }

  /**
   * Point the store at `id`, or at nothing when `id` is null.
   * An unknown id is a no-op: nothing is written and null is returned.
   */
  setActive(id: string | null): ProfileView | null {
    const file = this.requireWritable()
    if (id === null) {
      file.activeProfileId = null
      this.writeFile(file)
      return null
    }
    const profile = file.profiles.find((p) => p.id === id)
    if (profile === undefined) return null
    file.activeProfileId = id
    this.writeFile(file)
    return toView(profile, id)
  }

  /**
   * Create (no id) or update (existing id) one profile.
   * A supplied id that does not exist is an error: callers must not silently
   * create a profile they believe they are updating.
   */
  upsert(input: ProfileUpsertInput): ProfileView {
    const file = this.requireWritable()
    const now = Date.now()
    let profile: StoredProfile | undefined
    if (input.id !== undefined) {
      profile = file.profiles.find((p) => p.id === input.id)
      if (profile === undefined) throw new Error('unknown profile id "' + input.id + '"')
    }
    if (profile !== undefined) {
      profile.label = input.label
      profile.host = input.host
      profile.port = input.port
      profile.username = input.username
      profile.updatedAt = now
      if (input.password === null) profile.secret = { kind: 'none' }
      else if (typeof input.password === 'string') profile.secret = { kind: 'vault', token: this.vault.encrypt(input.password) }
    } else {
      const secret: StoredProfileSecret = typeof input.password === 'string' ? { kind: 'vault', token: this.vault.encrypt(input.password) } : { kind: 'none' }
      profile = {
        id: randomUUID(),
        label: input.label,
        host: input.host,
        port: input.port,
        username: input.username,
        secret,
        createdAt: now,
        updatedAt: now,
      }
      file.profiles.push(profile)
    }
    this.writeFile(file)
    return toView(profile, file.activeProfileId)
  }

  /** Delete one profile. Removing the active profile also clears the pointer. */
  remove(id: string): boolean {
    const file = this.requireWritable()
    const index = file.profiles.findIndex((p) => p.id === id)
    if (index < 0) return false
    file.profiles.splice(index, 1)
    if (file.activeProfileId === id) file.activeProfileId = null
    this.writeFile(file)
    return true
  }

  /**
   * Decrypt the stored password for the connection layer ONLY. Returns
   * undefined when there is no profile, no stored secret, or the token cannot
   * be decrypted. Never throws.
   */
  resolvePassword(id: string): string | undefined {
    try {
      const file = this.loadFile()
      const profile = file.profiles.find((p) => p.id === id)
      if (profile === undefined || profile.secret.kind !== 'vault') return undefined
      const plain = this.vault.decrypt(profile.secret.token)
      return plain === null ? undefined : plain
    } catch {
      return undefined
    }
  }

  /** Whether the profiles file could be parsed, and why not when it could not. */
  integrity(): ProfileIntegrity {
    this.loadFile()
    return { broken: this.broken, message: this.brokenMessage }
  }

  /**
   * Tolerant read: a missing file is simply empty, a corrupt one yields an
   * empty structure plus the broken flag. The file is never rewritten here.
   */
  private loadFile(): ProfileFile {
    const wasBroken = this.broken
    this.broken = false
    this.brokenMessage = null
    const file = this.parseFile()
    if (this.broken && !wasBroken) this.log('profiles file unusable: ' + (this.brokenMessage ?? 'unknown reason'))
    return file
  }

  private parseFile(): ProfileFile {
    if (!existsSync(this.filePath)) return emptyProfileFile()
    let raw: string
    try {
      raw = readFileSync(this.filePath, 'utf8')
    } catch {
      this.markBroken('file could not be read')
      return emptyProfileFile()
    }
    if (raw.trim().length === 0) return emptyProfileFile()
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      this.markBroken('file is not valid JSON')
      return emptyProfileFile()
    }
    const file = parseProfileFile(parsed)
    if (file === null) {
      this.markBroken('file has an unexpected structure')
      return emptyProfileFile()
    }
    return file
  }

  private markBroken(message: string): void {
    this.broken = true
    this.brokenMessage = message
  }

  /** Writes refuse to run while the on-disk file is corrupt. */
  private requireWritable(): ProfileFile {
    const file = this.loadFile()
    if (this.broken) {
      throw new Error('profiles file is unreadable (' + (this.brokenMessage ?? 'corrupted') + '); refusing to overwrite it')
    }
    return file
  }

  /** Atomic write: full content to `<file>.tmp`, then rename over the target. */
  private writeFile(file: ProfileFile): void {
    mkdirSync(dirname(this.filePath), { recursive: true })
    const temp = this.filePath + '.tmp'
    try {
      writeFileSync(temp, JSON.stringify(file, null, 2), { mode: 0o600 })
      renameSync(temp, this.filePath)
    } catch (error) {
      try {
        if (existsSync(temp)) unlinkSync(temp)
      } catch {
        /* ignore */
      }
      throw error
    }
    // Best effort only: harmless (and a no-op) on Windows.
    try {
      chmodSync(this.filePath, 0o600)
    } catch {
      /* ignore */
    }
  }
}
