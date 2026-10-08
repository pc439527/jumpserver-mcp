/**
 * CredentialVault — at-rest encryption for per-profile JumpServer passwords.
 *
 * THREAT MODEL
 *   What this protects: credentials that would otherwise sit as plain text on
 *   this machine's disk. A password is stored as an AES-256-GCM token next to a
 *   locally generated key file, which removes the everyday accidents — a
 *   profiles file copied into a chat, accidentally committed to a repository,
 *   or opened by someone idly browsing the home directory.
 *   What this does NOT protect against: a local administrator, or any attacker
 *   who already runs code as this OS user. They can read both the token and the
 *   key file. No password prompt stands in the way, by design: an MCP stdio
 *   server has nowhere to ask for one, and a master password would only move
 *   the secret somewhere else on the same disk.
 *
 * Zero dependencies — node:crypto / node:fs / node:path / node:os only.
 * No method ever puts plaintext or ciphertext into a log line, an error message
 * or a return value: failures are reported by category only.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

const ALGORITHM = 'aes-256-gcm'
const KEY_BYTES = 32
const IV_BYTES = 12
/** Token version prefix — a future format bump must not be read as v1. */
const TOKEN_VERSION = 'v1'

const KEY_MISSING = 'vault key is missing or corrupted'

export interface CredentialVaultOptions {
  /** Where the raw key lives. Defaults to ~/.workbuddy/jumpserver-mcp/vault.key */
  keyPath?: string
}

/** Default key location, next to the profiles file this vault serves. */
export function defaultVaultKeyPath(): string {
  return join(homedir(), '.workbuddy', 'jumpserver-mcp', 'vault.key')
}

export class CredentialVault {
  private readonly keyPath: string
  /** Cached key, or null once we know the key file is unusable. */
  private key: Buffer | null = null
  private loaded = false

  constructor(options: CredentialVaultOptions = {}) {
    this.keyPath = options.keyPath ?? defaultVaultKeyPath()
  }

  /**
   * True when a usable key can be obtained. On first call this may create the
   * key file, exactly like the first encrypt() would.
   */
  isAvailable(): boolean {
    return this.loadKey() !== null
  }

  /**
   * Encrypt one secret. Returns `v1:<ivB64>:<tagB64>:<cipherB64>`.
   * Throws a category-only error when no usable key exists — never stores the
   * plaintext as a fallback.
   */
  encrypt(plain: string): string {
    const key = this.loadKey()
    if (key === null) throw new Error(KEY_MISSING)
    const iv = randomBytes(IV_BYTES)
    const cipher = createCipheriv(ALGORITHM, key, iv)
    const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return [
      TOKEN_VERSION,
      iv.toString('base64'),
      tag.toString('base64'),
      ciphertext.toString('base64'),
    ].join(':')
  }

  /**
   * Decrypt a token produced by encrypt(). Returns null for ANY failure — bad
   * format, missing/corrupted key, failed authentication — and never throws.
   */
  decrypt(token: string): string | null {
    try {
      const key = this.loadKey()
      if (key === null) return null
      const parts = token.split(':')
      if (parts.length !== 4) return null
      const [version, ivB64, tagB64, cipherB64] = parts
      if (version !== TOKEN_VERSION) return null
      if (ivB64 === undefined || tagB64 === undefined || cipherB64 === undefined) return null
      const iv = Buffer.from(ivB64, 'base64')
      const tag = Buffer.from(tagB64, 'base64')
      const ciphertext = Buffer.from(cipherB64, 'base64')
      if (iv.length !== IV_BYTES) return null
      const decipher = createDecipheriv(ALGORITHM, key, iv)
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
    } catch {
      return null
    }
  }

  /**
   * Read the key, generating it on first use. A key file that exists with the
   * wrong length is treated as CORRUPTED: it is never overwritten (that would
   * destroy any chance of recovery) — encrypt() then fails and decrypt() yields
   * null until the operator removes it deliberately.
   */
  private loadKey(): Buffer | null {
    if (this.loaded) return this.key
    this.loaded = true
    if (existsSync(this.keyPath)) {
      try {
        const raw = readFileSync(this.keyPath)
        this.key = raw.length === KEY_BYTES ? raw : null
      } catch {
        this.key = null
      }
      return this.key
    }
    try {
      mkdirSync(dirname(this.keyPath), { recursive: true })
      const fresh = randomBytes(KEY_BYTES)
      writeFileSync(this.keyPath, fresh, { mode: 0o600 })
      // Best effort only: on Windows chmod is a no-op and must not block setup.
      try {
        chmodSync(this.keyPath, 0o600)
      } catch {
        /* ignore */
      }
      this.key = fresh
    } catch {
      this.key = null
    }
    return this.key
  }
}
