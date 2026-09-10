import { Client, type ClientChannel } from 'ssh2'
import { JumpServerError } from './errors.js'
import { createHostKeyGuard, describeHostKeyRefusal, type HostKeyDecision } from './host-key.js'

/** Testable wire seam: everything the session core needs from the transport. */
export interface Wire {
  write(text: string): void
  onData(cb: (chunk: string) => void): void
  onError(cb: (err: Error) => void): void
  onClose(cb: () => void): void
  close(): void
}

export interface WireConnectParams {
  host: string
  port: number
  username: string
  password: string
  connectTimeoutMs: number
  /** V0.5.0: operator-pinned SHA256/MD5 host-key fingerprint (optional). */
  hostFingerprint?: string
  /** V0.5.0: known_hosts store path — enables TOFU when no fingerprint is pinned. */
  knownHostsPath?: string
  /** V0.5.0: notified for every host-key decision (audit / diagnostics). */
  onHostKey?: (decision: HostKeyDecision) => void
}

const AUTH_FAILED_PATTERN = /authentication|permission denied|password.*incorrect|incorrect.*password|keyboard-interactive/i

/**
 * Live ssh2 adapter: one SSH connection with one interactive PTY shell.
 * The entire JumpServer session (menu -> asset -> commands) reuses this
 * single channel; nothing reconnects per command.
 *
 * V0.5.0: the handshake now verifies the bastion's host key before the
 * password is transmitted (see host-key.ts).
 */
export class SshPtyWire implements Wire {
  private client?: Client
  private stream?: ClientChannel
  private dataCbs = new Set<(chunk: string) => void>()
  private errorCbs = new Set<(err: Error) => void>()
  private closeCbs = new Set<() => void>()
  private settled = false

  private constructor() {}

  static connect(params: WireConnectParams): Promise<SshPtyWire> {
    return new Promise<SshPtyWire>((resolve, reject) => {
      const client = new Client()
      const wire = new SshPtyWire()
      wire.client = client

      // V0.5.0: built before `fail` so a refused key can be reported with its
      // actual fingerprint instead of ssh2's generic verification error.
      const guard = createHostKeyGuard({
        host: params.host,
        port: params.port,
        fingerprint: params.hostFingerprint,
        storePath: params.knownHostsPath,
        onDecision: params.onHostKey,
      })

      let timer: NodeJS.Timeout | undefined = setTimeout(() => {
        client.destroy()
        if (!wire.settled) {
          wire.settled = true
          reject(new JumpServerError('CONNECTION_TIMEOUT', 'SSH connect timed out'))
        }
      }, params.connectTimeoutMs)

      const fail = (err: Error): void => {
        if (wire.settled) {
          wire.fireError(err)
          return
        }
        wire.settled = true
        clearTimeout(timer)

        // A refused host key must never be reported as "wrong password" — the
        // two call for completely different operator responses.
        const decision = guard.last()
        if (decision !== undefined && !decision.accept) {
          reject(new JumpServerError(
            'HOST_KEY_MISMATCH',
            'JumpServer host key verification failed',
            describeHostKeyRefusal(decision),
          ))
          return
        }

        const code = AUTH_FAILED_PATTERN.test(err.message)
          ? 'AUTH_FAILED'
          : 'CONNECTION_LOST'
        reject(new JumpServerError(code, code === 'AUTH_FAILED' ? 'JumpServer authentication failed' : 'SSH connection failed', err.message))
      }

      client.on('error', fail)
      client.on('close', () => {
        wire.fireClose()
      })
      client.on('ready', () => {
        client.shell({ term: 'xterm', cols: 160, rows: 50 }, (err, stream) => {
          if (err !== undefined) {
            fail(new Error(err.message))
            return
          }
          if (wire.settled) {
            stream.end()
            return
          }
          wire.settled = true
          clearTimeout(timer)
          wire.stream = stream
          stream.on('data', (buf: Buffer) => {
            const text = buf.toString('utf8')
            for (const cb of wire.dataCbs) cb(text)
          })
          stream.on('error', (e: Error) => wire.fireError(e))
          stream.on('close', () => wire.fireClose())
          resolve(wire)
        })
      })
      client.connect({
        host: params.host,
        port: params.port,
        username: params.username,
        password: params.password,
        readyTimeout: params.connectTimeoutMs,
        keepaliveInterval: 10000,
        keepaliveCountMax: 3,
        hostVerifier: guard.verifier,
        // V0.5.0: the previous `algorithms.serverHostKey` override listed RSA
        // variants only, so any bastion offering just an ed25519 or ecdsa host
        // key failed to negotiate. kex / cipher / MAC were already at library
        // defaults; dropping this override restores the full modern set on all
        // four axes instead of pinning one of them to a subset.
      })
    })
  }

  write(text: string): void {
    this.stream?.write(text)
  }

  onData(cb: (chunk: string) => void): void {
    this.dataCbs.add(cb)
  }

  onError(cb: (err: Error) => void): void {
    this.errorCbs.add(cb)
  }

  onClose(cb: () => void): void {
    this.closeCbs.add(cb)
  }

  close(): void {
    try {
      this.stream?.end()
    } catch {
      /* already closed */
    }
    try {
      this.client?.end()
    } catch {
      /* already closed */
    }
    this.fireClose()
  }

  private fireError(err: Error): void {
    for (const cb of [...this.errorCbs]) cb(err)
  }

  private fireClose(): void {
    for (const cb of [...this.closeCbs]) cb()
  }
}

export { JumpServerError }
