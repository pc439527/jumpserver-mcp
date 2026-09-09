import { Client, type ClientChannel } from 'ssh2'
import { JumpServerError } from './errors.js'

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
}

const AUTH_FAILED_PATTERN = /authentication|permission denied|password.*incorrect|incorrect.*password|keyboard-interactive/i

/**
 * Live ssh2 adapter: one SSH connection with one interactive PTY shell.
 * The entire JumpServer session (menu -> asset -> commands) reuses this
 * single channel; nothing reconnects per command.
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
        algorithms: { serverHostKey: ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'] },
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
