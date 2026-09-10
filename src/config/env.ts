/**
 * V0.5.0 — WorkBuddy connector form → environment → runtime.
 *
 * The connector's token-schema.json collects the connection four-tuple into
 * WorkBuddy's local credential store and injects it as environment variables
 * into this stdio MCP process, so a new user never has to locate and edit
 * config.json. These keys are the whole connection contract; every policy
 * setting (permissionMode, allowedTargets, runbooks, auditViewer …) stays in
 * config.json.
 *
 * Resolution order for every connection field is:
 *
 *     ENV  >  config.json  >  built-in default
 *
 * The environment layer is additive: an existing deployment that keeps its
 * values in config.json and sets no JUMPSERVER_* variable behaves exactly as
 * it did before.
 */

/** Connector-injected connection keys. One source of truth for schema + runtime + docs. */
export const ENV_KEYS = {
  host: 'JUMPSERVER_HOST',
  port: 'JUMPSERVER_PORT',
  username: 'JUMPSERVER_USERNAME',
  password: 'JUMPSERVER_PASSWORD',
} as const

/** Default bastion SSH port (JumpServer / KoKo listens on 2222 by default). */
export const DEFAULT_JUMPERSERVER_PORT = 2222

/** MCP-local state pointers (not part of the connector form). */
export const LIFECYCLE_ENV_KEYS = {
  configPath: 'JUMPSERVER_MCP_CONFIG',
  sessionScope: 'JUMPSERVER_MCP_SESSION',
} as const

/**
 * Where a resolved connection value came from. Surfaced in the console's
 * 设置 tab so an operator can see whether the running process is fed by the
 * WorkBuddy form or by a hand-edited config.json.
 */
export type ConnectionSource = 'env' | 'config' | 'default'

export interface EnvConnection {
  host?: string
  port?: number
  username?: string
  password?: string
}

function blankToUndefined(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

/**
 * Read the connector-injected connection values. A blank string counts as
 * "not set" so an empty form field never shadows a valid config.json value.
 *
 * The password is NOT trimmed — leading/trailing whitespace can be part of a
 * real credential, and silently mangling it would produce a confusing auth
 * failure instead of an obvious one.
 */
export function readEnvConnection(env: NodeJS.ProcessEnv = process.env): EnvConnection {
  const out: EnvConnection = {}

  const host = blankToUndefined(env[ENV_KEYS.host])
  if (host !== undefined) out.host = host

  const username = blankToUndefined(env[ENV_KEYS.username])
  if (username !== undefined) out.username = username

  const password = env[ENV_KEYS.password]
  if (password !== undefined && password.length > 0) out.password = password

  const rawPort = blankToUndefined(env[ENV_KEYS.port])
  if (rawPort !== undefined) {
    const port = Number(rawPort)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(
        ENV_KEYS.port + ' must be an integer between 1 and 65535, got "' + rawPort + '"',
      )
    }
    out.port = port
  }

  return out
}

/** One resolved connection field, ready for display. */
export interface ConnectionField {
  value: string | undefined
  source: ConnectionSource
}

/**
 * Read-only description of where the live connection settings come from.
 * The password field carries its source but NEVER its value.
 */
export interface ConnectionView {
  host: ConnectionField
  port: ConnectionField
  username: ConnectionField
  password: { source: ConnectionSource; present: boolean; via?: string }
  configPath: string
  configPresent: boolean
  /** True when a host is available from ENV or config.json. */
  complete: boolean
}

/** Which layer supplied a value, given the raw inputs of each layer. */
export function sourceOf(configValue: unknown, envValue: unknown): ConnectionSource {
  if (envValue !== undefined && envValue !== null && String(envValue).length > 0) return 'env'
  if (configValue !== undefined && configValue !== null && String(configValue).length > 0) return 'config'
  return 'default'
}
