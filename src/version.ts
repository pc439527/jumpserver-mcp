/**
 * jumpserver-mcp runtime identity.
 *
 * V0.4.0: `package.json` is the SINGLE source of the version string. Runtime,
 * README, console footer and `jumpserver_status` all read it from there, so
 * npm version and MCP runtime can no longer drift apart.
 *
 * protocolVersion is MCP-local: bump when the tool result shapes change
 * incompatibly (the DSH browser bridge does not exist here).
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

function readPackageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url))
    // lib/version.js -> <root>/package.json (works in-repo and when installed)
    const raw = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')) as { version?: unknown }
    return typeof raw.version === 'string' && raw.version.length > 0 ? raw.version : '0.0.0'
  } catch {
    return '0.0.0'
  }
}

export const PLUGIN_VERSION = readPackageVersion()

export const PROTOCOL_VERSION = 1

export function hostBuild(): string {
  return 'mcp-stdio'
}

export interface RuntimeVersion {
  pluginVersion: string
  hostBuild: string
  protocolVersion: number
}

export function runtimeVersion(): RuntimeVersion {
  return { pluginVersion: PLUGIN_VERSION, hostBuild: hostBuild(), protocolVersion: PROTOCOL_VERSION }
}
