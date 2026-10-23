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
import { readBuildInfo } from './build-info.js'

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
  /**
   * V0.7.2 (E-2): the build fingerprint. `pluginVersion` alone cannot answer
   * "is the running build the one I just made?" — the version moves only when
   * someone remembers to bump it, and `lib/` (a gitignore artifact) can be
   * older than the commit that produced it. The commit hash can.
   */
  buildCommit: string
  buildCommitShort: string
  buildAt: string
  buildDirty: boolean
  buildFeatures: string[]
  buildFeatureMask: number
}

/**
 * V0.7.2 (E-2): the identity of the code that is actually running.
 *
 * The fingerprint is read from `lib/build-info.json` — the file written next
 * to the compiled code by `scripts/write-build-info.mjs`. A build made before
 * this feature existed has no such file; that is reported as
 * `buildCommit: 'unknown'` rather than an error, because a missing
 * fingerprint must never stop the connector from serving.
 */
export function runtimeVersion(): RuntimeVersion {
  const build = readBuildInfo()
  return {
    pluginVersion: PLUGIN_VERSION,
    hostBuild: hostBuild(),
    protocolVersion: PROTOCOL_VERSION,
    buildCommit: build.commit,
    buildCommitShort: build.commitShort,
    buildAt: build.builtAt,
    buildDirty: build.dirty,
    buildFeatures: build.features,
    buildFeatureMask: build.featureMask,
  }
}
