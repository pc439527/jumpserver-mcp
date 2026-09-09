/**
 * jumpserver-mcp runtime identity (mirrors dsh-jumpserver src/version.ts).
 * protocolVersion is MCP-local: bump when the tool result shapes change
 * incompatibly (the DSH browser bridge does not exist here).
 */
export const PLUGIN_VERSION = '0.3.1'

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
