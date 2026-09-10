/**
 * Shared tool plumbing for the MCP server (V0.4.0).
 *
 * server.ts and the ops tool modules (inspect / topology / jobs / interrupt)
 * all need the same four things: the console hint handover, the arm/grant
 * check, the per-conversation session bundle and the gate services. One
 * implementation, so no tool can drift into its own copy.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { JumpServerConfig } from '../config/types.js'
import type { SessionManager } from '../jumpserver/session-manager.js'
import type { SessionBundle, SessionRegistry } from '../jumpserver/session-registry.js'
import { JUMPSERVER_NOT_ARMED, NOT_ARMED_MESSAGE, type SessionGrant } from '../security/grant.js'
import type { GateServices } from '../security/permission-gate.js'
import { consoleHintForModel } from './audit-viewer.js'
import { bundleFor as bundleForId, renderResult, sessionIdOf, type ResultValue } from './tools-common.js'
import type { ToolRunContext } from './context.js'
import type { Runtime } from './runtime.js'

/**
 * The console can only be raised by the HOST app. This hands its URL to the
 * model exactly once per process (= once per conversation), instructing it to
 * open the URL via present_files -> WorkBuddy built-in preview panel.
 * Never use a shell-open here: that lands in the OS default browser.
 */
let toolCallCount = 0

/** First response hands over the URL; every 20th repeats it so it cannot be missed. */
export function withConsoleHint(body: string): string {
  toolCallCount += 1
  if (toolCallCount !== 1 && toolCallCount % 20 !== 0) return body
  const hint = consoleHintForModel()
  return hint === null ? body : hint + '\n' + body
}

export function toolText(value: ResultValue): { content: Array<{ type: 'text'; text: string }> } {
  return { content: [{ type: 'text', text: withConsoleHint(renderResult(value)) }] }
}

export function toolTextRaw(value: string): { content: Array<{ type: 'text'; text: string }> } {
  return { content: [{ type: 'text', text: withConsoleHint(value) }] }
}

export interface ToolHost {
  runtime: Runtime
  registry: SessionRegistry
  grants: SessionGrant
  getConfig: () => JumpServerConfig
  bundleFor: (exec: ToolRunContext) => SessionBundle
  servicesFor: (bundle: { manager: SessionManager }) => GateServices
  /** Returns a not-armed value when grants are required and locked, else null. */
  requireGrant: (exec: ToolRunContext) => ResultValue | null
  sessionIdOf: (exec: ToolRunContext) => string
}

export function createToolHost(runtime: Runtime): ToolHost {
  const { grants, registry, getConfig } = runtime
  return {
    runtime,
    registry,
    grants,
    getConfig: getConfig as () => JumpServerConfig,
    bundleFor: (exec) => bundleForId(exec, registry),
    servicesFor: (bundle) => ({
      getConfig: getConfig as () => JumpServerConfig,
      manager: bundle.manager,
    }),
    requireGrant: (exec) => {
      if (runtime.getConfig().requireArm !== true) return null
      return grants.isGranted(sessionIdOf(exec)) ? null : { ok: false, code: JUMPSERVER_NOT_ARMED, message: NOT_ARMED_MESSAGE }
    },
    sessionIdOf,
  }
}

/** Convenience: a grouped registration helper so server.ts stays readable. */
export type ToolRegistrar = (server: McpServer, host: ToolHost) => void
