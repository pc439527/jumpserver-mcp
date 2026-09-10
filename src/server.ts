#!/usr/bin/env node
/**
 * jumpserver-mcp — MCP stdio server exposing the dsh-jumpserver core
 * (state-machine SSH/PTY sessions through the JumpServer KoKo bastion) to
 * WorkBuddy as 10 model-facing tools.
 *
 * Ported from dsh-jumpserver src/tools/definitions.ts; the DSH defineTool API
 * is replaced by @modelcontextprotocol/sdk registerTool.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import type { JumpServerConfig } from './config/types.js'
import { AbortRequestedError, JumpServerError } from './jumpserver/errors.js'
import type { BatchCommandRequest, TargetBatchResult } from './jumpserver/session-manager.js'
import { gateCommand, gateCommandForNavigation, gateCommandsForNavigation, type GateServices } from './security/permission-gate.js'
import { JUMPSERVER_NOT_ARMED, NOT_ARMED_MESSAGE, type SessionGrant } from './security/grant.js'
import { redactCommandSecrets } from './security/command-redaction.js'
import { createRuntime, type Runtime } from './runtime/runtime.js'
import { auditViewerUrl, consoleTokenInfo, readAuditEntries, rotateConsoleAccessToken, stripInternalMarkers } from './runtime/audit-viewer.js'
import { registerOpsTools } from './runtime/tools-ops.js'
import { toolText, toolTextRaw } from './runtime/tool-host.js'
import { projectSessionScope } from './runtime/session-scope.js'
import { formatAuditTime } from './runtime/time.js'
import { requireTargetAllowed } from './security/target-scope.js'
import type { ToolRunContext } from './runtime/context.js'
import {
  assetsToValue,
  bundleFor,
  execOutcomeToValue,
  guardText,
  guardValue,
  renderAssetsResult,
  renderBatchResult,
  renderResult,
  sessionIdOf,
  statusToValue,
  type ResultValue,
} from './runtime/tools-common.js'
import { PLUGIN_VERSION, runtimeVersion } from './version.js'

function thisJumpError(error: unknown): { code: string; message: string } {
  if (error instanceof JumpServerError) return { code: error.code, message: error.message }
  return { code: 'FAILED', message: error instanceof Error ? error.message : String(error) }
}

function notArmed(): ResultValue {
  return { ok: false, code: JUMPSERVER_NOT_ARMED, message: NOT_ARMED_MESSAGE }
}

/** Returns the not-armed value when grants are required and locked, else null. */
function requireGrant(grants: SessionGrant, runtime: Runtime, exec: ToolRunContext): ResultValue | null {
  if (runtime.getConfig().requireArm !== true) return null
  return grants.isGranted(sessionIdOf(exec)) ? null : notArmed()
}

// Console handover + text projection live in runtime/tool-host.ts so the ops
// tool modules (inspect / topology / jobs) share the exact same behaviour.
const text = toolText
const textRaw = toolTextRaw

const CONFIRM_DESCRIPTION =
  'Set to true ONLY after the user explicitly approved the listed command(s). ' +
  'The first attempt of an approval-required command returns COMMAND_APPROVAL_REQUIRED with the reason; show it to the user, and retry with confirm:true after they agree.'

async function main(): Promise<void> {
  const runtime = createRuntime()
  const { grants, registry, getConfig } = runtime

  const servicesFor = (bundle: { manager: import('./jumpserver/session-manager.js').SessionManager }): GateServices => ({
    getConfig: getConfig as () => JumpServerConfig,
    manager: bundle.manager,
  })

  const server = new McpServer({ name: 'jumpserver-mcp', version: PLUGIN_VERSION })

  const confirmShape = { confirm: z.boolean().optional().describe(CONFIRM_DESCRIPTION) }
  const timeoutShape = { timeout: z.number().optional().describe('Timeout in seconds for this command (default: configured command timeout, max 600)') }

  server.registerTool(
    'jumpserver_status',
    {
      description:
        'Query the current JumpServer connector state: whether a session exists, which bastion gateway it uses, which target asset is entered (verified via probe), and the current permission mode. Also returns the live ops-console URL and its token expiry. Never returns credentials. This tool is strictly READ-ONLY — to invalidate the console token use jumpserver_console_rotate_token.',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_status', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        // V0.4.2: surface the live console URL + token expiry so a user whose
        // console aged out can be handed a fresh link without a restart.
        const tokenInfo = consoleTokenInfo()
        return {
          ...statusToValue(bundle.manager.status()),
          ...runtimeVersion(),
          // V0.4.3: state the conversation-isolation mode so an operator can
          // tell process-per-conversation from a multiplexed host.
          // V0.4.5: derived from whether the TRANSPORT carried a sessionId.
          // V0.4.4 asked sessionIdOf(exec).length > 0, which is always true
          // (it falls back to JUMPSERVER_MCP_SESSION / ANONYMOUS_SESSION), so
          // every WorkBuddy stdio conversation claimed to be transport-scoped.
          sessionScope: projectSessionScope(exec, runtime.sessionScope),
          sessionId: sessionIdOf(exec),
          consoleUrl: auditViewerUrl(),
          consoleTokenTtlMinutes: tokenInfo.ttlMinutes,
          consoleTokenExpiresAt: tokenInfo.expiresAt,
          consoleTokenExpired: tokenInfo.expired,
        }
      }))
    },
  )

  // V0.4.3: rotation is a SIDE EFFECT, so it must not hide inside a tool that
  // advertises readOnlyHint:true. Separate tool, honest annotations.
  server.registerTool(
    'jumpserver_console_rotate_token',
    {
      description:
        'Invalidate the current ops-console access token and issue a fresh one, returning the new console URL. The previous link stops working immediately, so hand the new URL to the user. Use this when the console shows "令牌已过期" and you cannot restart the MCP process. Has a side effect (the old token is revoked) — not a read-only operation.',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_console_rotate_token', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const url = rotateConsoleAccessToken()
        const tokenInfo = consoleTokenInfo()
        if (url === null) {
          return {
            ok: false,
            code: 'CONSOLE_NOT_RUNNING',
            message: 'no ops console is running for this conversation (auditViewer.enabled=false or the listener failed to bind)',
          } as unknown as import('./runtime/tools-common.js').ResultValue
        }
        return {
          ok: true,
          consoleUrl: url,
          consoleTokenTtlMinutes: tokenInfo.ttlMinutes,
          consoleTokenExpiresAt: tokenInfo.expiresAt,
          message: 'console token rotated; the previous link no longer works — open the new URL via present_files.',
        } as unknown as import('./runtime/tools-common.js').ResultValue
      }))
    },
  )

  server.registerTool(
    'jumpserver_connect',
    {
      description:
        'Establish the persistent JumpServer SSH session and wait until the JumpServer menu is detected. If a session already exists, this does NOT create a second one; it simply returns the current state. One session per WorkBuddy conversation (one MCP server process).',
      inputSchema: {},
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_connect', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        // V0.4.2: a session that drifted into a denied asset must not be resumed.
        requireTargetAllowed(runtime.getConfig(), bundle.manager.status().target)
        return statusToValue(await bundle.manager.connect(exec.signal))
      }))
    },
  )

  server.registerTool(
    'jumpserver_enter',
    {
      description:
        'Enter a target asset THROUGH the JumpServer menu by its IP/name. Requires the session to be at the JumpServer menu. Internally runs a target probe (hostname/whoami/pwd) and only reports the asset as entered after verification succeeds.',
      inputSchema: {
        target: z.string().describe('Target asset IP or name, e.g. 203.0.113.101'),
      },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_enter', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        // V0.4.2: scope check BEFORE navigation — a denied target must never
        // get an SSH/PTY session opened against it.
        requireTargetAllowed(runtime.getConfig(), args.target)
        const bundle = bundleFor(exec, registry)
        return statusToValue(await bundle.manager.enter(args.target, exec.signal))
      }))
    },
  )

  server.registerTool(
    'jumpserver_assets',
    {
      description:
        'List the assets (servers) your JumpServer account is authorized for, WITHOUT entering any of them: sends the KoKo menu command "p" (strictly display-only), parses the captured list locally, and optionally filters by substring (case-insensitive across name/ip/platform/node/comment) or by a configured system group (group="OA" OR-matches every OA keyword). Use this to discover targets before jumpserver_run/jumpserver_batch — NEVER guess IPs, and type no asset name back into the menu (KoKo auto-logs-in on a unique hit). Footer verification: parsedRows == reportedTotal is the only proof the whole list was captured. rawText is NOT included by default to keep context slim.',
      inputSchema: {
        filter: z.string().optional().describe('Optional substring filter, e.g. "OA" or "203.0.113" — matched against asset name, IP and comment (case-insensitive)'),
        group: z.string().optional().describe('Optional configured asset group name (exact, case-insensitive), e.g. "OA" or "ESB" — OR-matches the group keywords (assetGroups setting). Unknown groups error with INVALID_GROUP instead of returning "0 assets".'),
        refresh: z.boolean().optional().describe('Force a fresh "p" capture instead of reusing the cache (default false). Use after a failed/incomplete capture.'),
        includeRawText: z.boolean().optional().describe('Include the raw captured screen in rawText (default false, bounded) — for diagnostics only.'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_assets', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      const value = await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        const result = await bundle.manager.listAssets(
          typeof args.filter === 'string' ? args.filter : undefined,
          exec.signal,
          args.refresh === true,
          typeof args.group === 'string' ? args.group : undefined,
        )
        // V0.4.1: hand the listing to the console's 资产 tab (read-only mirror).
        runtime.assets.set({
          updatedAt: Date.now(),
          filter: typeof args.filter === 'string' && args.filter.length > 0 ? args.filter : null,
          group: typeof args.group === 'string' && args.group.length > 0 ? args.group : null,
          reportedTotal: result.reportedTotal,
          health: result.health,
          assets: result.assets,
        })
        return assetsToValue(result, { includeRawText: args.includeRawText === true })
      })
      return textRaw(renderAssetsResult(value))
    },
  )

  server.registerTool(
    'jumpserver_exec',
    {
      description:
        'Execute one SIMPLE command on the CURRENTLY entered target asset and return its stdout plus the real exit code (completion is detected with a unique marker, never by waiting a fixed time). Only works while the session is inside a verified asset shell. Send ONE simple read-only command (e.g. "free -m", "df -h", "tail -n 100 /var/log/app.log") — do NOT wrap several checks in for/if loops, $(...) substitutions or multi-statement one-liners, because READ_ONLY mode classifies every command statically and blocks complex or mutating shell structure. For several checks on one target use jumpserver_batch with one simple command per entry.',
      inputSchema: {
        command: z.string().describe('Shell command to execute on the remote asset'),
        ...timeoutShape,
        ...confirmShape,
      },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_exec', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        const gated = await gateCommand(servicesFor(bundle), exec, args.command)
        requireTargetAllowed(runtime.getConfig(), bundle.manager.status().target)
        const timeoutMs = args.timeout !== undefined ? Math.max(1, args.timeout) * 1000 : undefined
        const { status, outcome } = await bundle.manager.exec({
          command: args.command,
          timeoutMs,
          toolCallId: String(exec.callId),
          risk: gated.risk,
          classification: gated.classification,
          approvalRequired: gated.approvalRequired,
          approvalResult: gated.approvalRequired ? 'approved' : 'none',
          signal: exec.signal,
        })
        return execOutcomeToValue(status, outcome)
      }))
    },
  )

  server.registerTool(
    'jumpserver_run',
    {
      description:
        'Execute ONE SIMPLE command on a server reachable through the configured JumpServer. Automatically connects (or reuses the session), switches from the current asset when necessary, verifies the requested target, executes the command, and returns structured output. BATCHING CONTRACT: for MULTIPLE metrics on one target, do NOT call jumpserver_run repeatedly and do NOT wrap everything in for/if loops or long &&/; one-liners — call jumpserver_batch ONCE with one simple read-only command per commands[] entry instead. Use jumpserver_assets first when you do not know the exact target names/IPs.',
      inputSchema: {
        target: z.string().describe('Target asset IP or name, e.g. 203.0.113.101'),
        command: z.string().describe('Shell command to execute on the remote asset'),
        ...timeoutShape,
        ...confirmShape,
      },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_run', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        // V0.4.2: fail fast on out-of-scope targets before any classification work.
        requireTargetAllowed(runtime.getConfig(), args.target)
        const gated = await gateCommandForNavigation(servicesFor(bundle), exec, args.command)
        const timeoutMs = args.timeout !== undefined ? Math.max(1, args.timeout) * 1000 : undefined
        const result = await bundle.manager.run({
          target: args.target,
          command: args.command,
          timeoutMs,
          toolCallId: String(exec.callId),
          risk: gated.risk,
          classification: gated.classification,
          approvalRequired: gated.approvalRequired,
          approvalResult: gated.approvalRequired ? 'approved' : 'none',
          signal: exec.signal,
          beforeExec: gated.beforeExec,
        })
        const { target, hostname, status, outcome } = result
        return { ...execOutcomeToValue(status, outcome), target, hostname }
      }))
    },
  )

  server.registerTool(
    'jumpserver_batch',
    {
      description:
        'Run a batch of SIMPLE commands across one or more targets through JumpServer in a single call. Each task lists a target plus the commands to run on it; the connector enters a target ONCE, runs ALL of its commands, then leaves and moves to the next target (target affinity). COMMAND STYLE (important in READ_ONLY mode): put ONE simple read-only command per commands[] entry (e.g. "hostname", "uptime", "free -m", "df -h", "ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -20", "tail -n 300 /var/log/app.log"). Do NOT assemble shell programs (for/while loops, if branches, $(...) substitution, chained redirection) — each entry is classified independently and statically. Never bounce between targets — all commands of one target run before the next target is entered.',
      inputSchema: {
        tasks: z.array(z.object({
          target: z.string().describe('Target asset IP or name, e.g. 203.0.113.101'),
          commands: z.array(z.string()).describe('Simple shell commands to execute on this target (run sequentially, results returned per command)'),
          timeout: z.number().optional().describe('Per-command timeout in seconds for this task (default: configured command timeout, max 600)'),
        })).min(1).describe('One or more target tasks.'),
        ...confirmShape,
      },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_batch', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      const value = await guardValue(exec, async (): Promise<ResultValue> => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        const executed: TargetBatchResult[] = []
        const batchId = 'bat_' + Math.random().toString(36).slice(2, 8)
        for (const task of args.tasks) {
          if (exec.signal.aborted === true) throw new AbortRequestedError()
          const target = String(task.target ?? '')
          const commands = task.commands.map((c) => String(c ?? '')).filter((c: string) => c.trim().length > 0)
          if (target.length === 0) {
            executed.push({ target, hostname: null, error: { code: 'INVALID_BATCH', message: 'task target is missing' }, commands: [] })
            continue
          }
          if (commands.length === 0) {
            executed.push({ target, hostname: null, error: { code: 'INVALID_BATCH', message: 'task commands is empty' }, commands: [] })
            continue
          }
          try {
            requireTargetAllowed(runtime.getConfig(), target)
            const gated = await gateCommandsForNavigation(servicesFor(bundle), exec, commands)
            const timeoutMs = typeof task.timeout === 'number' && Number.isFinite(task.timeout) ? Math.max(1, task.timeout) * 1000 : undefined
            const commandRequests: BatchCommandRequest[] = gated.map((g, i) => {
              const request: BatchCommandRequest = {
                command: commands[i]!,
                timeoutMs,
                risk: g.risk,
                classification: g.classification,
                approvalRequired: g.approvalRequired,
                approvalResult: g.approvalRequired ? 'pending' : 'none',
                toolCallId: String(exec.callId),
                batchId,
                batchIndex: i,
              }
              if (g.beforeExec !== undefined) {
                const before = g.beforeExec
                request.beforeExec = async () => {
                  try {
                    await before()
                    request.approvalResult = 'approved'
                  } catch (error) {
                    request.approvalResult = 'denied'
                    throw error
                  }
                }
              }
              return request
            })
            executed.push(await bundle.manager.runTargetBatch({
              target,
              commands: commandRequests,
              signal: exec.signal,
              toolCallId: String(exec.callId),
              batchId,
            }))
          } catch (error) {
            if (error instanceof AbortRequestedError || (exec.signal as { aborted?: boolean }).aborted === true) throw error
            executed.push({ target, hostname: null, error: thisJumpError(error), commands: [] })
          }
        }
        return renderBatchResult(executed)
      })
      return text(value)
    },
  )

  server.registerTool(
    'jumpserver_leave',
    {
      description:
        'Leave the currently entered asset and return to the JumpServer menu. Sends exit at most once and only reports success after the JumpServer menu is detected again.',
      inputSchema: {},
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_leave', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        return statusToValue(await bundle.manager.leave(exec.signal))
      }))
    },
  )

  server.registerTool(
    'jumpserver_close',
    {
      description:
        "Close the JumpServer session: PTY, SSH channel/client, buffers and timers are released and the connector returns to the DISCONNECTED state.",
      inputSchema: {},
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_close', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return blocked
        const sessionId = sessionIdOf(exec)
        const bundle = bundleFor(exec, registry)
        grants.revoke(sessionId)
        await bundle.manager.close()
        return statusToValue(bundle.manager.status())
      }))
    },
  )

  server.registerTool(
    'jumpserver_snapshot',
    {
      description:
        'Read-only terminal mirror: return the recent PTY event stream (output chunks, state transitions, target changes) as bounded text, plus the current state. Use it to show the user what the terminal looks like right now (render it as a terminal view), to diagnose a stuck menu/state, or to poll incrementally with sinceSeq. Never includes credentials (input/output are redacted by the observer).',
      inputSchema: {
        sinceSeq: z.number().optional().describe('Return only events with seq > sinceSeq (incremental polling). Omit to return the full scrollback.'),
        maxChars: z.number().optional().describe('Cap the returned text length in characters (default 8000).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_snapshot', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return textRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = requireGrant(grants, runtime, exec)
        if (blocked !== null) return renderResult(blocked)
        const bundle = bundleFor(exec, registry)
        const status = bundle.manager.status()
        const events = (typeof args.sinceSeq === 'number'
          ? bundle.observer.snapshotSince(Math.max(0, Math.floor(args.sinceSeq)))
          : bundle.observer.snapshot()
        ).map(stripInternalMarkers)
        const maxChars = typeof args.maxChars === 'number' && args.maxChars > 200 ? Math.floor(args.maxChars) : 8000
        const lines: string[] = [
          'state=' + status.state + ' target=' + (status.target ?? 'none') + ' hostname=' + (status.hostname ?? '?') + ' permissionMode=' + status.permissionMode,
          'lastSeq=' + String(lastSeqOf(bundle)) + ' events=' + String(events.length),
        ]
        let size = 0
        for (const event of events) {
          let line: string
          switch (event.type) {
            case 'output':
              line = event.data
              break
            case 'input':
              line = '[input] ' + event.data
              break
            case 'state':
              line = '[state] ' + (event.prev ?? '?') + ' -> ' + event.state
              break
            case 'target':
              line = '[target] ' + event.target + ' (' + (event.hostname ?? '?') + ')'
              break
            case 'error':
              line = '[error] ' + event.message
              break
          }
          if (size + line.length > maxChars) {
            lines.push('... truncated (' + String(events.length) + ' events, showing ' + String(lines.length - 2) + ')')
            break
          }
          size += line.length
          lines.push(line)
        }
        return lines.join('\n')
      }))
    },
  )

  // In-chat audit trail — answers "what did the AI run?" without the web viewer.
  server.registerTool(
    'jumpserver_audit',
    {
      description:
        'Read the local audit trail of THIS connector in-chat: recent audited events (time, operation, target asset, redacted command, risk, result). Use it when the user asks what the AI ran through JumpServer, or to double-check executed commands after a task. Purely local file read: never touches the bastion, works even when no session exists.',
      inputSchema: {
        limit: z.number().int().min(1).max(200).optional().describe('How many recent entries to return (default 20, oldest first).'),
        filter: z.string().optional().describe('Substring filter, matched case-insensitively against each raw audit entry (e.g. an IP like 192.168.79.103 or a command fragment).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_audit', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return textRaw(await guardText(exec, async (): Promise<string> => {
        const entries = readAuditEntries(runtime.auditPath)
        const q = typeof args.filter === 'string' && args.filter.length > 0 ? args.filter.toLowerCase() : null
        const filtered = q !== null ? entries.filter((e) => JSON.stringify(e).toLowerCase().includes(q)) : entries
        const limit = typeof args.limit === 'number' ? Math.max(1, Math.floor(args.limit)) : 20
        const picked = filtered.slice(-limit)
        const tz = runtime.timeZone
        const lines = picked.map((e) => {
          // V0.4.0: storage is UTC; display uses the configured zone.
          const ts = formatAuditTime(e['timestamp'], tz)
          const cmd = String(e['redactedCommand'] ?? e['command'] ?? '-')
          const callId = e['toolCallId'] !== undefined ? String(e['toolCallId']) : '-'
          const batchId = e['batchId'] !== undefined ? String(e['batchId']) : '-'
          return [ts, String(e['operation'] ?? '-'), String(e['target'] ?? e['hostname'] ?? '-'), '[' + String(e['risk'] ?? '?') + ']', String(e['result'] ?? '?'), 'call=' + callId, 'batch=' + batchId, cmd].join(' | ')
        })
        lines.unshift('entries=' + String(filtered.length) + (q !== null ? ' (filtered)' : '') + ' showing=' + String(picked.length) + ' tz=' + tz)
        lines.unshift('audit=' + runtime.auditPath)
        const viewer = auditViewerUrl()
        if (viewer !== null) lines.unshift('viewer=' + viewer)
        return lines.join('\n')
      }))
    },
  )

  // Optional arm/disarm tools (requireArm: true keeps the DSH session-grant UX).
  if (runtime.getConfig().requireArm === true) {
    server.registerTool(
      'jumpserver_arm',
      {
        description: 'Authorize (arm) the JumpServer tools for this session for 30 minutes. Requires requireArm:true in config.',
        inputSchema: {},
      },
      async (_args, extra) => {
        const exec: ToolRunContext = { name: 'jumpserver_arm', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
        grants.arm(sessionIdOf(exec), 'persistent', 30 * 60 * 1000)
        return textRaw('JumpServer tools armed for 30 minutes.')
      },
    )
    server.registerTool(
      'jumpserver_disarm',
      {
        description: 'Revoke the JumpServer authorization and close the session.',
        inputSchema: {},
      },
      async (_args, extra) => {
        const exec: ToolRunContext = { name: 'jumpserver_disarm', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
        const sessionId = sessionIdOf(exec)
        grants.revoke(sessionId)
        const bundle = registry.get(sessionId)
        if (bundle !== undefined) await bundle.manager.close().catch(() => undefined)
        return textRaw('JumpServer tools disarmed.')
      },
    )
  }

  // V0.4.0: the investigation layer (inspect / topology / interrupt / jobs).
  registerOpsTools(server, runtime)

  process.on('SIGINT', () => {
    runtime.dispose()
    process.exit(0)
  })
  process.on('SIGTERM', () => {
    runtime.dispose()
    process.exit(0)
  })

  await server.connect(new StdioServerTransport())
  console.error('[jumpserver-mcp] ready: config=' + runtime.configPath + ' audit=' + runtime.auditPath + ' permissionMode=' + runtime.getConfig().permissionMode)
}

function lastSeqOf(bundle: { observer: { snapshot(): Array<{ seq: number }> } }): number {
  const events = bundle.observer.snapshot()
  return events.length > 0 ? events[events.length - 1]!.seq : 0
}

main().catch((error) => {
  console.error('[jumpserver-mcp] fatal: ' + (error instanceof Error ? error.stack ?? error.message : String(error)))
  process.exit(1)
})
