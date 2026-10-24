#!/usr/bin/env node
/**
 * jumpserver-mcp — MCP stdio server exposing the dsh-jumpserver core
 * (state-machine SSH/PTY sessions through the JumpServer KoKo bastion) to
 * WorkBuddy.
 *
 * Ported from dsh-jumpserver src/tools/definitions.ts; the DSH defineTool API
 * is replaced by @modelcontextprotocol/sdk registerTool.
 *
 * V0.5.2 notes on the tool table itself:
 *
 *  - EVERY tool declares `annotations`. The connector has always had a strict
 *    internal classifier + permission gate, but that judgement was invisible
 *    to the host, which could only see "none of these tools claims to be
 *    read-only" and therefore had to prompt for every call. The annotations
 *    below publish the same judgement outward.
 *    `tests/runtime/tool-annotations.test.mjs` freezes them, the way the
 *    classifier corpus freezes risk levels.
 *
 *  - Descriptions carry ONE sentence of what/when plus the hard constraints.
 *    The long-form usage guidance lives in connector/skills/jumpserver/SKILL.md,
 *    which is loaded lazily — the tool table is injected into EVERY
 *    conversation, including ones that never touch JumpServer.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { dirname, join } from 'node:path'
import type { ConnectionSource } from './config/env.js'
import type { JumpServerConfig } from './config/types.js'
import { AbortRequestedError, JumpServerError } from './jumpserver/errors.js'
import type { BatchCommandRequest, TargetBatchResult } from './jumpserver/session-manager.js'
import { gateCommand, gateCommandForNavigation, gateCommandsForNavigation, judgeAutoAllowNote, type GateServices } from './security/permission-gate.js'
import { JUMPSERVER_NOT_ARMED, NOT_ARMED_MESSAGE, type SessionGrant } from './security/grant.js'
import { redactCommandSecrets } from './security/command-redaction.js'
import { createRuntime, type Runtime } from './runtime/runtime.js'
import { renderDoctor, runDoctor, wantsDoctor } from './runtime/doctor.js'
import { auditViewerUrl, consoleOwnership, consoleTokenInfo, readAuditEntries, rotateConsoleAccessToken, stripInternalMarkers } from './runtime/audit-viewer.js'
import { applyGuardrail } from './security/guardrail.js'
import { registerOpsTools } from './runtime/tools-ops.js'
// V0.6.1 (B-4): the tool-surface self-check.
import { ALWAYS_TOOL_NAMES, missingAlwaysToolNames, registeredToolCount, trackToolRegistrations } from './runtime/tool-names.js'
// V0.6.1 (B-1): batch tasks also accept the string / single-object / nested form.
import { commandListSchema, taskListSchema } from './runtime/arg-normalize.js'
import { requireReady, toolText, toolTextRaw } from './runtime/tool-host.js'
import { progressReporter } from './runtime/progress.js'
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

/**
 * V0.5.11: human-readable counterpart of `ConnectionView['password']`.
 *
 * The console's 设置 tab could always show WHICH account supplies the live
 * credential, but the model could not — `jumpserver_status` carried no source
 * field, so "which bastion account am I using?" was unanswerable in chat. The
 * view is redacted by construction (source + label, never a value), so this
 * projection can name the layer without ever touching the secret.
 */
function describeCredentialSource(password: { source: ConnectionSource; via?: string }): string {
  const via = password.via !== undefined && password.via.length > 0 ? password.via : undefined
  switch (password.source) {
    case 'profile':
      // `via` is the operator-chosen account label, e.g. "生产维护".
      return via !== undefined ? '账号：' + via : '本机账号'
    case 'env':
      return via !== undefined ? '环境变量 ' + via : '环境变量'
    case 'config':
      return 'config.json'
    default:
      return '未配置'
  }
}

/**
 * Returns the not-armed value when grants are required and locked, else null.
 *
 * V0.5.2: only the tools that MUST stay answerable while unconfigured use this
 * (status / rotate / audit / snapshot) — a user has to be able to ask what is
 * wrong. Everything that touches the bastion goes through `requireReady`,
 * which reports a missing connection BEFORE it asks anyone to arm.
 */
function requireGrant(grants: SessionGrant, runtime: Runtime, exec: ToolRunContext): ResultValue | null {
  if (runtime.getConfig().requireArm !== true) return null
  return grants.isGranted(sessionIdOf(exec)) ? null : notArmed()
}

// Console handover + text projection live in runtime/tool-host.ts so the ops
// tool modules (inspect / topology / jobs) share the exact same behaviour.
const text = toolText
const textRaw = toolTextRaw

// V0.5.2: these two strings are emitted into the schema of every tool that
// takes them, so they are written for signal density — the long-form rule
// lives in the tool description and in connector/skills/jumpserver/SKILL.md.
const CONFIRM_DESCRIPTION =
  'Set true only after the user approved these command(s). The first attempt returns COMMAND_APPROVAL_REQUIRED with the reason.'

const TIMEOUT_DESCRIPTION = 'Timeout in seconds (default: configured command timeout, max 600).'

async function main(): Promise<void> {
  // V0.5.2: `--doctor` is a CLI diagnostic, checked BEFORE anything is built.
  // It must not start the console (which binds a port), must not connect the
  // stdio transport (stdout stays human-readable), and must survive exactly the
  // input it exists to diagnose — a malformed config. See runtime/doctor.ts.
  if (wantsDoctor()) {
    const report = await runDoctor()
    // stdout: a person ran this in a terminal. stderr carries the machine
    // marker, so a host that passes --doctor by accident fails visibly instead
    // of waiting forever for a handshake that will never come.
    console.log(renderDoctor(report))
    console.error('[jumpserver-mcp] --doctor finished; no MCP server was started.')
    process.exit(report.exitCode)
  }

  const runtime = createRuntime()
  const { grants, registry, getConfig } = runtime

  const servicesFor = (bundle: { manager: import('./jumpserver/session-manager.js').SessionManager }): GateServices => ({
    getConfig: getConfig as () => JumpServerConfig,
    manager: bundle.manager,
  })

  const server = new McpServer({ name: 'jumpserver-mcp', version: PLUGIN_VERSION })
  // V0.7.1 (D-1/D-2/D-3): the model-facing output budget.
  //
  // The budget belongs here, at the tool layer: it caps what enters the
  // model's context WITHOUT touching what the bastion actually printed (the
  // audit trail must keep the truth). An over-budget output is written to
  // `data/outputs/` so the full text is still retrievable, and the model is
  // told how to ask the remote host for the slice it actually wants.
  const outputBudget = {
    spillDir: join(dirname(runtime.auditPath), 'outputs'),
    spillName: 'output',
  } as const
  // V0.6.1 (B-4): record every registration so `jumpserver_status` can say
  // whether the tool surface is complete. Must come BEFORE the first
  // registerTool call — including the ones made by registerOpsTools.
  trackToolRegistrations(server)

  const confirmShape = { confirm: z.boolean().optional().describe(CONFIRM_DESCRIPTION) }
  const timeoutShape = { timeout: z.number().optional().describe(TIMEOUT_DESCRIPTION) }

  server.registerTool(
    'jumpserver_status',
    {
      description:
        'Report connector state: session, gateway, entered target (probe-verified), permission mode, the ops-console URL and token expiry, and whether the connection settings are complete. Never returns credentials. Strictly read-only — to invalidate the console token use jumpserver_console_rotate_token.',
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
        // V0.5.2: an unconfigured connector now STARTS and answers here rather
        // than dying at boot, so this is the one place that must say what is
        // still missing instead of refusing outright.
        const problems = runtime.configProblems()
        // V0.5.11: expose WHERE the live connection comes from, so the model can
        // answer "which bastion account is in effect?" — the console already
        // could, but the tool payload did not. `connection()` is a redacted view:
        // it carries each field's source layer (and, for the password, the
        // account label via `via`) and never a credential value or `v1:` token.
        const connection = runtime.connection()
        const ownership = consoleOwnership()
        return {
          ...statusToValue(bundle.manager.status()),
          ...runtimeVersion(),
          connectionComplete: problems.length === 0,
          connectionMissing: [...problems],
          credentialSource: connection.password.source,
          credentialSourceDetail: describeCredentialSource(connection.password),
          hostSource: connection.host.source,
          usernameSource: connection.username.source,
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
          // V0.6.1 (B-4): tool-surface self-check. "The host shows the
          // connector as connected but `mcp__jumpserver` has zero sub-tools"
          // has three indistinguishable causes, and the model could answer
          // none of them. These fields say whether THIS process published the
          // expected tools, who owns the console address, and whether the
          // console URL is still served by a live process.
          toolsRegistered: registeredToolCount(),
          toolsExpected: ALWAYS_TOOL_NAMES.length,
          toolsMissing: missingAlwaysToolNames(),
          consoleRole: ownership.role,
          consoleOwnerPid: ownership.ownerPid,
          consoleUrlServed: ownership.urlServed,
          consoleInstances: ownership.instanceCount,
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
        'Revoke the ops-console access token and issue a fresh one. In stable mode (the default) the console address is unchanged — reload the page and it picks the new token up. Use when the console reports 令牌已过期. Side-effecting (the old token dies immediately), so not read-only.',
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
        'Open the persistent JumpServer SSH session and wait until the menu is detected. Idempotent — if a session already exists this does NOT create a second one, it returns the current state. One session per conversation.',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_connect', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
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
        'Enter a target asset THROUGH the JumpServer menu by its IP or name. Safe to call from any navigable state: if the session is already inside another asset it leaves that asset first, and re-entering the asset you are already on is a no-op that returns the current status. A probe (hostname/whoami/pwd) runs internally and the asset is reported as entered only after it verifies. When the target has multiple authorised bastion users, KoKo shows a numbered list ending in `ID>`; pass `accountIndex` (the displayed ID, usually 1 or 2) to pick one, or omit to fail with ACCOUNT_SELECTION_REQUIRED and the parsed list in `detail`. An asset the bastion cannot reach (`网络不通（连接超时）`) fails fast as ASSET_UNREACHABLE and is then refused for 2 minutes — report it to the user instead of retrying.',
      inputSchema: {
        target: z.string().describe('Target asset IP or name, e.g. 203.0.113.101'),
        accountIndex: z.number().int().min(0).optional().describe('The account ID shown by KoKo at the `ID>` prompt (usually 1 or 2; matches the number on the screen).'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_enter', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
        if (blocked !== null) return blocked
        // V0.4.2: scope check BEFORE navigation — a denied target must never
        // get an SSH/PTY session opened against it.
        requireTargetAllowed(runtime.getConfig(), args.target)
        const bundle = bundleFor(exec, registry)
        return statusToValue(await bundle.manager.enter(args.target, typeof args.accountIndex === 'number' ? args.accountIndex : undefined, exec.signal))
      }))
    },
  )

  server.registerTool(
    'jumpserver_assets',
    {
      description:
        'List the assets this account is authorized for WITHOUT entering any of them: KoKo menu command "p" (display-only), parsed locally, cached ~5 min. Filter by substring or by a configured asset group. Call this before jumpserver_run/jumpserver_batch — never guess IPs, and never type an asset name into the menu (KoKo auto-logs-in on a unique hit).',
      inputSchema: {
        filter: z.string().optional().describe('Substring filter, matched case-insensitively across name / IP / platform / node / comment.'),
        group: z.string().optional().describe('Configured asset group name (assetGroups setting). Unknown groups error instead of returning "0 assets".'),
        refresh: z.boolean().optional().describe('Force a fresh capture instead of the cache (default false). Use after a failed or incomplete capture.'),
        includeRawText: z.boolean().optional().describe('Include the raw captured screen in rawText, bounded (default false) — diagnostics only.'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_assets', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      const value = await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
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
        // V0.7.2 (E-5): refresh the alias cache. Only a HEALTHY, COMPLETE,
        // UNFILTERED listing is worth caching — a failed, paged or filtered
        // capture would poison the reverse lookup with half an asset list, and
        // a wrong candidate is worse than no candidate.
        const unfiltered =
          (typeof args.filter !== 'string' || args.filter.length === 0) &&
          (typeof args.group !== 'string' || args.group.length === 0)
        if (result.health === 'ok' && unfiltered && result.assets.length > 0) {
          runtime.aliases.update(result.assets)
        }
        return assetsToValue(result, { includeRawText: args.includeRawText === true })
      })
      return textRaw(renderAssetsResult(value))
    },
  )

  server.registerTool(
    'jumpserver_exec',
    {
      description:
        'Run ONE simple command on the CURRENTLY entered asset and return stdout plus the real exit code (completion is detected by a unique marker, never by waiting a fixed time). Send one simple read-only command — no for/if loops, no $(...) substitution, no multi-statement one-liners, because READ_ONLY classifies every command statically and blocks shell structure. For several checks on one target use jumpserver_batch.',
      inputSchema: {
        command: z.string().describe('Shell command to execute on the remote asset.'),
        ...timeoutShape,
        ...confirmShape,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_exec', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      return text(await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        const gated = await gateCommand(servicesFor(bundle), exec, args.command)
        requireTargetAllowed(runtime.getConfig(), bundle.manager.status().target)
        // V0.7.1 (D-10): the dangerous-command guardrail caps the execution
        // time of a DANGEROUS/UNKNOWN command and reports the impact estimate
        // next to the result. READ commands are never touched.
        const guard = applyGuardrail(
          gated.classification.risk as Parameters<typeof applyGuardrail>[0],
          args.command,
          args.timeout !== undefined ? Math.max(1, args.timeout) * 1000 : undefined,
          runtime.getConfig().commandTimeout * 1000,
        )
        const timeoutMs = guard.timeoutMs
        const { status, outcome } = await bundle.manager.exec({
          command: args.command,
          timeoutMs,
          toolCallId: String(exec.callId),
          risk: gated.risk,
          classification: gated.classification,
          approvalRequired: gated.approvalRequired,
          approvalResult: gated.approvalRequired ? 'approved' : 'none',
          riskJudge: gated.judgeNote,
          signal: exec.signal,
        })
        const value = execOutcomeToValue(status, outcome, { ...outputBudget, command: args.command })
        if (gated.judgeAutoAllowed === true && gated.judgeNote !== undefined) value.riskJudge = gated.judgeNote
        if (guard.note !== null) value.guardrailNote = guard.note
        if (guard.capped) value.guardrailCapped = true
        return value
      }))
    },
  )

  server.registerTool(
    'jumpserver_run',
    {
      description:
        'Run ONE simple command on a target reachable through JumpServer: connects (or reuses the session), switches asset when necessary, verifies the target, executes, and returns structured output. Same command-style limits as jumpserver_exec. For MULTIPLE metrics on one target call jumpserver_batch ONCE instead of calling this repeatedly.',
      inputSchema: {
        target: z.string().describe('Target asset IP or name, e.g. 203.0.113.101'),
        command: z.string().describe('Shell command to execute on the remote asset.'),
        // V0.5.3: same `ID>` handling as jumpserver_enter — required only when
        // the target has multiple bastion users.
        accountIndex: z.number().int().min(0).optional().describe('The account ID shown by KoKo at the `ID>` prompt (usually 1 or 2; matches the number on the screen).'),
        ...timeoutShape,
        ...confirmShape,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_run', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      return text(await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        // V0.4.2: fail fast on out-of-scope targets before any classification work.
        requireTargetAllowed(runtime.getConfig(), args.target)
        const gated = await gateCommandForNavigation(servicesFor(bundle), exec, args.command)
        // V0.7.1 (D-10): the same guardrail as jumpserver_exec.
        const guard = applyGuardrail(
          gated.classification.risk as Parameters<typeof applyGuardrail>[0],
          args.command,
          args.timeout !== undefined ? Math.max(1, args.timeout) * 1000 : undefined,
          runtime.getConfig().commandTimeout * 1000,
        )
        const timeoutMs = guard.timeoutMs
        const result = await bundle.manager.run({
          target: args.target,
          command: args.command,
          accountIndex: typeof args.accountIndex === 'number' ? args.accountIndex : undefined,
          timeoutMs,
          toolCallId: String(exec.callId),
          risk: gated.risk,
          classification: gated.classification,
          approvalRequired: gated.approvalRequired,
          approvalResult: gated.approvalRequired ? 'approved' : 'none',
          riskJudge: gated.judgeNote,
          signal: exec.signal,
          beforeExec: gated.beforeExec,
        })
        const { target, hostname, status, outcome } = result
        return {
          ...execOutcomeToValue(status, outcome, { ...outputBudget, command: args.command }),
          target,
          hostname,
          riskJudge: gated.judgeAutoAllowed === true ? gated.judgeNote : undefined,
          ...(guard.note !== null ? { guardrailNote: guard.note } : {}),
          ...(guard.capped ? { guardrailCapped: true } : {}),
        }
      }))
    },
  )

  server.registerTool(
    'jumpserver_batch',
    {
      description:
        'Run simple commands across one or more targets in a single call. All commands of a target run before the next target is entered (target affinity). Put ONE simple read-only command per commands[] entry — no for/while loops, if branches, $(...) substitution or chained redirection; each entry is classified independently and statically.',
      inputSchema: {
        tasks: taskListSchema({
          element: z.object({
            target: z.string().describe('Target asset IP or name.'),
            commands: commandListSchema({ field: 'commands' }).describe('Simple shell commands for this target, run sequentially with per-command results.'),
            // V0.5.3: per-task accountIndex — a batch may mix single-user and
            // multi-user targets, so the connector lets each task carry its own.
            accountIndex: z.number().int().min(0).optional().describe('The account ID shown by KoKo at this task\'s `ID>` prompt (usually 1 or 2).'),
            timeout: z.number().optional().describe('Per-command timeout in seconds for this task (max 600).'),
          }),
          field: 'tasks',
          example: '[{"target":"1.1.1.1","commands":["uptime"]}]',
        }).describe('One or more target tasks.'),
        ...confirmShape,
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_batch', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      // V0.5.2: a multi-target batch is one of the longest silent operations in
      // the connector; report per-target progress when the client asked for it.
      const progress = progressReporter(extra)
      // V0.5.8: judge auto-allows of this call, collected per target so the
      // result can state that a prompt was skipped on purpose.
      const autoAllowed: string[] = []
      const value = await guardValue(exec, async (): Promise<ResultValue> => {
        const blocked = requireReady(runtime, grants, exec)
        if (blocked !== null) return blocked
        const bundle = bundleFor(exec, registry)
        const executed: TargetBatchResult[] = []
        const batchId = 'bat_' + Math.random().toString(36).slice(2, 8)
        let done = 0
        progress(0, args.tasks.length, 'batch: ' + args.tasks.length + ' target(s)')
        for (const task of args.tasks) {
          if (exec.signal.aborted === true) throw new AbortRequestedError()
          const target = String(task.target ?? '')
          const commands = task.commands.map((c) => String(c ?? '')).filter((c: string) => c.trim().length > 0)
          done += 1
          progress(done, args.tasks.length, 'batch: ' + target)
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
            // V0.5.8: collect the judge auto-allows of this target for the result.
            const autoNote = judgeAutoAllowNote(gated)
            if (autoNote !== undefined) autoAllowed.push(target + ': ' + autoNote)
            const timeoutMs = typeof task.timeout === 'number' && Number.isFinite(task.timeout) ? Math.max(1, task.timeout) * 1000 : undefined
            const commandRequests: BatchCommandRequest[] = gated.map((g, i) => {
              const request: BatchCommandRequest = {
                command: commands[i]!,
                timeoutMs,
                risk: g.risk,
                blocked: g.blocked,
                classification: g.classification,
                approvalRequired: g.approvalRequired,
                approvalResult: g.approvalRequired ? 'pending' : 'none',
                riskJudge: g.judgeNote,
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
              accountIndex: typeof task.accountIndex === 'number' ? task.accountIndex : undefined,
            }))
          } catch (error) {
            if (error instanceof AbortRequestedError || (exec.signal as { aborted?: boolean }).aborted === true) throw error
            executed.push({ target, hostname: null, error: thisJumpError(error), commands: [] })
          }
        }
        return renderBatchResult(executed, outputBudget)
      })
      const batchValue = value as ResultValue
      if (autoAllowed.length > 0) batchValue.riskJudge = autoAllowed.join(' | ')
      return text(batchValue)
    },
  )

  server.registerTool(
    'jumpserver_leave',
    {
      description:
        'Leave the currently entered asset and return to the JumpServer menu. Sends exit at most once, and reports success only after the menu is detected again.',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_leave', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
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
        'Close the JumpServer session: PTY, SSH channel, buffers and timers are released and the connector returns to the DISCONNECTED state.',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_close', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return text(await guardValue(exec, async () => {
        const blocked = requireReady(runtime, grants, exec)
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
        'Read-only terminal mirror: the recent PTY event stream (output chunks, state transitions, target changes) plus the current state. Poll incrementally with sinceSeq. Use it to show the user what the terminal looks like now, or to diagnose a stuck menu. Credentials are redacted by the observer.',
      inputSchema: {
        sinceSeq: z.number().optional().describe('Return only events with seq > sinceSeq (incremental polling). Omit for the full scrollback.'),
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
        'Read the local audit trail of THIS connector in-chat: recent audited events (time, operation, target asset, redacted command, risk, result). Use it when the user asks what the AI ran through JumpServer. Purely local file read — never touches the bastion, and works with no session and no configuration.',
      inputSchema: {
        limit: z.number().int().min(1).max(200).optional().describe('How many recent entries to return (default 20, oldest first).'),
        filter: z.string().optional().describe('Substring filter matched case-insensitively against each raw audit entry (e.g. an IP or a command fragment).'),
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
          const parts = [
            ts,
            String(e['operation'] ?? '-'),
            String(e['target'] ?? e['hostname'] ?? '-'),
            '[' + String(e['risk'] ?? '?') + ']',
            String(e['result'] ?? '?'),
            'call=' + callId,
            'batch=' + batchId,
          ]
          // V0.5.9: a refusal record is only useful if the reason survives the
          // projection — a bare "BLOCKED" would send the model back to
          // guessing. Present only on refusals, so an ordinary line is
          // byte-identical to what it was before.
          const why = e['refusalReason']
          if (why !== undefined && why !== null && String(why).length > 0) parts.push('why=' + String(why))
          parts.push(cmd)
          return parts.join(' | ')
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
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
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
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
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
