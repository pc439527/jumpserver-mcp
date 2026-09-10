/**
 * Ops tools (V0.4.0) — the "AI infrastructure investigation" layer:
 *
 *   jumpserver_inspect    fixed read-only probes -> structured host inventory
 *   jumpserver_topology   inventories -> evidence-annotated relationship graph
 *   jumpserver_interrupt  Ctrl+C the remote shell (console/abort parity)
 *   jumpserver_job_start  streaming job (tail -f / journalctl -f / tcpdump)
 *   jumpserver_job_read   incremental output of a running job
 *   jumpserver_job_stop   Ctrl+C + release the PTY
 *   jumpserver_jobs       list jobs of this conversation
 *
 * Kept out of server.ts so the tool registry stays readable; the shared
 * plumbing (grant check, console hint, session bundle) comes from tool-host.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import { inspectTargets } from '../jumpserver/inspector.js'
import { buildTopology, renderTopology } from '../jumpserver/topology.js'
import type { HostInventory } from '../jumpserver/host-parse.js'
import { INSPECT_PROFILES, type InspectProfile } from '../jumpserver/profiles.js'
import { resolveRunbook, runRunbook, type RunbookResult } from '../jumpserver/runbook.js'
import { compareTargets, type CompareResult } from '../jumpserver/compare.js'
import { diffBaseline, type Baseline, type BaselineHost, type DriftResult } from './baseline-store.js'
import { requireTargetAllowed } from '../security/target-scope.js'
import { gateCommandForNavigation } from '../security/permission-gate.js'
import { JumpServerError } from '../jumpserver/errors.js'
import { redactCommandSecrets } from '../security/command-redaction.js'
import { guardText, guardValue, type ResultValue } from './tools-common.js'
import { createToolHost, toolText, toolTextRaw, type ToolHost } from './tool-host.js'
import { randomHex } from '../jumpserver/timing.js'
import type { ToolRunContext } from './context.js'

export function registerOpsTools(server: McpServer, runtime: import('./runtime.js').Runtime): void {
  const host = createToolHost(runtime)

  // ---------------------------------------------------------------- inspect
  server.registerTool(
    'jumpserver_inspect',
    {
      description:
        'Collect a STRUCTURED host inventory from one or more servers through JumpServer, using FIXED read-only probes (the connector decides the commands — do not invent shell). Returns parsed facts (OS, kernel, uptime, load, memory, disks, IPs, listening ports, established connections, processes, services, nginx upstreams, java, docker, detected roles) instead of raw shell text. Use this (not a pile of jumpserver_exec calls) whenever you need to understand what a server is or how servers relate. Profiles: basic / network / process / service / web / java / database / container / full.',
      inputSchema: {
        targets: z.array(z.string()).min(1).max(20).describe('Target IPs or asset names to inspect (max 20).'),
        profile: z.union([z.enum(INSPECT_PROFILES), z.array(z.enum(INSPECT_PROFILES))]).optional().describe('Probe profile(s), default "basic". "full" runs every profile.'),
        group: z.string().optional().describe('Instead of targets: a configured asset group (e.g. "OA") — every asset of that group is inspected.'),
        format: z.enum(['text', 'json']).optional().describe('text (default, compact) or json (full structured inventory).'),
        concurrency: z.number().int().min(1).max(8).optional().describe('How many targets to survey at once (default: batchConcurrency setting). Raise for a large estate; each target still gets its own bastion session turn.'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_inspect', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return render(blocked)
        const bundle = host.bundleFor(exec)
        const targets = await resolveTargets(host, bundle, exec, args.targets, args.group)
        const result = await inspectTargets(bundle.manager, host.getConfig, {
          targets,
          profile: args.profile as InspectProfile | InspectProfile[] | undefined,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          batchId: 'ins_' + randomHex(6),
          concurrency: args.concurrency ?? host.getConfig().batchConcurrency ?? 1,
        })
        const head = 'ok inspect profile=' + result.profiles.join(',') +
          ' targets=' + result.targets + ' reachable=' + result.reachable +
          ' durationMs=' + result.durationMs
        if (args.format === 'json') {
          return head + '\n' + JSON.stringify(result, null, 2)
        }
        return [head, ...result.inventories.map(renderInventory), ...result.warnings.map((w) => 'note: ' + w)].join('\n')
      }))
    },
  )

  // -------------------------------------------------------------- topology
  server.registerTool(
    'jumpserver_topology',
    {
      description:
        'Build the relationship graph between servers: which host proxies/connects to which, on which port, with what evidence (nginx upstream, ESTABLISHED socket, /etc/hosts). Internally runs the read-only inspect probes (profiles network/process/web by default) and returns nodes (roles, ports, OS, load, memory) plus edges (type, port, confidence, evidence). Use it for "what is the relationship between 99/100/101/102/103" style questions instead of guessing from names. depth>=2 also links app nodes that share one upstream (same cluster).',
      inputSchema: {
        targets: z.array(z.string()).optional().describe('Target IPs or asset names (max 20). Omit when using group.'),
        group: z.string().optional().describe('Configured asset group (e.g. "OA") — every asset of that group is surveyed.'),
        profiles: z.array(z.enum(INSPECT_PROFILES)).optional().describe('Probe profiles for the survey (default: network, process, web).'),
        depth: z.number().int().min(1).max(3).optional().describe('1 = direct evidence only (default); 2+ also links nodes sharing one upstream.'),
        format: z.enum(['text', 'json']).optional().describe('text (default, tree) or json (nodes + edges).'),
        concurrency: z.number().int().min(1).max(8).optional().describe('How many targets to survey at once (default: batchConcurrency setting).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_topology', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return render(blocked)
        const bundle = host.bundleFor(exec)
        const targets = await resolveTargets(host, bundle, exec, args.targets, args.group)
        const profiles = args.profiles !== undefined && args.profiles.length > 0 ? args.profiles : ['network', 'process', 'web']
        const started = Date.now()
        const result = await inspectTargets(bundle.manager, host.getConfig, {
          targets,
          profile: profiles,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          batchId: 'topo_' + randomHex(6),
          concurrency: args.concurrency ?? host.getConfig().batchConcurrency ?? 1,
        })
        const topology = buildTopology(result.inventories, { depth: args.depth ?? 1 })
        runtime.topology.set({
          updatedAt: Date.now(),
          group: args.group ?? null,
          profiles: result.profiles,
          targets,
          nodes: topology.nodes,
          edges: topology.edges,
          warnings: topology.warnings,
          durationMs: Date.now() - started,
        })
        if (args.format === 'json') {
          return JSON.stringify({ ok: true, ...topology, profiles: result.profiles, durationMs: Date.now() - started }, null, 2)
        }
        return [
          'ok topology nodes=' + topology.nodes.length + ' edges=' + topology.edges.length + ' depth=' + String(args.depth ?? 1),
          renderTopology(topology),
          ...(topology.edges.length > 0 ? ['', 'edges (json):', JSON.stringify(topology.edges)] : []),
        ].join('\n')
      }))
    },
  )

  // ---------------------------------------------------------- profile_run
  server.registerTool(
    'jumpserver_profile_run',
    {
      description:
        'Run a NAMED runbook (a reviewed, reusable survey recipe defined in config under "runbooks") against one or more servers. Each step is either an inspect profile or an explicit READ-only command; non-READ steps are SKIPPED and reported, never executed. Use this instead of hand-assembling the same set of checks for several hosts: it guarantees the exact same steps run on every target, and the results come back grouped per target and per step. Call it with a runbook name (see the config) plus targets[] or a configured group.',
      inputSchema: {
        runbook: z.string().describe('Runbook name as defined in config.json under "runbooks", e.g. "oa-health".'),
        targets: z.array(z.string()).optional().describe('Target IPs or asset names (max 20). Omit when using group.'),
        group: z.string().optional().describe('Configured asset group (e.g. "OA") — the runbook runs on every asset of that group.'),
        format: z.enum(['text', 'json']).optional().describe('text (default, compact) or json (full structured result).'),
        concurrency: z.number().int().min(1).max(8).optional().describe('How many targets to run at once (default: batchConcurrency setting).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_profile_run', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return render(blocked)
        const bundle = host.bundleFor(exec)
        const def = resolveRunbook(host.getConfig().runbooks, args.runbook)
        const targets = await resolveTargets(host, bundle, exec, args.targets, args.group)
        const result = await runRunbook(bundle.manager, host.getConfig, args.runbook, def, {
          targets,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          batchId: 'rbk_' + randomHex(6),
          concurrency: args.concurrency ?? host.getConfig().batchConcurrency ?? 1,
        })
        if (args.format === 'json') return JSON.stringify({ ok: true, ...result }, null, 2)
        return renderRunbook(result)
      }))
    },
  )

  // -------------------------------------------------------------- compare
  server.registerTool(
    'jumpserver_compare',
    {
      description:
        'Run the SAME read-only command (or inspect profile) across several servers and report what DIFFERS — which host has a different config, a missing listener, a full disk. Returns groups of identical hosts plus, for each outlier, the lines it is missing / has extra versus the majority. Use this for "are these 6 nodes configured the same?" / "which one is different?" questions instead of eyeballing 6 raw dumps. Only READ commands are accepted; a mutating command refuses the whole call.',
      inputSchema: {
        targets: z.array(z.string()).min(2).max(20).describe('Target IPs or asset names to compare (2..20).'),
        command: z.string().optional().describe('One read-only command to run on every target (mutually exclusive with profile).'),
        profile: z.enum(INSPECT_PROFILES).optional().describe('Inspect profile to run on every target (mutually exclusive with command).'),
        stripPrefixes: z.array(z.string()).optional().describe('Line prefixes to strip before diffing (e.g. volatile timestamps).'),
        format: z.enum(['text', 'json']).optional().describe('text (default, compact) or json (full structured diff).'),
        concurrency: z.number().int().min(1).max(8).optional().describe('How many targets at once (default: batchConcurrency setting).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_compare', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return render(blocked)
        const bundle = host.bundleFor(exec)
        const result = await compareTargets(bundle.manager, host.getConfig, {
          targets: args.targets,
          command: args.command,
          profile: args.profile,
          stripPrefixes: args.stripPrefixes,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          batchId: 'cmp_' + randomHex(6),
          concurrency: args.concurrency ?? host.getConfig().batchConcurrency ?? 1,
        })
        if (args.format === 'json') return JSON.stringify({ ok: true, ...result }, null, 2)
        return renderCompare(result)
      }))
    },
  )

  // ------------------------------------------------------------ baseline
  server.registerTool(
    'jumpserver_baseline_capture',
    {
      description:
        'Capture a NAMED baseline snapshot of one or more servers: the read-only inspect probes are run and a compact state (OS, kernel, cores, memory, disks, listening ports, services, roles) is saved to data/baselines/<name>.json. Later, jumpserver_baseline_compare re-inspects the same targets and reports DRIFT (new/removed ports, disk growth, service changes, load/memory shifts). Use it before a change window, then compare after, to prove what actually changed.',
      inputSchema: {
        name: z.string().describe('Baseline name (letters/digits/._-, max 64), e.g. "oa-prechange-20260910".'),
        targets: z.array(z.string()).min(1).max(20).describe('Target IPs or asset names to snapshot (max 20).'),
        group: z.string().optional().describe('Instead of targets: a configured asset group whose assets are snapshotted.'),
        profile: z.enum(INSPECT_PROFILES).optional().describe('Probe profile used for the snapshot (default "full").'),
        overwrite: z.boolean().optional().describe('Allow replacing an existing baseline of the same name (default false).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_baseline_capture', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return render(blocked)
        const bundle = host.bundleFor(exec)
        const targets = await resolveTargets(host, bundle, exec, args.targets, args.group)
        if (args.overwrite !== true && runtime.baselines.list().includes(args.name)) {
          throw new JumpServerError('INVALID_ARGUMENT', 'baseline "' + args.name + '" already exists; pass overwrite:true to replace it')
        }
        const profile = args.profile ?? 'full'
        const result = await inspectTargets(bundle.manager, host.getConfig, {
          targets,
          profile,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          batchId: 'bl_' + randomHex(6),
          concurrency: host.getConfig().batchConcurrency ?? 1,
        })
        const baseline: Baseline = {
          name: args.name,
          createdAt: new Date().toISOString(),
          profile: result.profiles.join(','),
          targets,
          hosts: result.inventories.map(toBaselineHost),
        }
        const path = runtime.baselines.save(baseline)
        const reachable = baseline.hosts.filter((h) => h.reachable).length
        return [
          'ok baseline=' + baseline.name + ' profile=' + baseline.profile + ' targets=' + String(targets.length) +
            ' reachable=' + String(reachable) + ' saved=' + path,
          'createdAt=' + baseline.createdAt,
          ...baseline.hosts.map((h) => '  ' + h.target + (h.hostname !== null ? ' ' + h.hostname : '') + (h.reachable ? '' : '  !! ' + (h.error ?? 'unreachable'))),
          ...result.warnings.map((w) => 'note: ' + w),
        ].join('\n')
      }))
    },
  )

  server.registerTool(
    'jumpserver_baseline_compare',
    {
      description:
        'Compare a saved baseline (jumpserver_baseline_capture) against the CURRENT state of the same servers and report DRIFT: which hosts changed and exactly what changed (added/removed listening ports, disk usage, services, roles, kernel, cores, memory %, load). Use it after a change window, or periodically, to prove what moved. Hosts that cannot be reached now are reported as unreachable, never as "unchanged".',
      inputSchema: {
        name: z.string().describe('Baseline name to compare against.'),
        profile: z.enum(INSPECT_PROFILES).optional().describe('Probe profile for the fresh capture (default: the profile stored in the baseline).'),
        format: z.enum(['text', 'json']).optional().describe('text (default, compact) or json (full structured drift).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_baseline_compare', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return render(blocked)
        const bundle = host.bundleFor(exec)
        const baseline = runtime.baselines.load(args.name)
        const profile = args.profile ?? baseline.profile
        const result = await inspectTargets(bundle.manager, host.getConfig, {
          targets: baseline.targets,
          profile,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          batchId: 'bld_' + randomHex(6),
          concurrency: host.getConfig().batchConcurrency ?? 1,
        })
        const current = result.inventories.map(toBaselineHost)
        const drift = diffBaseline(baseline, current, new Date().toISOString())
        if (args.format === 'json') return JSON.stringify({ ok: true, drift, warnings: result.warnings }, null, 2)
        return renderDrift(drift, result.warnings)
      }))
    },
  )

  // ------------------------------------------------------------- interrupt
  server.registerTool(
    'jumpserver_interrupt',
    {
      description:
        'Send Ctrl+C to the remote shell NOW to interrupt whatever is running (a stuck command, a tail that will not end, a long find). Out-of-band: it does NOT wait for the current operation to finish. Afterwards the connector re-probes the shell and reports whether it is usable again (ASSET_SHELL) or collapsed to UNKNOWN. Use it instead of jumpserver_close when you only want to stop the remote job and keep the session.',
      inputSchema: {},
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_interrupt', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolText(await guardValue(exec, async (): Promise<ResultValue> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return blocked
        const bundle = host.bundleFor(exec)
        const jobs = runtime.jobs.list().filter((j) => j.state === 'RUNNING')
        const result = await bundle.manager.interrupt()
        for (const job of jobs) await runtime.jobs.stop(job.id).catch(() => undefined)
        return {
          ok: result.sent,
          code: result.sent ? undefined : 'NOTHING_TO_INTERRUPT',
          message: result.sent
            ? (result.verified
                ? '中断信号已发送，远程 Shell 已重新验证可用（ASSET_SHELL）'
                : '中断信号已发送，但 Shell 未能重新验证；会话已降级为 UNKNOWN，需要重连后再操作')
            : '当前没有可中断的活动会话或远端 Shell',
          state: result.state,
          target: result.target,
          interrupted: result.sent,
          verified: result.verified,
        } as unknown as ResultValue
      }))
    },
  )

  // ----------------------------------------------------------- job (stream)
  server.registerTool(
    'jumpserver_job_start',
    {
      description:
        'Start a STREAMING job on a server — for commands that never return on their own: tail -f /…/stdout.log, journalctl -f -u nginx, tcpdump, top -b, ping. Returns a jobId; then poll jumpserver_job_read(jobId) for the new output and call jumpserver_job_stop(jobId) when done. While a job is running the shell is reserved for it (other commands get SESSION_BUSY). The job auto-stops at maxDuration.',
      inputSchema: {
        target: z.string().describe('Target asset IP or name.'),
        command: z.string().describe('Streaming command, e.g. "tail -f /usr/weaver/Resin4/log/stdout.log"'),
        maxDuration: z.number().int().min(1).max(900).optional().describe('Auto-stop after N seconds (default 300, max 900).'),
        confirm: z.boolean().optional().describe('Set true after the user approved this command (non-READ classifications require it).'),
      },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_job_start', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: args.confirm === true }
      return toolText(await guardValue(exec, async (): Promise<ResultValue> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return blocked
        requireTargetAllowed(host.getConfig(), args.target)
        const bundle = host.bundleFor(exec)
        // V0.4.3: job_start runs through the SAME gate as every other
        // execution tool. Before this it classified + asked for confirmation
        // itself, so a READ_ONLY deployment could still start a MODIFY job
        // with confirm:true, and the audit hardcoded risk:'READ'.
        const gated = await gateCommandForNavigation(host.servicesFor(bundle), exec, args.command)
        const job = await runtime.jobs.start({
          sessionId: host.sessionIdOf(exec),
          target: args.target,
          command: args.command,
          maxDurationMs: args.maxDuration !== undefined ? args.maxDuration * 1000 : undefined,
          signal: exec.signal,
          toolCallId: String(exec.callId),
          classification: {
            risk: gated.classification.risk,
            reason: gated.classification.reason,
            ruleId: gated.classification.ruleId,
            confidence: gated.classification.confidence,
            classifierVersion: gated.classification.classifierVersion,
            normalizedCommand: gated.classification.normalizedCommand,
          },
          approvalRequired: gated.approvalRequired,
          approvalResult: gated.approvalRequired ? 'approved' : 'none',
        })
        return {
          ok: true,
          jobId: job.id,
          target: job.target,
          hostname: job.hostname,
          state: job.state,
          risk: gated.classification.risk,
          maxDurationMs: job.maxDurationMs,
          message: 'job started: 用 jumpserver_job_read("' + job.id + '") 读取增量输出，jumpserver_job_stop("' + job.id + '") 结束。',
        } as unknown as ResultValue
      }))
    },
  )

  server.registerTool(
    'jumpserver_job_read',
    {
      description:
        'Read the output collected so far by a streaming job (jumpserver_job_start). Returns only what arrived since the last read unless full:true. Use it to watch logs while you work: "keep reading the OA log" = call this repeatedly.',
      inputSchema: {
        jobId: z.string().describe('Job id returned by jumpserver_job_start, e.g. jsjob_8fd11a'),
        full: z.boolean().optional().describe('Return the whole buffered output instead of only the new tail (default false).'),
        maxChars: z.number().int().min(200).max(200000).optional().describe('Cap the returned characters (default 8000).'),
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_job_read', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const job = runtime.jobs.read(args.jobId)
        if (job === null) return 'code: UNKNOWN_JOB\nno job with id ' + args.jobId
        const maxChars = args.maxChars ?? 8000
        const full = args.full === true
        const output = full ? job.output : tailSince(job.output, maxChars)
        return [
          'jobId=' + job.id + ' state=' + job.state + ' target=' + job.target +
            ' elapsedMs=' + (Date.now() - job.startedAt) + ' bytes=' + job.bytes + (job.truncated ? ' (buffer truncated)' : ''),
          '$ ' + redactCommandSecrets(job.command),
          '--- output (' + (full ? 'full' : 'tail') + ') ---',
          output.length > 0 ? output : '(还没有输出)',
          ...(job.error !== null ? ['note: ' + job.error] : []),
        ].join('\n')
      }))
    },
  )

  server.registerTool(
    'jumpserver_job_stop',
    {
      description: 'Stop a streaming job: sends Ctrl+C to the remote shell and releases it for normal commands.',
      inputSchema: {
        jobId: z.string().describe('Job id returned by jumpserver_job_start.'),
      },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_job_stop', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolText(await guardValue(exec, async (): Promise<ResultValue> => {
        const job = await runtime.jobs.stop(args.jobId)
        // V0.4.3: LOST means Ctrl+C was sent but the shell could not be
        // re-proved — the job is over, but the session is NOT usable.
        const lost = job.state === 'LOST'
        return {
          ok: !lost,
          jobId: job.id,
          state: job.state,
          elapsedMs: (job.stoppedAt ?? Date.now()) - job.startedAt,
          bytes: job.bytes,
          message: lost
            ? 'job stopped, but the remote shell could NOT be re-verified; the session collapsed to UNKNOWN - reconnect before running anything else'
            : 'job stopped; the shell was re-verified and is available again',
        } as unknown as ResultValue
      }))
    },
  )

  server.registerTool(
    'jumpserver_jobs',
    {
      description: 'List streaming jobs of this conversation (id, target, command, state, elapsed, buffered bytes).',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_jobs', callId: extra.requestId, signal: extra.signal , sessionId: extra.sessionId, confirm: false }
      return toolTextRaw(await guardText(exec, async (): Promise<string> => {
        const jobs = runtime.jobs.list()
        if (jobs.length === 0) return 'jobs=0 (没有流式任务)'
        return ['jobs=' + jobs.length, ...jobs.map((j) =>
          [j.id, j.state, j.target, (j.hostname ?? '?'), String(Date.now() - j.startedAt) + 'ms', j.bytes + 'B', redactCommandSecrets(j.command)].join(' | '),
        )].join('\n')
      }))
    },
  )
}

function render(value: ResultValue): string {
  const lines: string[] = []
  if (value.code !== undefined) lines.push('code: ' + String(value.code))
  if (value.message !== undefined) lines.push(String(value.message))
  return lines.join('\n')
}

/** Compact model-facing projection of a runbook run. */
export function renderRunbook(result: RunbookResult): string {
  const lines: string[] = []
  lines.push(
    'ok runbook=' + result.runbook + (result.title !== null ? ' (' + result.title + ')' : '') +
      ' steps=' + String(result.plan.runnable) + ' skipped=' + String(result.plan.skipped) +
      ' targets=' + String(result.targets) + ' reachable=' + String(result.reachable) +
      ' durationMs=' + String(result.durationMs),
  )
  if (result.verdict !== null) {
    lines.push(
      'verdict: ' + result.verdict.toUpperCase() +
        ' (asserted steps=' + String(result.plan.asserted) +
        ', targets passed=' + String(result.passed) + ' failed=' + String(result.failed) + ')',
    )
  }
  for (const warning of result.warnings) lines.push('note: ' + warning)
  for (const target of result.results) {
    lines.push('')
    lines.push(
      '== ' + target.target + (target.hostname !== null ? '  ' + target.hostname : '') +
        (target.verdict !== null ? '  [' + target.verdict.toUpperCase() + ']' : '') + ' ==',
    )
    if (target.error !== null) {
      lines.push('  !! 失败: ' + target.error.code + ': ' + target.error.message)
      continue
    }
    for (const step of target.steps) {
      const head = '  [' + step.id + ']' + (step.title !== null ? ' ' + step.title : '') +
        (step.kind === 'profile' ? ' (profile ' + step.source + ', ' + String(step.commands.length) + ' probes)' : '') +
        ' exit=' + (step.exitCode ?? '?') + ' ' + step.durationMs + 'ms' + (step.truncated ? ' (truncated)' : '') +
        (step.check !== null ? ' -> ' + step.check.verdict.toUpperCase() : '')
      lines.push(head)
      if (step.check !== null && step.check.verdict === 'fail') {
        for (const failure of step.check.failures) lines.push('    x ' + failure)
      }
      if (step.error !== null) {
        lines.push('    !! ' + step.error.code + ': ' + step.error.message)
        continue
      }
      // V0.4.3: a profile step is ONE row; its per-probe output is nested so
      // the model still sees every probe without the step being repeated.
      if (step.kind === 'profile' && step.commands.length > 1) {
        for (const cmd of step.commands) {
          const probeHead = '    - ' + (cmd.probe ?? '?') + ': ' + cmd.command +
            ' exit=' + (cmd.exitCode ?? '?')
          lines.push(probeHead)
          if (cmd.error !== null) {
            lines.push('      !! ' + cmd.error.code + ': ' + cmd.error.message)
            continue
          }
          const probeBody = cmd.output.trim()
          lines.push(probeBody.length > 0 ? indent(probeBody, '      ') : '      (无输出)')
        }
        continue
      }
      const body = step.output.trim()
      lines.push(body.length > 0 ? indent(body, '    ') : '    (无输出)')
    }
  }
  return lines.join('\n')
}

function indent(text: string, prefix: string): string {
  return text.split('\n').map((line) => prefix + line).join('\n')
}

/** Project a full HostInventory down to the compact baseline shape. */
export function toBaselineHost(inv: HostInventory): BaselineHost {
  return {
    target: inv.target,
    hostname: inv.hostname,
    reachable: inv.reachable,
    error: inv.error,
    os: inv.os.name !== null ? [inv.os.name, inv.os.version].filter(Boolean).join(' ') : null,
    kernel: inv.kernel,
    cores: inv.cores,
    memoryTotalMb: inv.memory.totalMb,
    memoryUsedPct: inv.memory.usedPct,
    load: inv.load,
    disks: inv.disks.map((d) => ({ mount: d.mount, usePct: d.usePct })),
    listening: inv.listening.map((l) => ({ port: l.port, process: l.process })),
    services: inv.services,
    roles: inv.roles,
  }
}

/** Compact model-facing projection of a baseline drift report. */
export function renderDrift(drift: DriftResult, warnings: string[] = []): string {
  const lines: string[] = []
  lines.push(
    'ok baseline=' + drift.baseline + ' createdAt=' + drift.createdAt + ' comparedAt=' + drift.comparedAt +
      ' changed=' + String(drift.changed) + ' unchanged=' + String(drift.unchanged) + ' unreachable=' + String(drift.unreachable),
  )
  for (const warning of warnings) lines.push('note: ' + warning)
  if (drift.changed === 0 && drift.unreachable === 0) {
    lines.push('(未检测到漂移：所有目标状态与基线一致)')
  }
  for (const host of drift.hosts) {
    if (host.status === 'unchanged') continue
    lines.push('')
    lines.push('== ' + host.target + ' [' + host.status + '] ==')
    for (const change of host.changes) {
      lines.push('  ' + change.field + ': ' + change.before + '  ->  ' + change.after)
    }
  }
  if (drift.unchanged > 0) {
    const unchanged = drift.hosts.filter((h) => h.status === 'unchanged').map((h) => h.target)
    lines.push('')
    lines.push('未变化: ' + unchanged.join(', '))
  }
  return lines.join('\n')
}

/** Compact model-facing projection of a comparison. */
export function renderCompare(result: CompareResult): string {
  const lines: string[] = []
  lines.push(
    'ok compare mode=' + result.mode + ' source=' + redactCommandSecrets(result.source) +
      ' targets=' + String(result.targets) + ' ok=' + String(result.succeeded) + ' failed=' + String(result.failed) +
      ' distinct=' + String(result.distinct) +
      (result.distinct <= 1 ? ' (全部一致)' : ' (' + String(result.distinct) + ' 组差异)') +
      ' durationMs=' + String(result.durationMs),
  )
  for (const warning of result.warnings) lines.push('note: ' + warning)
  if (result.succeeded === 0) {
    lines.push('(没有可比对的目标：全部失败)')
    return lines.join('\n')
  }
  result.groups.forEach((group, index) => {
    lines.push('')
    lines.push('--- 组 ' + String(index + 1) + (index === 0 ? ' (多数派)' : '') + ' 目标: ' +
      (group.outliers.length > 0 ? group.outliers.map((o) => o.target).join(', ') : '(多数派全部成员)') +
      ' 共 ' + String(group.signature.length) + ' 行 ---')
    const shown = group.signature.slice(0, 40)
    for (const line of shown) lines.push('  ' + line)
    if (group.signature.length > shown.length) lines.push('  ... 省略 ' + String(group.signature.length - shown.length) + ' 行')
    for (const outlier of group.outliers) {
      lines.push('  [' + outlier.target + '] 差异:')
      for (const line of outlier.missing.slice(0, 20)) lines.push('    - ' + line)
      for (const line of outlier.extra.slice(0, 20)) lines.push('    + ' + line)
      const hidden = Math.max(0, outlier.missing.length - 20) + Math.max(0, outlier.extra.length - 20)
      if (hidden > 0) lines.push('    ... 省略 ' + String(hidden) + ' 行差异')
    }
  })
  const failures = result.results.filter((r) => !r.ok)
  if (failures.length > 0) {
    lines.push('')
    lines.push('--- 失败目标 ---')
    for (const failure of failures) {
      lines.push('  ' + failure.target + ': ' + (failure.error !== null ? failure.error.code + ': ' + failure.error.message : '?'))
    }
  }
  return lines.join('\n')
}

function tailSince(output: string, maxChars: number): string {
  return output.length <= maxChars ? output : output.slice(output.length - maxChars)
}

/** Resolve explicit targets or a configured asset group into a target list. */
async function resolveTargets(
  host: ToolHost,
  bundle: { manager: import('../jumpserver/session-manager.js').SessionManager },
  exec: ToolRunContext,
  targets: string[] | undefined,
  group: string | undefined,
): Promise<string[]> {
  const explicit = (targets ?? []).map((t) => String(t).trim()).filter((t) => t.length > 0)
  if (group === undefined || group.length === 0) {
    if (explicit.length === 0) throw new JumpServerError('ASSET_NOT_FOUND', 'provide targets[] or group')
    return explicit
  }
  const listing = await bundle.manager.listAssets(undefined, exec.signal, false, group)
  const resolved = listing.assets.map((a) => (a.ip !== null && a.ip.length > 0 ? a.ip : a.name)).filter((t) => t.length > 0)
  if (resolved.length === 0) {
    throw new JumpServerError('ASSET_NOT_FOUND', 'asset group "' + group + '" matched no assets')
  }
  return [...new Set([...explicit, ...resolved])]
}

/** Compact one-host projection (the model-facing default). */
export function renderInventory(inv: HostInventory): string {
  const lines: string[] = []
  const head = inv.target + (inv.hostname !== null ? '  ' + inv.hostname : '')
  lines.push(head)
  if (!inv.reachable) {
    lines.push('  !! 不可达: ' + (inv.error ?? '?'))
    return lines.join('\n')
  }
  const facts: string[] = []
  if (inv.os.name !== null) facts.push('OS=' + [inv.os.name, inv.os.version].filter(Boolean).join(' '))
  if (inv.kernel !== null) facts.push('内核=' + inv.kernel)
  if (inv.uptime !== null) facts.push('up=' + inv.uptime)
  if (inv.load !== null) facts.push('load=' + inv.load.join('/'))
  if (inv.cores !== null) facts.push('cores=' + inv.cores)
  if (inv.memory.usedPct !== null) facts.push('mem=' + inv.memory.usedPct + '% (' + inv.memory.usedMb + '/' + inv.memory.totalMb + 'MB)')
  if (facts.length > 0) lines.push('  ' + facts.join('  '))
  lines.push('  角色: ' + (inv.roles.length > 0 ? inv.roles.join(', ') : '未识别'))
  if (inv.listening.length > 0) {
    lines.push('  监听: ' + inv.listening.map((l) => l.port + (l.process !== null ? '(' + l.process + ')' : '')).join(', '))
  }
  const top = [...inv.processes].sort((a, b) => (b.cpu ?? 0) - (a.cpu ?? 0)).slice(0, 6)
  if (top.length > 0) {
    lines.push('  进程(top CPU):')
    for (const p of top) lines.push('    ' + p.pid + '  cpu=' + (p.cpu ?? '?') + '% mem=' + (p.mem ?? '?') + '%  ' + p.cmd.slice(0, 120))
  }
  if (inv.connections.length > 0) {
    const counts = new Map<string, number>()
    for (const c of inv.connections) {
      const key = c.remoteIp + (c.remotePort !== null ? ':' + c.remotePort : '')
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    lines.push('  出向连接: ' + [...counts.entries()].slice(0, 10).map(([k, n]) => k + ' x' + n).join(', '))
  }
  if (inv.nginx !== null) {
    const upstreams = inv.nginx.upstreams.map((u) => u.name + '=[' + u.servers.map((s) => s.host + (s.port !== null ? ':' + s.port : '')).join(', ') + ']')
    if (upstreams.length > 0) lines.push('  nginx upstream: ' + upstreams.join('  '))
    if (inv.nginx.proxies.length > 0) lines.push('  proxy_pass: ' + inv.nginx.proxies.slice(0, 8).join('  '))
  }
  if (inv.java.length > 0) lines.push('  java: ' + inv.java.slice(0, 6).map((j) => j.pid + ' ' + (j.main ?? '?')).join(', '))
  if (inv.containers.length > 0) lines.push('  containers: ' + inv.containers.slice(0, 8).map((c) => c.name + '(' + c.image + ')').join(', '))
  const hot = inv.disks.filter((d) => (d.usePct ?? 0) >= 80)
  if (hot.length > 0) lines.push('  磁盘告警: ' + hot.map((d) => d.mount + ' ' + d.usePct + '%').join(', '))
  return lines.join('\n')
}
