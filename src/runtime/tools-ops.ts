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
import { requireTargetAllowed } from '../security/target-scope.js'
import { classifyCommand } from '../security/permission.js'
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
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_inspect', callId: extra.requestId, signal: extra.signal, confirm: false }
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
      },
      annotations: { readOnlyHint: true },
    },
    async (args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_topology', callId: extra.requestId, signal: extra.signal, confirm: false }
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

  // ------------------------------------------------------------- interrupt
  server.registerTool(
    'jumpserver_interrupt',
    {
      description:
        'Send Ctrl+C to the remote shell NOW to interrupt whatever is running (a stuck command, a tail that will not end, a long find). Out-of-band: it does NOT wait for the current operation to finish. Afterwards the connector re-probes the shell and reports whether it is usable again (ASSET_SHELL) or collapsed to UNKNOWN. Use it instead of jumpserver_close when you only want to stop the remote job and keep the session.',
      inputSchema: {},
    },
    async (_args, extra) => {
      const exec: ToolRunContext = { name: 'jumpserver_interrupt', callId: extra.requestId, signal: extra.signal, confirm: false }
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
      const exec: ToolRunContext = { name: 'jumpserver_job_start', callId: extra.requestId, signal: extra.signal, confirm: args.confirm === true }
      return toolText(await guardValue(exec, async (): Promise<ResultValue> => {
        const blocked = host.requireGrant(exec)
        if (blocked !== null) return blocked
        requireTargetAllowed(host.getConfig(), args.target)
        const classification = classifyCommand(args.command)
        if (classification.risk !== 'READ' && exec.confirm !== true) {
          throw new JumpServerError(
            'COMMAND_APPROVAL_REQUIRED',
            '【未执行】流式任务命令被分类为 ' + classification.risk + '（规则 ' + classification.ruleId + '：' + classification.reason + '）。\n' +
              '目标：' + args.target + '\n命令：' + redactCommandSecrets(args.command) + '\n' +
              '确认后请用同样的参数并带上 confirm:true 重试；否则请改用只读命令（如 tail -f / journalctl -f）。',
          )
        }
        const job = await runtime.jobs.start({
          sessionId: host.sessionIdOf(exec),
          target: args.target,
          command: args.command,
          maxDurationMs: args.maxDuration !== undefined ? args.maxDuration * 1000 : undefined,
          signal: exec.signal,
          toolCallId: String(exec.callId),
        })
        return {
          ok: true,
          jobId: job.id,
          target: job.target,
          hostname: job.hostname,
          state: job.state,
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
      const exec: ToolRunContext = { name: 'jumpserver_job_read', callId: extra.requestId, signal: extra.signal, confirm: false }
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
      const exec: ToolRunContext = { name: 'jumpserver_job_stop', callId: extra.requestId, signal: extra.signal, confirm: false }
      return toolText(await guardValue(exec, async (): Promise<ResultValue> => {
        const job = await runtime.jobs.stop(args.jobId)
        return {
          ok: true,
          jobId: job.id,
          state: job.state,
          elapsedMs: (job.stoppedAt ?? Date.now()) - job.startedAt,
          bytes: job.bytes,
          message: 'job stopped; the shell is available again',
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
      const exec: ToolRunContext = { name: 'jumpserver_jobs', callId: extra.requestId, signal: extra.signal, confirm: false }
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
