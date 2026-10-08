/**
 * Permission gate — ported from dsh-jumpserver src/security/permission-gate.ts.
 * The DSH ApprovalService is replaced by MCP-idiomatic confirm: the first
 * attempt of an approval-required command returns COMMAND_APPROVAL_REQUIRED
 * with the full (redacted) approval reason; the model shows it to the user and
 * retries the same call with confirm:true ONLY after the user agrees.
 */
import type { CommandRisk, PermissionMode, RiskJudgeAutoAllowConfig, RiskJudgeConfig } from '../config/types.js'
import { APPROVAL_DENIED_REASON, JumpServerError } from '../jumpserver/errors.js'
import type { SessionManager } from '../jumpserver/session-manager.js'
import { redactCommandSecrets } from './command-redaction.js'
import { classifyCommand, gateDecision, requireTargetVerified, type Classification } from './permission.js'
import {
  decideAutoAllow,
  judgeCommandRisk,
  riskJudgeAuditLine,
  riskJudgeNote,
  riskJudgeSummary,
  type RiskJudgeVerdict,
} from './risk-judge.js'
import type { ToolRunContext } from '../runtime/context.js'

export interface GateServices {
  getConfig: () => {
    permissionMode: PermissionMode
    privilegedReadInReadOnly?: boolean
    riskJudge?: RiskJudgeConfig
  }
  manager: SessionManager
}

export interface GatedCommand {
  risk: CommandRisk
  /** Full classification (ruleId/reason/confidence) — audit + approval copy. */
  classification: Classification
  /** True when this gated command required a human approval (for the audit). */
  approvalRequired: boolean
  /** Runs right after navigation (run/batch): verify target, then ask. */
  beforeExec?: () => Promise<void>
  /** V0.5.8: the judge's opinion, when the classifier could not rule. */
  judge?: RiskJudgeVerdict
  /** V0.5.8: true when that opinion let this command skip the human prompt. */
  judgeAutoAllowed?: boolean
  /** V0.5.8: one-line record of the judge decision (audit + tool result). */
  judgeNote?: string
}

/** Approval text never exposes command-line secrets. */
function approvalReason(
  status: { target: string | null; hostname: string | null },
  command: string,
  classification: Classification,
  judgeLines: string[] = [],
): string {
  const target = '目标服务器：' + (status.target ?? '?') + ' / ' + (status.hostname ?? 'unknown host')
  const safeCommand = redactCommandSecrets(command)
  const lines: string[] = [target, '准备执行：' + safeCommand, '']
  switch (classification.risk) {
    case 'UNKNOWN':
      lines.push('风险：无法确认该命令是否为只读（规则 ' + classification.ruleId + '）')
      lines.push('原因：当前分类器没有足够语义规则，不能确认它是否修改服务器。')
      if (judgeLines.length > 0) {
        lines.push('')
        for (const line of judgeLines) lines.push(line)
      }
      lines.push('这不代表命令一定会修改服务器——是否允许本次执行？')
      break
    case 'MODIFY':
      lines.push('风险：修改操作（规则 ' + classification.ruleId + '）')
      lines.push('原因：' + (classification.reason || '识别为修改命令') + '。')
      lines.push('该命令会改变服务器运行状态，是否执行？')
      break
    case 'DANGEROUS':
      lines.push('风险：高危操作（规则 ' + classification.ruleId + '）')
      lines.push('原因：该命令可能造成服务中断、数据破坏或系统不可用。')
      lines.push('是否仍然执行？')
      break
    case 'PRIVILEGED_READ':
      lines.push('风险：特权只读（需要 sudo/root，规则 ' + classification.ruleId + '）')
      lines.push('原因：' + (classification.reason || 'privileged read') + '。')
      lines.push('是否允许本次执行？')
      break
    default:
      lines.push('风险：' + classification.risk + '（规则 ' + classification.ruleId + '）')
      lines.push('原因：' + (classification.reason || '') + '。是否执行？')
  }
  return lines.join('\n')
}

function batchApprovalReason(
  status: { target: string | null; hostname: string | null },
  items: Array<{ command: string; classification: Classification; judgeLines?: string[] }>,
): string {
  const lines = [
    '目标服务器：' + (status.target ?? '?') + ' / ' + (status.hostname ?? 'unknown host'),
    '本批次有 ' + items.length + ' 条命令需要人工审批：',
    '',
  ]
  for (let i = 0; i < items.length; i++) {
    const item = items[i]!
    lines.push(String(i + 1) + '. [' + item.classification.risk + '] ' + redactCommandSecrets(item.command))
    lines.push('   规则：' + item.classification.ruleId + ' · ' + item.classification.reason)
    if (item.judgeLines !== undefined) for (const line of item.judgeLines) lines.push('   ' + line)
  }
  lines.push('', '允许后仅执行上面列出的本批次命令；是否允许？')
  return lines.join('\n')
}

function approvalDenied(exec: ToolRunContext, reason: string): JumpServerError {
  return new JumpServerError(
    'COMMAND_APPROVAL_REQUIRED',
    reason +
      '\n\n[NOT EXECUTED] Ask the user to review the command(s) above. Only retry the SAME call with confirm:true after the user explicitly agrees.',
  )
}

async function requestApproval(services: GateServices, exec: ToolRunContext, reason: string): Promise<void> {
  void services
  if (exec.confirm) return
  throw approvalDenied(exec, reason)
}

async function askApproval(
  services: GateServices,
  exec: ToolRunContext,
  command: string,
  classification: Classification,
  verdict: RiskJudgeVerdict | null = null,
  noteOptions: { autoAllowEnabled?: boolean; autoAllowRefusal?: string } = {},
): Promise<void> {
  const status = services.manager.status()
  await requestApproval(
    services,
    exec,
    approvalReason(status, command, classification, riskJudgeNote(verdict, noteOptions)),
  )
}

/**
 * V0.5.7 advisory second opinion for one UNKNOWN command.
 *
 * Called ONLY right before an approval prompt is built: a command that is
 * blocked outright needs no reading, and READ / PRIVILEGED_READ / MODIFY /
 * DANGEROUS are never sent anywhere. Every failure — judge disabled, no
 * credential, timeout, bad payload — yields null, so the prompt keeps exactly
 * the text it has today and the gate never depends on a remote service.
 */
async function judgeUnknown(services: GateServices, classification: Classification): Promise<RiskJudgeVerdict | null> {
  if (classification.risk !== 'UNKNOWN') return null
  try {
    return await judgeCommandRisk(classification.command, services.getConfig().riskJudge)
  } catch {
    return null
  }
}

function autoAllowConfig(services: GateServices): RiskJudgeAutoAllowConfig | undefined {
  return services.getConfig().riskJudge?.autoAllow
}

/**
 * V0.5.8: apply the (opt-in, fail-closed) auto-allow guard to one pending
 * UNKNOWN command. Returns the decision plus the audit line, so the caller can
 * record WHY a command ran unattended.
 *
 * Ordering matters: the target is verified by the caller BEFORE this runs, so
 * an auto-allowed command is never executed against an unverified asset.
 */
function applyJudge(
  services: GateServices,
  classification: Classification,
  verdict: RiskJudgeVerdict | null,
): { auto: boolean; reason: string; note?: string } {
  const config = autoAllowConfig(services)
  const decision = decideAutoAllow(verdict, { command: classification.command, ruleId: classification.ruleId }, config)
  if (decision.allow) {
    return {
      auto: true,
      reason: decision.reason,
      note: verdict === null ? undefined : riskJudgeAuditLine(verdict, true, decision.reason),
    }
  }
  if (verdict === null) return { auto: false, reason: decision.reason }
  return { auto: false, reason: decision.reason, note: riskJudgeAuditLine(verdict, false, decision.reason) }
}

/**
 * V0.5.8: one line reporting the commands that ran WITHOUT a human prompt
 * because the judge allowed them, plus the verdict that allowed it. Undefined
 * when nothing was auto-allowed, so an unremarkable call renders as before.
 */
export function judgeAutoAllowNote(gated: GatedCommand[]): string | undefined {
  const allowed = gated.filter((item) => item.judgeAutoAllowed === true && item.judgeNote !== undefined)
  if (allowed.length === 0) return undefined
  return (
    allowed.length + ' 条命令经 Jev 语义判定自动放行（未询问人工）: ' + allowed.map((item) => item.judgeNote).join(' | ')
  )
}

/**
 * V0.5.9: leave a trace before a refusal turns into an exception.
 *
 * Best-effort on purpose: the audit sink must never be able to change what the
 * gate does, so a write failure is swallowed and the refusal proceeds.
 */
async function recordRefusal(
  services: GateServices,
  exec: ToolRunContext,
  input: {
    operation: string
    command: string
    classification: Classification
    reason: string
    kind: 'blocked' | 'denied'
    riskJudge?: string
    batchId?: string
    batchIndex?: number
  },
): Promise<void> {
  try {
    await services.manager.recordDenied({
      operation: input.operation,
      command: input.command,
      risk: input.classification.risk,
      classification: input.classification,
      reason: input.reason,
      kind: input.kind,
      riskJudge: input.riskJudge,
      toolCallId: String(exec.callId),
      batchId: input.batchId,
      batchIndex: input.batchIndex,
    })
  } catch {
    /* never let an audit failure alter the gate's decision */
  }
}

function verifyTarget(services: GateServices): void {
  const status = services.manager.status()
  requireTargetVerified({ state: status.state, currentTarget: status.target, currentHostname: status.hostname })
}

/** Gate for jumpserver_exec: session is already in ASSET_SHELL. */
export async function gateCommand(services: GateServices, exec: ToolRunContext, command: string): Promise<GatedCommand> {
  const cfg = services.getConfig()
  const classification = classifyCommand(command)
  const decision = gateDecision(classification.risk, cfg.permissionMode, { privilegedReadInReadOnly: cfg.privilegedReadInReadOnly })
  if (decision.kind === 'allow') return { risk: classification.risk, classification, approvalRequired: false }
  if (classification.risk === 'MODIFY' || classification.risk === 'DANGEROUS' || classification.risk === 'UNKNOWN') {
    verifyTarget(services)
  }
  if (decision.code === 'COMMAND_APPROVAL_REQUIRED') {
    const verdict = await judgeUnknown(services, classification)
    const judge = applyJudge(services, classification, verdict)
    if (judge.auto) {
      return {
        risk: classification.risk,
        classification,
        approvalRequired: false,
        judge: verdict ?? undefined,
        judgeAutoAllowed: true,
        judgeNote: judge.note,
      }
    }
    try {
      await askApproval(services, exec, command, classification, verdict, {
        autoAllowEnabled: autoAllowConfig(services)?.enabled === true,
        autoAllowRefusal: judge.reason,
      })
    } catch (error) {
      // V0.5.9: exec's approval runs inline (exec has no beforeExec), so this is
      // the only place a DENIED record can come from on the exec path.
      if (error instanceof JumpServerError && error.code === 'COMMAND_APPROVAL_REQUIRED') {
        await recordRefusal(services, exec, {
          operation: 'exec',
          command,
          classification,
          reason: APPROVAL_DENIED_REASON,
          kind: 'denied',
          riskJudge: judge.note,
        })
      }
      throw error
    }
    return {
      risk: classification.risk,
      classification,
      approvalRequired: true,
      judge: verdict ?? undefined,
      judgeNote: judge.note,
    }
  }
  // V0.5.9: a rule refusal is recorded, not only thrown — "who tried to run
  // what, and was stopped" is exactly what an audit trail is for.
  await recordRefusal(services, exec, {
    operation: 'exec',
    command,
    classification,
    reason: decision.reason,
    kind: 'blocked',
  })
  throw new JumpServerError('COMMAND_BLOCKED', command + ' -- ' + decision.reason)
}

/**
 * Gate for jumpserver_run: navigation happens inside manager.run, so target
 * verification + approval are deferred until the requested asset is entered.
 */
export async function gateCommandForNavigation(services: GateServices, exec: ToolRunContext, command: string): Promise<GatedCommand> {
  const cfg = services.getConfig()
  const classification = classifyCommand(command)
  const decision = gateDecision(classification.risk, cfg.permissionMode, { privilegedReadInReadOnly: cfg.privilegedReadInReadOnly })
  if (decision.kind === 'allow') return { risk: classification.risk, classification, approvalRequired: false }
  if (decision.code === 'COMMAND_BLOCKED') {
    await recordRefusal(services, exec, {
      operation: 'run',
      command,
      classification,
      reason: decision.reason,
      kind: 'blocked',
    })
    throw new JumpServerError('COMMAND_BLOCKED', command + ' -- ' + decision.reason)
  }
  const verdict = await judgeUnknown(services, classification)
  const judge = applyJudge(services, classification, verdict)
  const autoAllowEnabled = autoAllowConfig(services)?.enabled === true
  if (judge.auto) {
    return {
      risk: classification.risk,
      classification,
      approvalRequired: false,
      judge: verdict ?? undefined,
      judgeAutoAllowed: true,
      judgeNote: judge.note,
      // Verification is NOT skipped for an auto-allowed command: it is the
      // reason the approval existed, and it is cheap.
      beforeExec: async () => {
        verifyTarget(services)
      },
    }
  }
  return {
    risk: classification.risk,
    classification,
    approvalRequired: true,
    judge: verdict ?? undefined,
    judgeNote: judge.note,
    beforeExec: async () => {
      verifyTarget(services)
      await askApproval(services, exec, command, classification, verdict, {
        autoAllowEnabled,
        autoAllowRefusal: judge.reason,
      })
    },
  }
}

/**
 * Batch gate for one target (ported unchanged from the DSH plugin): confirmed
 * READs never appear in an approval; 2-10 short approval-required commands
 * share ONE target-verified prompt; DANGEROUS items stay explicitly visible.
 */
export async function gateCommandsForNavigation(
  services: GateServices,
  exec: ToolRunContext,
  commands: string[],
): Promise<GatedCommand[]> {
  const cfg = services.getConfig()
  // V0.5.9: a plain for-loop, not map() — a refusal has to reach the audit
  // BEFORE it is thrown, and that needs an await inside the iteration.
  const gated: { command: string; gated: GatedCommand }[] = []
  for (const command of commands) {
    const classification = classifyCommand(command)
    const decision = gateDecision(classification.risk, cfg.permissionMode, { privilegedReadInReadOnly: cfg.privilegedReadInReadOnly })
    if (decision.kind === 'allow') {
      gated.push({ command, gated: { risk: classification.risk, classification, approvalRequired: false } })
      continue
    }
    if (decision.code === 'COMMAND_BLOCKED') {
      await recordRefusal(services, exec, {
        operation: 'run-batch',
        command,
        classification,
        reason: decision.reason,
        kind: 'blocked',
      })
      throw new JumpServerError('COMMAND_BLOCKED', command + ' -- ' + decision.reason)
    }
    gated.push({ command, gated: { risk: classification.risk, classification, approvalRequired: true } })
  }

  const approvalItems = gated.filter((item) => item.gated.approvalRequired)
  if (approvalItems.length === 0) return gated.map((item) => item.gated)

  /**
   * V0.5.7: advisory verdicts for the UNKNOWN items of this batch, fetched in
   * parallel (one round trip each, cached per command). Rendered into the
   * prompt only — the gate decisions above are already final and the copy says
   * so. `riskJudge.enabled:false` resolves to null without any request.
   * V0.5.8: the same verdicts then feed the auto-allow guard, which can drop
   * an item out of the prompt entirely.
   */
  const verdicts = new Map<object, RiskJudgeVerdict | null>()
  await Promise.all(
    approvalItems.map(async (item) => {
      verdicts.set(item, await judgeUnknown(services, item.gated.classification))
    }),
  )

  const autoAllowEnabled = autoAllowConfig(services)?.enabled === true
  const refusals = new Map<object, string>()
  const stillPending: typeof approvalItems = []
  for (const item of approvalItems) {
    const verdict = verdicts.get(item) ?? null
    const judge = applyJudge(services, item.gated.classification, verdict)
    item.gated.judge = verdict ?? undefined
    item.gated.judgeNote = judge.note
    if (judge.auto) {
      item.gated.approvalRequired = false
      item.gated.judgeAutoAllowed = true
      // Target verification survives the skipped prompt (see gateCommandForNavigation).
      item.gated.beforeExec = async () => {
        verifyTarget(services)
      }
      continue
    }
    refusals.set(item, judge.reason)
    stillPending.push(item)
  }
  if (stillPending.length === 0) return gated.map((item) => item.gated)

  const judgeLinesFor = (item: { command: string }): string[] | undefined => {
    const verdict = verdicts.get(item) ?? null
    if (verdict === null) return undefined
    if (!autoAllowEnabled) return ['语义副驾：' + riskJudgeSummary(verdict) + '（仅供参考，不参与放行判定）']
    const refusal = refusals.get(item) ?? ''
    return ['语义副驾：' + riskJudgeSummary(verdict) + ' · 自动放行未通过：' + refusal]
  }

  const canGroup = stillPending.length >= 2 && stillPending.length <= 10 && stillPending.every((item) => redactCommandSecrets(item.command).length <= 500)
  if (!canGroup) {
    for (const item of stillPending) {
      item.gated.beforeExec = async () => {
        verifyTarget(services)
        await askApproval(services, exec, item.command, item.gated.classification, verdicts.get(item) ?? null, {
          autoAllowEnabled,
          autoAllowRefusal: refusals.get(item) ?? '',
        })
      }
    }
    return gated.map((item) => item.gated)
  }

  let state: 'pending' | 'approved' | 'failed' = 'pending'
  let failure: unknown
  const approveGroup = async (): Promise<void> => {
    if (state === 'approved') return
    if (state === 'failed') throw failure
    verifyTarget(services)
    try {
      const status = services.manager.status()
      await requestApproval(
        services,
        exec,
        batchApprovalReason(
          status,
          stillPending.map((item) => ({
            command: item.command,
            classification: item.gated.classification,
            judgeLines: judgeLinesFor(item),
          })),
        ),
      )
      state = 'approved'
    } catch (error) {
      state = 'failed'
      failure = error
      throw error
    }
  }
  for (const item of stillPending) item.gated.beforeExec = approveGroup
  return gated.map((item) => item.gated)
}
