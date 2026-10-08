import { z } from 'zod'
import type { AuditRecord } from '../jumpserver/session-manager.js'

/** zod record schema for the storageDomain audit table. */
export const auditRecordSchema = z.object({
  timestamp: z.string(),
  operation: z.string(),
  gateway: z.string(),
  target: z.string().nullable(),
  hostname: z.string().nullable(),
  command: z.string().nullable(),
  redactedCommand: z.string().optional(),
  normalizedRedactedCommand: z.string().optional(),
  /** V0.3.1: AGENT | HUMAN | SYSTEM_PROFILE; default AGENT keeps records written pre-0.3.1 readable. */
  actor: z.string().default('AGENT'),
  risk: z.string(),
  /** V0.3.1: classifier explainability — why this risk, which semantic rule. */
  riskReason: z.string().optional(),
  riskRuleId: z.string().optional(),
  riskConfidence: z.string().optional(),
  classifierVersion: z.number().optional(),
  normalizedCommand: z.string().optional(),
  /** V0.3.1: approval gate outcomes. */
  approvalRequired: z.boolean().default(false),
  approvalResult: z.string().default('none'),
  /**
   * V0.5.8: the semantic judge's verdict on a command the rule classifier
   * could not rule on. Prefixed AUTO_ALLOWED when that verdict let the command
   * run without a human round-trip — the audit must show not only what ran but
   * WHO decided it was safe.
   */
  riskJudge: z.string().optional(),
  /**
   * V0.5.9: why a refused command was refused. Set on BLOCKED (the rules said
   * no) and DENIED (no human approval) records.
   */
  refusalReason: z.string().optional(),
  /** V0.4.0: AI task correlation (one MCP request / batch / job). */
  toolCallId: z.string().optional(),
  batchId: z.string().optional(),
  taskId: z.string().optional(),
  sequence: z.number().optional(),
  batchIndex: z.number().optional(),
  permissionMode: z.string(),
  result: z.string(),
  exitCode: z.number().nullable(),
  durationMs: z.number().nullable(),
})

export type StructuredAuditRecord = z.infer<typeof auditRecordSchema>

export function toStructuredAuditRecord(record: AuditRecord): StructuredAuditRecord {
  return auditRecordSchema.parse(record)
}

/** Simple monotonic sequence for record keys within one process. */
let recordSeq = 0
export function nextAuditKey(timestampIso: string): string {
  recordSeq += 1
  return timestampIso + ':' + recordSeq.toString(36).padStart(4, '0')
}
