import { createHash } from 'node:crypto'
import { appendFileSync, readFileSync } from 'node:fs'

export function auditFeedbackId(record: Record<string, unknown>): string {
  return createHash('sha256').update(JSON.stringify(record)).digest('hex')
}

export interface AuditFeedback {
  recordId: string
  falsePositive: boolean
  timestamp: string
  actor: 'HUMAN'
}

/** 反馈仅记录人工标签，不存命令、凭据或自由文本，也不参与权限决策。 */
export class AuditFeedbackStore {
  constructor(private readonly file: string) {}

  list(): AuditFeedback[] {
    let text: string
    try { text = readFileSync(this.file, 'utf8') } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw new Error('FEEDBACK_UNAVAILABLE')
    }
    const latest = new Map<string, AuditFeedback>()
    for (const line of text.split('\n')) {
      if (!line.trim()) continue
      let value: AuditFeedback
      try { value = JSON.parse(line) as AuditFeedback } catch { throw new Error('FEEDBACK_UNAVAILABLE') }
      if (!/^[a-f0-9]{64}$/.test(value.recordId) || typeof value.falsePositive !== 'boolean' || value.actor !== 'HUMAN' || typeof value.timestamp !== 'string') throw new Error('FEEDBACK_UNAVAILABLE')
      latest.set(value.recordId, { recordId: value.recordId, falsePositive: value.falsePositive, timestamp: value.timestamp, actor: 'HUMAN' })
    }
    return [...latest.values()]
  }

  set(recordId: string, falsePositive: boolean): void {
    if (!/^[a-f0-9]{64}$/.test(recordId) || typeof falsePositive !== 'boolean') throw new Error('INVALID_FEEDBACK')
    this.list()
    appendFileSync(this.file, JSON.stringify({ recordId, falsePositive, timestamp: new Date().toISOString(), actor: 'HUMAN' }) + '\n', { encoding: 'utf8', mode: 0o600 })
  }
}
