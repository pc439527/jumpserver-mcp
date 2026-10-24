import { splitSegments } from './command-classifier.js'
import { classifyCommand } from './permission.js'
import { redactCommandSecrets } from './command-redaction.js'

/** 仅提供诊断候选，不承诺拆分后与原命令等价或可直接放行。 */
export function splitSuggestion(command: string): string | undefined {
  // 管道、条件、替换与 shell 结构存在执行依赖，不提供可复制的伪等价拆分。
  if (/[|&`$(){}<>\n]/.test(command) || /\b(?:if|then|for|while|until|case|do|done|fi)\b/.test(command)) return undefined
  try {
    const parts = splitSegments(command).map((part) => part.trim()).filter(Boolean)
    if (parts.length < 2) return undefined
    return [
      '拆分诊断建议（不等价执行保证）：各段可能依赖前段的目录、变量或状态；请先人工核对语义，每条重新提交完整门禁，不保证可直接执行。',
      ...parts.map((part, index) => String(index + 1) + '. [' + classifyCommand(part).risk + '] ' + redactCommandSecrets(part)),
    ].join('\n')
  } catch {
    return undefined
  }
}
