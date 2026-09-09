import type { Classification } from './command-classifier.js'
import { CLASSIFIER_VERSION } from './command-classifier.js'
import type { CommandRisk } from '../config/types.js'

/**
 * Semantic classifier for mysql/mariadb CLI commands.
 *
 * The generic shell classifier intentionally treats unknown executables as
 * UNKNOWN. That is safe, but it caused every routine `mysql -e "SELECT ..."`
 * diagnostic to prompt in AUTO mode. This module adds a narrow allow-list for
 * SQL query forms while keeping all ambiguous SQL fail-closed.
 *
 * Only non-interactive -e/--execute invocations are classified here. Interactive
 * mysql, stdin scripts and commands with shell chaining/redirection are left to
 * the generic classifier as UNKNOWN/MODIFY.
 */

const ORDER: Record<CommandRisk, number> = {
  READ: 0,
  PRIVILEGED_READ: 1,
  UNKNOWN: 2,
  MODIFY: 3,
  DANGEROUS: 4,
}

function result(command: string, risk: CommandRisk, ruleId: string, reason: string, confidence: 'HIGH' | 'LOW' = 'HIGH'): Classification {
  return {
    risk,
    ruleId,
    reason,
    confidence,
    command,
    normalizedCommand: command.trim().replace(/\s+/g, ' '),
    classifierVersion: CLASSIFIER_VERSION,
  }
}

/** Tokenize enough shell syntax to preserve quoted SQL after -e/--execute.
 * Returns null if an unquoted shell control operator is seen: SQL semicolons
 * inside the quoted -e argument are fine, but `mysql ... ; rm ...` must never
 * be interpreted as one safe database command.
 */
function shellTokens(command: string): string[] | null {
  const out: string[] = []
  let current = ''
  let quote: "'" | '"' | null = null
  let escaped = false
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!
    if (escaped) {
      current += ch
      escaped = false
      continue
    }
    if (quote !== "'" && ch === '\\') {
      escaped = true
      continue
    }
    if (quote !== null) {
      if (ch === quote) quote = null
      else current += ch
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      continue
    }
    if (ch === ';' || ch === '|' || ch === '&' || ch === '<' || ch === '>' || ch === '`') return null
    if (ch === '$' && command[i + 1] === '(') return null
    if (/\s/.test(ch)) {
      if (current.length > 0) { out.push(current); current = '' }
      continue
    }
    current += ch
  }
  if (escaped || quote !== null) return null
  if (current.length > 0) out.push(current)
  return out
}

function splitSqlStatements(sql: string): string[] | null {
  const out: string[] = []
  let current = ''
  let quote: "'" | '"' | '`' | null = null
  let escaped = false
  let lineComment = false
  let blockComment = false

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i]!
    const next = sql[i + 1]
    if (lineComment) {
      if (ch === '\n') lineComment = false
      continue
    }
    if (blockComment) {
      if (ch === '*' && next === '/') { blockComment = false; i++ }
      continue
    }
    if (escaped) { current += ch; escaped = false; continue }
    if (quote !== "'" && ch === '\\') { current += ch; escaped = true; continue }
    if (quote !== null) {
      current += ch
      if (ch === quote) {
        // SQL doubles quote characters to escape them.
        if (next === quote) { current += next; i++; continue }
        quote = null
      }
      continue
    }
    if ((ch === '-' && next === '-' && /\s/.test(sql[i + 2] ?? ' ')) || ch === '#') {
      lineComment = true
      if (ch === '-') i++
      continue
    }
    if (ch === '/' && next === '*') { blockComment = true; i++; continue }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; current += ch; continue }
    if (ch === ';') {
      if (current.trim().length > 0) out.push(current.trim())
      current = ''
      continue
    }
    current += ch
  }
  if (quote !== null || blockComment) return null
  if (current.trim().length > 0) out.push(current.trim())
  return out
}

function classifyStatement(statement: string): { risk: CommandRisk; ruleId: string; reason: string; confidence?: 'HIGH' | 'LOW' } {
  const normalized = statement.trim().replace(/\s+/g, ' ')
  const upper = normalized.toUpperCase()
  const first = upper.match(/^([A-Z]+)/)?.[1]
  if (first === undefined) return { risk: 'UNKNOWN', ruleId: 'mysql.sql.unknown', reason: 'SQL statement could not be parsed', confidence: 'LOW' }

  if (first === 'SELECT') {
    if (/\bINTO\s+(?:OUTFILE|DUMPFILE)\b/i.test(normalized)) {
      return { risk: 'MODIFY', ruleId: 'mysql.sql.select-into-file', reason: 'SELECT INTO OUTFILE/DUMPFILE writes a server-side file' }
    }
    if (/\bFOR\s+UPDATE\b|\bLOCK\s+IN\s+SHARE\s+MODE\b/i.test(normalized)) {
      return { risk: 'UNKNOWN', ruleId: 'mysql.sql.select-lock', reason: 'locking SELECT changes transaction/lock state; automatic read-only confirmation is not safe', confidence: 'LOW' }
    }
    if (/\b(?:GET_LOCK|RELEASE_LOCK|SLEEP|BENCHMARK)\s*\(/i.test(normalized)) {
      return { risk: 'UNKNOWN', ruleId: 'mysql.sql.select-side-effect', reason: 'SELECT invokes a function with lock/timing side effects', confidence: 'LOW' }
    }
    return { risk: 'READ', ruleId: 'mysql.sql.select', reason: 'MySQL SELECT query is read-only' }
  }

  if (first === 'SHOW') return { risk: 'READ', ruleId: 'mysql.sql.show', reason: 'MySQL SHOW query is read-only' }
  if (first === 'DESC' || first === 'DESCRIBE') return { risk: 'READ', ruleId: 'mysql.sql.describe', reason: 'MySQL DESCRIBE query is read-only' }

  if (first === 'EXPLAIN') {
    if (/^EXPLAIN\s+ANALYZE\b/i.test(normalized)) {
      return { risk: 'UNKNOWN', ruleId: 'mysql.sql.explain-analyze', reason: 'EXPLAIN ANALYZE executes the statement; side effects cannot be excluded', confidence: 'LOW' }
    }
    return { risk: 'READ', ruleId: 'mysql.sql.explain', reason: 'MySQL EXPLAIN without ANALYZE does not modify data' }
  }

  if (first === 'DROP' || first === 'TRUNCATE') {
    return { risk: 'DANGEROUS', ruleId: 'mysql.sql.' + first.toLowerCase(), reason: 'MySQL ' + first + ' is destructive' }
  }

  if (['INSERT','UPDATE','DELETE','REPLACE','CREATE','ALTER','RENAME','GRANT','REVOKE','LOAD','LOCK','UNLOCK','FLUSH','RESET','KILL','SET','USE','START','COMMIT','ROLLBACK','SAVEPOINT','RELEASE'].includes(first)) {
    return { risk: 'MODIFY', ruleId: 'mysql.sql.' + first.toLowerCase(), reason: 'MySQL ' + first + ' changes data, schema, privileges, server or session state' }
  }

  // CALL may invoke arbitrary stored procedures; WITH can prefix SELECT or DML
  // and requires a real SQL parser to prove the terminal statement is read-only.
  if (first === 'CALL' || first === 'WITH' || first === 'DO' || first === 'HANDLER') {
    return { risk: 'UNKNOWN', ruleId: 'mysql.sql.' + first.toLowerCase(), reason: 'MySQL ' + first + ' semantics may include side effects', confidence: 'LOW' }
  }

  return { risk: 'UNKNOWN', ruleId: 'mysql.sql.unknown', reason: 'MySQL statement type ' + first + ' is not in the verified read-only set', confidence: 'LOW' }
}

function extractExecute(tokens: string[]): string | null {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i]!
    if (t === '-e' || t === '--execute') return tokens[i + 1] ?? null
    if (t.startsWith('--execute=')) return t.slice('--execute='.length)
    if (t.startsWith('-e') && t.length > 2) return t.slice(2)
  }
  return null
}

/** Return null when the command is not a mysql/mariadb CLI invocation. */
export function classifyMysqlCli(command: string): Classification | null {
  const trimmed = command.trim()
  if (trimmed.length === 0) return null

  const tokens = shellTokens(trimmed)
  if (tokens === null || tokens.length === 0) return null
  let executableIndex = 0
  while (['env','sudo','timeout','nice'].includes(tokens[executableIndex] ?? '')) executableIndex++
  const executable = (tokens[executableIndex] ?? '').split('/').at(-1)?.toLowerCase()
  if (executable !== 'mysql' && executable !== 'mariadb') return null

  const cliTokens = tokens.slice(executableIndex)
  const sql = extractExecute(cliTokens)
  if (sql === null || sql.trim().length === 0) {
    return result(trimmed, 'UNKNOWN', 'mysql.cli.interactive', 'mysql/mariadb without -e/--execute is interactive or script-driven; read-only cannot be confirmed', 'LOW')
  }

  const statements = splitSqlStatements(sql)
  if (statements === null || statements.length === 0) {
    return result(trimmed, 'UNKNOWN', 'mysql.sql.parse', 'SQL could not be safely parsed', 'LOW')
  }

  let worst = classifyStatement(statements[0]!)
  for (const statement of statements.slice(1)) {
    const next = classifyStatement(statement)
    if (ORDER[next.risk] > ORDER[worst.risk]) worst = next
  }
  return result(trimmed, worst.risk, worst.ruleId, worst.reason, worst.confidence ?? 'HIGH')
}
