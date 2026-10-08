import type { Classification } from './command-classifier.js'
import { CLASSIFIER_VERSION } from './command-classifier.js'
import type { CommandRisk } from '../config/types.js'

/**
 * Semantic classifier for database CLIs.
 *
 * The generic shell classifier intentionally treats unknown executables as
 * UNKNOWN. That is safe, but it caused every routine `mysql -e "SELECT ..."`
 * diagnostic to prompt in AUTO mode. This module adds narrow allow-lists for
 * the query forms that can be PROVEN read-only, while keeping all ambiguous
 * SQL fail-closed.
 *
 * Covered:
 *  - mysql / mariadb (`-e` / `--execute`)          -> classifyMysqlCli
 *  - SAP HANA `hdbsql` (positional statement)      -> classifyHanaCli
 *
 * Only non-interactive invocations are classified here. Interactive shells,
 * stdin scripts, file-driven input and commands with shell chaining or
 * redirection fall through to the generic classifier as UNKNOWN.
 *
 * Every rule here is a SECURITY boundary: a wrong READ verdict means an
 * AUTO-mode deployment runs a mutating statement without asking. So the
 * failure direction is always "prompt the human", never "assume it is fine".
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

/**
 * SAP HANA `hdbsql` (V0.5.2).
 *
 * WHY THIS EXISTS: HANA has no `-e`. hdbsql takes the statement as a POSITIONAL
 * argument, so `hdbsql -n host:30013 -u SYSTEM -p *** -d SAPHANADB "SELECT ..."`.
 * Every such call was an unknown executable, so a BASIS reading CSKS / COSS /
 * COSP / ACDOCA was prompted for confirmation on every single query — which is
 * exactly the daily verification work the connector exists to serve.
 *
 * WHAT STAYS FAIL-CLOSED, and why it must:
 *  - `-o` / `-I` / `-O` / `-L`: hdbsql writes or reads a FILE with these. A file
 *    target turns "read-only query" into a side effect, so the verdict is
 *    UNKNOWN rather than trying to reason about what the file is used for.
 *  - no positional statement: interactive or script-driven; nothing to classify.
 *  - any statement type not explicitly proven read-only below.
 *
 * Shell-level chaining (`; rm -rf`, pipes, redirection, `$(...)`) is already
 * rejected by `shellTokens`, so quoting cannot smuggle a second command in.
 */

/** hdbsql flags that consume the FOLLOWING token as their value. */
const HANA_VALUE_FLAGS = new Set([
  '-n', // host:port
  '-i', // instance number
  '-d', // database name
  '-u', // user
  '-p', // password
  '-U', // user-store key
  '-c', // (reserved value-taking form)
  '-t', // (reserved value-taking form)
  '-C', // (reserved value-taking form)
  '-s', // (reserved value-taking form)
])

/** hdbsql flags that touch the filesystem: never provable as read-only. */
const HANA_FILE_FLAGS = new Set(['-o', '-O', '-I', '-L'])

/** `\s`, `\dt`, `\du` … — hdbsql's OWN meta-commands, not SQL. */
const HANA_READ_META = new Set(['\\S', '\\D', '\\DT', '\\DV', '\\DS', '\\DU', '\\L', '\\Q', '\\?', '\\H'])

/**
 * Statement types that change data, schema, privileges or session state.
 * `CALL` / `DO` / `WITH` are deliberately NOT here: they are neither provably
 * read-only nor obviously mutating, so they are reported UNKNOWN (which
 * prompts) instead of MODIFY (which also prompts, but with a wrong reason).
 */
const HANA_MODIFY_KEYWORDS = new Set([
  'INSERT', 'UPDATE', 'DELETE', 'UPSERT', 'REPLACE', 'MERGE',
  'CREATE', 'ALTER', 'RENAME', 'COMMENT',
  'GRANT', 'REVOKE',
  'IMPORT', 'EXPORT', 'LOAD', 'UNLOAD',
  'SET', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'RELEASE', 'START', 'ABORT',
  'CONNECT', 'RECONFIGURE', 'CHECKPOINT',
])

function classifyHanaStatement(statement: string): { risk: CommandRisk; ruleId: string; reason: string; confidence?: 'HIGH' | 'LOW' } {
  const normalized = statement.trim().replace(/\s+/g, ' ')
  const upper = normalized.toUpperCase()

  if (upper.startsWith('\\')) {
    const meta = upper.split(/\s+/)[0] ?? ''
    if (HANA_READ_META.has(meta)) {
      return { risk: 'READ', ruleId: 'hana.meta.list', reason: 'hdbsql meta-command ' + meta + ' only reports metadata' }
    }
    return {
      risk: 'UNKNOWN',
      ruleId: 'hana.meta.other',
      reason: 'hdbsql meta-command ' + meta + ' is not in the verified read-only set',
      confidence: 'LOW',
    }
  }

  const first = upper.match(/^([A-Z]+)/)?.[1]
  if (first === undefined) {
    return { risk: 'UNKNOWN', ruleId: 'hana.sql.unknown', reason: 'SAP HANA statement could not be parsed', confidence: 'LOW' }
  }

  if (first === 'SELECT') {
    // A locking SELECT changes transaction state; do not auto-approve.
    if (/\bFOR\s+UPDATE\b/i.test(normalized)) {
      return {
        risk: 'UNKNOWN',
        ruleId: 'hana.sql.select-lock',
        reason: 'locking SELECT changes transaction state; automatic read-only confirmation is not safe',
        confidence: 'LOW',
      }
    }
    return { risk: 'READ', ruleId: 'hana.sql.select', reason: 'SAP HANA SELECT query is read-only' }
  }

  // EXPLAIN PLAN FOR <select> only compiles the plan. Anything else under
  // EXPLAIN (e.g. PLAN FOR an UPDATE) is not proven side-effect free.
  if (first === 'EXPLAIN') {
    if (/^EXPLAIN\s+(?:PLAN\s+)?FOR\s+SELECT\b/i.test(normalized)) {
      return { risk: 'READ', ruleId: 'hana.sql.explain-select', reason: 'EXPLAIN PLAN FOR a SELECT compiles a plan and does not execute it' }
    }
    return {
      risk: 'UNKNOWN',
      ruleId: 'hana.sql.explain-other',
      reason: 'EXPLAIN of a non-SELECT statement is not proven side-effect free',
      confidence: 'LOW',
    }
  }

  if (first === 'DROP' || first === 'TRUNCATE') {
    return { risk: 'DANGEROUS', ruleId: 'hana.sql.' + first.toLowerCase(), reason: 'SAP HANA ' + first + ' is destructive' }
  }

  if (HANA_MODIFY_KEYWORDS.has(first)) {
    return { risk: 'MODIFY', ruleId: 'hana.sql.' + first.toLowerCase(), reason: 'SAP HANA ' + first + ' changes data, schema, privileges or session state' }
  }

  if (first === 'CALL' || first === 'DO' || first === 'WITH') {
    return {
      risk: 'UNKNOWN',
      ruleId: 'hana.sql.' + first.toLowerCase(),
      reason: 'SAP HANA ' + first + ' semantics may include side effects',
      confidence: 'LOW',
    }
  }

  return {
    risk: 'UNKNOWN',
    ruleId: 'hana.sql.unknown',
    reason: 'SAP HANA statement type ' + first + ' is not in the verified read-only set',
    confidence: 'LOW',
  }
}

/**
 * The first NON-flag token after the executable, which is where hdbsql expects
 * the statement. Flags are skipped; the value of a known value-taking flag is
 * skipped with it.
 *
 * Misjudging a flag only ever costs accuracy: a value mistaken for SQL fails to
 * match any statement keyword and lands on UNKNOWN, and a flag mistaken for a
 * value hides the statement, which also lands on UNKNOWN.
 */
function extractHanaStatement(cliTokens: string[]): string | null {
  for (let i = 1; i < cliTokens.length; i++) {
    const token = cliTokens[i]!
    if (token.startsWith('-')) {
      if (token.includes('=')) continue // --host=...
      if (HANA_VALUE_FLAGS.has(token)) i++ // its value is not the statement
      continue
    }
    return token
  }
  return null
}

/** Return null when the command is not an `hdbsql` invocation. */
export function classifyHanaCli(command: string): Classification | null {
  const trimmed = command.trim()
  if (trimmed.length === 0) return null

  const tokens = shellTokens(trimmed)
  if (tokens === null || tokens.length === 0) return null
  let executableIndex = 0
  while (['env', 'sudo', 'timeout', 'nice'].includes(tokens[executableIndex] ?? '')) executableIndex++
  const executable = (tokens[executableIndex] ?? '').split('/').at(-1)?.toLowerCase()
  if (executable !== 'hdbsql') return null

  const cliTokens = tokens.slice(executableIndex)

  for (const token of cliTokens.slice(1)) {
    if (HANA_FILE_FLAGS.has(token)) {
      return result(
        trimmed,
        'UNKNOWN',
        'hana.cli.file-io',
        'hdbsql ' + token + ' reads or writes a file, so a read-only verdict cannot be given',
        'LOW',
      )
    }
  }

  const statement = extractHanaStatement(cliTokens)
  if (statement === null || statement.trim().length === 0) {
    return result(
      trimmed,
      'UNKNOWN',
      'hana.cli.no-statement',
      'hdbsql without a positional statement is interactive or script-driven; read-only cannot be confirmed',
      'LOW',
    )
  }

  const statements = splitSqlStatements(statement)
  if (statements === null || statements.length === 0) {
    return result(trimmed, 'UNKNOWN', 'hana.sql.parse', 'SAP HANA statement could not be safely parsed', 'LOW')
  }

  let worst = classifyHanaStatement(statements[0]!)
  for (const item of statements.slice(1)) {
    const next = classifyHanaStatement(item)
    if (ORDER[next.risk] > ORDER[worst.risk]) worst = next
  }
  return result(trimmed, worst.risk, worst.ruleId, worst.reason, worst.confidence ?? 'HIGH')
}
