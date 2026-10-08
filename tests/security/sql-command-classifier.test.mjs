/**
 * Database-CLI classifier contract — mysql/mariadb + SAP HANA `hdbsql`.
 *
 * WHY THIS FILE EXISTS: `sql-command-classifier.ts` is a SECURITY boundary. A
 * wrong READ verdict means an AUTO-mode deployment executes a mutating
 * statement with no human in the loop. It shipped with zero tests.
 *
 * The subject under test is `classifyCommand` from `permission.ts` — the
 * AUTHORITATIVE chain (mysql -> HANA -> generic shell). Testing the two
 * database classifiers in isolation would miss the only thing that matters:
 * that the chain picks them up before the generic classifier gets a chance to
 * call everything UNKNOWN, and that the generic classifier still wins whenever
 * the database classifier declines.
 *
 * Assertions are on RISK LEVEL, never `ruleId`: a rule id is an implementation
 * detail and changes as rules land, but a risk level is a promise.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyCommand } from '../../lib/security/permission.js'
import { classifyHanaCli, classifyMysqlCli } from '../../lib/security/sql-command-classifier.js'

function expectRead(commands) {
  for (const command of commands) {
    const c = classifyCommand(command)
    assert.equal(c.risk, 'READ', command + ' should be READ, got ' + c.risk + ' (' + c.ruleId + ')')
  }
}

function expectRisk(rows) {
  for (const [expected, command] of rows) {
    const c = classifyCommand(command)
    assert.equal(c.risk, expected, command + ' should be ' + expected + ', got ' + c.risk + ' (' + c.ruleId + ')')
  }
}

function expectNotRead(commands) {
  for (const command of commands) {
    const c = classifyCommand(command)
    assert.notEqual(c.risk, 'READ', command + ' must NEVER be classified READ (got ' + c.ruleId + ')')
  }
}

// ------------------------------------------------------------------ HANA READ

test('hdbsql: the read-only queries a BASIS actually runs are confirmed READ', () => {
  expectRead([
    // The canonical shape: positional statement, no -e.
    'hdbsql -n localhost:30013 -u SYSTEM -p s3cret -d SAPHANADB -A -j -m "SELECT * FROM CSKS"',
    // Instance form, no host.
    'hdbsql -i 00 -d SAPHANADB "SELECT COUNT(*) FROM COSS WHERE GJAHR = \'2026\'"',
    // Absolute path to the HANA exe.
    '/usr/sap/HDB/HDB00/exe/hdbsql -n hdb:30013 "SELECT * FROM M_SERVICE_MEMORY"',
    // Prefixed by a privilege wrapper.
    'sudo hdbsql -n hdb:30013 "SELECT * FROM DUMMY"',
    'env hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY"',
    // User-store key instead of user/password.
    'hdbsql -U DEFAULT -d SAPHANADB "SELECT * FROM ACDOCA WHERE RCLNT = \'100\'"',
    // EXPLAIN PLAN FOR a SELECT compiles a plan; it does not execute.
    'hdbsql -n hdb:30013 "EXPLAIN PLAN FOR SELECT * FROM COSP"',
  ])
})

test('hdbsql: a semicolon-separated batch of read-only statements is READ', () => {
  expectRead([
    'hdbsql -n hdb:30013 "SELECT * FROM CSKS; SELECT * FROM COSS"',
  ])
})

test('hdbsql: read-only meta-commands are READ, unknown ones are not', () => {
  expectRead(['hdbsql -n hdb:30013 "\\\\dt"', 'hdbsql -n hdb:30013 "\\\\s"'])
  expectRisk([
    ['UNKNOWN', 'hdbsql -n hdb:30013 "\\\\i evil.sql"'],
    ['UNKNOWN', 'hdbsql -n hdb:30013 "\\\\o /tmp/dump.txt"'],
  ])
})

// ----------------------------------------------------------- HANA must NOT be

test('hdbsql: mutating statements keep their real risk, never READ', () => {
  expectRisk([
    ['MODIFY', 'hdbsql -n hdb:30013 "UPDATE CSKS SET KOSTL = \'X\' WHERE MANDT = \'100\'"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "DELETE FROM COSS WHERE GJAHR = \'2019\'"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "INSERT INTO ZTAB VALUES (1)"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "UPSERT ZTAB VALUES (1,2)"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "MERGE INTO ZTAB USING ZSRC ON ZTAB.ID = ZSRC.ID"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "ALTER TABLE ZTAB ADD (COL NVARCHAR(10))"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "GRANT SELECT ON CSKS TO ZUSER"'],
    ['MODIFY', 'hdbsql -n hdb:30013 "EXPORT ZTAB TO \'/tmp/x\'"'],
    ['DANGEROUS', 'hdbsql -n hdb:30013 "DROP TABLE CSKS"'],
    ['DANGEROUS', 'hdbsql -n hdb:30013 "TRUNCATE TABLE CSKS"'],
  ])
})

test('hdbsql: opaque statement types are UNKNOWN, which prompts', () => {
  expectRisk([
    ['UNKNOWN', 'hdbsql -n hdb:30013 "CALL SYS.SOME_PROCEDURE()"'],
    ['UNKNOWN', 'hdbsql -n hdb:30013 "DO BEGIN SELECT 1 FROM DUMMY; END"'],
    ['UNKNOWN', 'hdbsql -n hdb:30013 "WITH x AS (SELECT 1 FROM DUMMY) SELECT * FROM x"'],
    // A locking SELECT changes transaction state.
    ['UNKNOWN', 'hdbsql -n hdb:30013 "SELECT * FROM CSKS FOR UPDATE"'],
    // EXPLAIN of a non-SELECT is not proven side-effect free.
    ['UNKNOWN', 'hdbsql -n hdb:30013 "EXPLAIN PLAN FOR UPDATE CSKS SET X = 1"'],
  ])
})

test('hdbsql: file-based I/O is UNKNOWN even when the statement is a SELECT', () => {
  // The statement being read-only does not matter: -o writes a file, -I reads
  // a script of arbitrary statements.
  expectRisk([
    ['UNKNOWN', 'hdbsql -n hdb:30013 -o /tmp/out.txt "SELECT * FROM CSKS"'],
    ['UNKNOWN', 'hdbsql -n hdb:30013 -I /tmp/query.sql'],
    ['UNKNOWN', 'hdbsql -n hdb:30013 -L /tmp/trace "SELECT 1 FROM DUMMY"'],
  ])
})

test('hdbsql: no positional statement means interactive, which is UNKNOWN', () => {
  expectRisk([
    ['UNKNOWN', 'hdbsql -n hdb:30013 -u SYSTEM -p s3cret -d SAPHANADB'],
    ['UNKNOWN', 'hdbsql'],
  ])
})

// ------------------------------------------------------- shell-level escapes

test('shell chaining cannot smuggle a second command past the hdbsql rule', () => {
  // `shellTokens` bails out on these, so BOTH classifiers decline and the
  // generic classifier decides. The invariant that matters is only that the
  // result is never READ.
  expectNotRead([
    'hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY"; rm -rf /hana/data',
    'hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY" && rm -rf /hana/data',
    'hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY" > /tmp/out.txt',
    'hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY" | tee /tmp/out.txt',
    'hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY" `whoami`',
    'hdbsql -n hdb:30013 "SELECT 1 FROM DUMMY" $(whoami)',
    'echo "DROP TABLE CSKS" | hdbsql -n hdb:30013',
  ])
})

// -------------------------------------------------------- mysql regression

test('mysql: the verified -e form still classifies as before', () => {
  expectRead([
    'mysql -e "SELECT 1"',
    'mysql --execute="SELECT 1"',
    'mysql -uroot -p -e "SHOW PROCESSLIST"',
    'mysql -e "EXPLAIN SELECT * FROM t"',
    'mysql -e "SELECT * FROM t; SELECT * FROM u"',
  ])
})

test('mysql: mutating and ambiguous forms are unchanged', () => {
  expectRisk([
    ['DANGEROUS', 'mysql -e "DROP TABLE t"'],
    ['MODIFY', 'mysql -e "INSERT INTO t VALUES (1)"'],
    // INTO OUTFILE writes a server-side file.
    ['MODIFY', 'mysql -e "SELECT * FROM t INTO OUTFILE \'/tmp/x\'"'],
    ['UNKNOWN', 'mysql -e "SELECT * FROM t FOR UPDATE"'],
    ['UNKNOWN', 'mysql -e "CALL some_proc()"'],
    ['UNKNOWN', 'mysql -e "EXPLAIN ANALYZE SELECT * FROM t"'],
    ['UNKNOWN', 'mysql'],
  ])
})

test('mysql: a shell-chained form is handed back to the generic classifier', () => {
  // The database classifier deliberately declines anything with a pipe, so the
  // verdict comes from the generic rules — which is a BETTER answer than
  // UNKNOWN here: `| tee /tmp/x` really does write a file (mutation.verb).
  const piped = classifyCommand('mysql -e "SELECT 1" | tee /tmp/x')
  assert.equal(piped.risk, 'MODIFY', 'a pipeline into tee must not be READ')
  assert.equal(classifyMysqlCli('mysql -e "SELECT 1" | tee /tmp/x'), null, 'the mysql rule must decline piped input')
})

// ------------------------------------------------------------- the chain

test('the database classifiers only claim commands they own', () => {
  // Declining must be silent and total: a non-DB command must come back null
  // so the generic classifier keeps its verdict.
  for (const command of ['ls -l', 'systemctl status nginx', 'mariadb-helper x', 'hdbsqlx "SELECT 1"']) {
    assert.equal(classifyHanaCli(command), null, command + ' is not an hdbsql invocation')
  }
  assert.equal(classifyMysqlCli('ls -l'), null)
  assert.equal(classifyMysqlCli('mariadb-dump -x db'), null)
})

test('the HANA rule is registered before the generic classifier, and both agree on risk', () => {
  const command = 'hdbsql -n hdb:30013 -A -j -m "SELECT * FROM CSKS"'
  const chained = classifyCommand(command)
  const direct = classifyHanaCli(command)
  assert.notEqual(direct, null, 'the HANA classifier must claim this command')
  assert.equal(chained.risk, direct.risk, 'the chained classifier must return the HANA verdict, not UNKNOWN')
  assert.equal(chained.ruleId, direct.ruleId)
})
