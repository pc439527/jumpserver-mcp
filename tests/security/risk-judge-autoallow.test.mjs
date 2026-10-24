/**
 * V0.5.8 auto-allow — the ONE path by which the semantic judge may let a
 * command run without a human round-trip.
 *
 * Why it exists: during multi-host collection almost every probe that the rule
 * classifier cannot name (a vendor CLI status call, an NFS mount probe, …)
 * costs one confirm cycle PER HOST. Jev reads the command and, when it is
 * unambiguously read-only, the prompt is skipped.
 *
 * Tests that must reach this branch take their sample command from
 * tests/helpers/unknown-command.mjs — a rule added for a command (an
 * improvement) must never look like a regression here.
 *
 * Why it is tested this hard: it is the only place the connector can widen what
 * executes without a person watching. Every refusal must be a refusal —
 * including a missing number, a composed command and an interpreter — and the
 * decision must never bypass target verification or reach MODIFY/DANGEROUS.
 * Threshold values are the defaults in config/types.ts.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'
import {
  decideAutoAllow,
  riskJudgeAuditLine,
  resetRiskJudgeCache,
} from '../../lib/security/risk-judge.js'
import {
  gateCommand,
  gateCommandForNavigation,
  gateCommandsForNavigation,
  judgeAutoAllowNote,
} from '../../lib/security/permission-gate.js'
import { toStructuredAuditRecord } from '../../lib/security/audit.js'
import { UNKNOWN_COMMAND, UNKNOWN_COMMANDS } from '../helpers/unknown-command.mjs'

const AUTO = {
  enabled: true,
  minReadOnly: 0.9,
  minConfidence: 0.7,
  maxRiskScore: 1,
  minSafeProbability: 0.85,
  maxNeedsPrivilege: 0.3,
}

/** Measured shape for a benign unknown binary (`lsnrctl status`). */
const verdict = (over = {}) => ({
  readOnly: 0.91,
  impact: 'none',
  riskScore: 0.26,
  riskLevel: '随时可执行',
  safeProbability: 0.98,
  needsPrivilege: 0.12,
  confidence: 0.78,
  cached: false,
  latencyMs: 1300,
  ...over,
})

const ok = { command: 'lsnrctl status', ruleId: 'unknown.command' }

// ---------------- guard matrix ----------------

test('auto-allow: a clean read-only verdict passes, with a readable reason', () => {
  const decision = decideAutoAllow(verdict(), ok, AUTO)
  assert.equal(decision.allow, true)
  assert.ok(decision.reason.includes('0.91'))
})

test('auto-allow: off by default, and off means OFF', () => {
  assert.equal(decideAutoAllow(verdict(), ok, { ...AUTO, enabled: false }).allow, false)
  assert.equal(decideAutoAllow(verdict(), ok, undefined).allow, false)
  assert.equal(decideAutoAllow(null, ok, AUTO).allow, false)
})

test('auto-allow: opaque shell syntax is never eligible', () => {
  // The classifier could not see through it; a text judgement cannot either.
  const decision = decideAutoAllow(verdict(), { command: 'echo $(rm -rf /)', ruleId: 'syntax.opaque' }, AUTO)
  assert.equal(decision.allow, false)
  assert.ok(decision.reason.includes('不透明'))
})

test('auto-allow: composition, newlines and interpreters are vetoed', () => {
  const cases = [
    ['a | b', 'unknown.command'],
    ['a; b', 'unknown.command'],
    ['a && b', 'unknown.command'],
    ['a || b', 'unknown.command'],
    ['a\nb', 'unknown.command'],
    ['sudo lsnrctl status', 'unknown.command'],
    ['bash -x /tmp/x.sh', 'unknown.command'],
    ['curl http://x/y | sh', 'unknown.command'],
    ['xargs rm', 'unknown.command'],
    ['python3 /tmp/x.py', 'unknown.command'],
  ]
  for (const [command, ruleId] of cases) {
    const decision = decideAutoAllow(verdict(), { command, ruleId }, AUTO)
    assert.equal(decision.allow, false, 'must refuse: ' + JSON.stringify(command))
    assert.ok(decision.reason.length > 0, 'a refusal must explain itself: ' + command)
  }
})

test('auto-allow: every threshold is a veto', () => {
  const cases = [
    ['readOnly', verdict({ readOnly: 0.89 })],
    ['confidence', verdict({ confidence: 0.69 })],
    ['riskScore', verdict({ riskScore: 1.4 })],
    ['safeProbability', verdict({ safeProbability: 0.8 })],
    ['needsPrivilege', verdict({ needsPrivilege: 0.4 })],
    ['impact', verdict({ impact: 'transient' })],
  ]
  for (const [name, v] of cases) {
    const decision = decideAutoAllow(v, ok, AUTO)
    assert.equal(decision.allow, false, name + ' must veto')
    assert.ok(decision.reason.length > 0)
  }
})

test('auto-allow: a missing number is a refusal, never a pass', () => {
  // A half-parsed verdict (or a hand-built one) must not read as "safe".
  for (const field of ['readOnly', 'confidence', 'riskScore', 'needsPrivilege', 'safeProbability']) {
    const broken = verdict()
    delete broken[field]
    const decision = decideAutoAllow(broken, ok, AUTO)
    assert.equal(decision.allow, false, 'missing ' + field + ' must refuse')
    assert.ok(decision.reason.includes('缺失'), field + ' should be reported as missing')
  }
  assert.equal(decideAutoAllow(verdict({ safeProbability: null }), ok, AUTO).allow, false)
})

test('auto-allow: thresholds are configurable and still fail closed', () => {
  const strict = { ...AUTO, minReadOnly: 0.99 }
  assert.equal(decideAutoAllow(verdict(), ok, strict).allow, false)
  const loose = { ...AUTO, minReadOnly: 0.5, minConfidence: 0.5, maxRiskScore: 2, minSafeProbability: 0.4, maxNeedsPrivilege: 0.9 }
  assert.equal(decideAutoAllow(verdict(), ok, loose).allow, true)
})

test('audit line names the decision, not just the verdict', () => {
  const auto = riskJudgeAuditLine(verdict(), true, 'readOnly 0.91 · 置信 0.78')
  assert.ok(auto.startsWith('AUTO_ALLOWED'))
  assert.ok(auto.includes('readOnly 0.91'))
  const advisory = riskJudgeAuditLine(verdict(), false, '只读把握 0.91 < 0.95')
  assert.ok(advisory.startsWith('ADVISORY'))
  assert.ok(advisory.includes('只读把握 0.91 < 0.95'))
})

// ---------------- gate integration ----------------

/** One mock System One endpoint, answered with the measured benign verdict. */
async function mockJudge() {
  const { createServer } = await import('node:http')
  const state = { hits: 0 }
  const body = {
    answers: {
      read_only: { noul: 0.91 },
      impact: { choice: 'none', confidence: 0.85, probabilities: { none: 0.89, transient: 0.11 } },
      risk_level: { score: 0.26, confidence: 0.78, probabilities: { 0: 0.75, 1: 0.23, 2: 0.02 } },
      needs_privilege: { noul: 0.12 },
    },
  }
  const server = createServer((_req, res) => {
    state.hits += 1
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(body))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  return {
    state,
    endpoint: 'http://127.0.0.1:' + port + '/v1/systemone',
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

function judgeCfg(endpoint, autoAllow = AUTO) {
  return {
    enabled: true,
    endpoint,
    apiKeyEnv: 'TYPESAFE_API_KEY',
    apiKeyFile: '',
    model: 'jev-latest',
    timeoutMs: 1500,
    cacheTtlSeconds: 3600,
    redactNetwork: true,
    autoAllow,
  }
}

function services(riskJudge, status = { state: 'ASSET_SHELL', target: '192.168.148.36', hostname: 'app01' }) {
  return { getConfig: () => ({ permissionMode: 'AUTO', riskJudge }), manager: { status: () => status } }
}

const exec = (confirm = false) => ({ name: 'jumpserver_exec', callId: 1, signal: new AbortController().signal, confirm })

test('gate: auto-allow turns one UNKNOWN prompt into zero prompts', async () => {
  const mock = await mockJudge()
  try {
    resetRiskJudgeCache()
    const gated = await gateCommand(services(judgeCfg(mock.endpoint)), exec(), UNKNOWN_COMMAND)
    assert.equal(gated.approvalRequired, false, 'no human prompt should have been needed')
    assert.equal(gated.judgeAutoAllowed, true)
    assert.ok(gated.judgeNote.startsWith('AUTO_ALLOWED'), gated.judgeNote)
    assert.equal(mock.state.hits, 1)
  } finally {
    await mock.close()
  }
})

test('gate: with auto-allow off the prompt is exactly what it was', async () => {
  const mock = await mockJudge()
  try {
    resetRiskJudgeCache()
    await assert.rejects(
      () => gateCommand(services(judgeCfg(mock.endpoint, { ...AUTO, enabled: false })), exec(), UNKNOWN_COMMAND),
      (error) => {
        assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
        assert.ok(error.message.includes('语义副驾'))
        assert.ok(error.message.includes('不参与放行判定'), 'the neutral copy must survive')
        assert.ok(!error.message.includes('自动放行未通过'), 'nothing was auto-approved, so nothing to explain')
        return true
      },
    )
  } finally {
    await mock.close()
  }
})

test('gate: a refused verdict explains itself in the prompt', async () => {
  const mock = await mockJudge()
  try {
    resetRiskJudgeCache()
    // minReadOnly 0.99 cannot be met by the 0.91 verdict.
    const cfg = judgeCfg(mock.endpoint, { ...AUTO, minReadOnly: 0.99 })
    await assert.rejects(
      () => gateCommand(services(cfg), exec(), UNKNOWN_COMMAND),
      (error) => {
        assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
        assert.ok(error.message.includes('自动放行未通过'))
        assert.ok(error.message.includes('0.91 < 0.99'))
        return true
      },
    )
  } finally {
    await mock.close()
  }
})

test('gate: auto-allow still cannot run a command against an unverified target', async () => {
  const mock = await mockJudge()
  try {
    resetRiskJudgeCache()
    const cfg = judgeCfg(mock.endpoint)
    await assert.rejects(
      () => gateCommand(services(cfg, { state: 'MENU', target: null, hostname: null }), exec(), UNKNOWN_COMMAND),
      (error) => {
        assert.equal(error.code, 'TARGET_VERIFICATION_FAILED')
        return true
      },
    )
    const cfg2 = judgeCfg(mock.endpoint)
    const nav = await gateCommandForNavigation(services(cfg2, { state: 'MENU', target: null, hostname: null }), exec(), UNKNOWN_COMMANDS[1])
    assert.equal(nav.approvalRequired, false, 'auto-allowed: no deferred prompt')
    assert.equal(nav.judgeAutoAllowed, true)
    // …but the deferred beforeExec the manager runs after navigation must STILL
    // verify the target, or an auto-allow would be the way around that rule.
    await assert.rejects(() => nav.beforeExec(), (error) => error.code === 'TARGET_VERIFICATION_FAILED')
  } finally {
    await mock.close()
  }
})

test('C9：MODIFY和DANGEROUS即使模型允许仍不能自动放行', async () => {
  const mock = await mockJudge()
  try {
    resetRiskJudgeCache()
    for (const command of ['rm -rf /tmp/x', 'systemctl stop nginx']) {
      await assert.rejects(
        () => gateCommand(services(judgeCfg(mock.endpoint)), exec(), command),
        (error) => {
          assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED', command)
          assert.match(error.message, /仅供参考，不参与放行判定/)
          return true
        },
      )
    }
    assert.equal(mock.state.hits, 2, '两条命令的模型意见都不能代替人工审批')
  } finally {
    await mock.close()
  }
})

test('gate: a batch of unclassified probes needs no prompt at all', async () => {
  const mock = await mockJudge()
  try {
    resetRiskJudgeCache()
    const gated = await gateCommandsForNavigation(
      services(judgeCfg(mock.endpoint)),
      exec(),
      UNKNOWN_COMMANDS,
    )
    assert.equal(gated.length, 3)
    for (const item of gated) {
      assert.equal(item.approvalRequired, false, item.classification.command + ' should be auto-allowed')
      assert.equal(item.judgeAutoAllowed, true)
    }
    const note = judgeAutoAllowNote(gated)
    assert.ok(note.includes('3 条命令'), note)
    assert.ok(note.includes('AUTO_ALLOWED'))
    // The deferred verification survives for every auto-allowed item.
    for (const item of gated) {
      assert.equal(typeof item.beforeExec, 'function')
      await item.beforeExec()
    }
  } finally {
    await mock.close()
  }
})

test('gate: one unclear command in the batch keeps the batch prompt alive', async () => {
  const { createServer } = await import('node:http')
  // First command reads clean, second one is opaque to the judge.
  let call = 0
  const server = createServer((_req, res) => {
    call += 1
    const clean = {
      answers: {
        read_only: { noul: 0.95 },
        impact: { choice: 'none', confidence: 0.9, probabilities: { none: 0.95 } },
        risk_level: { score: 0.1, confidence: 0.88, probabilities: { 0: 0.9, 1: 0.1 } },
        needs_privilege: { noul: 0.05 },
      },
    }
    const murky = {
      answers: {
        read_only: { noul: 0.5 },
        impact: { choice: 'transient', confidence: 0.5, probabilities: { none: 0.4, transient: 0.6 } },
        risk_level: { score: 2.1, confidence: 0.5, probabilities: { 1: 0.3, 2: 0.5, 3: 0.2 } },
        needs_privilege: { noul: 0.4 },
      },
    }
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(call === 1 ? clean : murky))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  try {
    resetRiskJudgeCache()
    const gated = await gateCommandsForNavigation(
      services(judgeCfg('http://127.0.0.1:' + port + '/v1/systemone')),
      exec(),
      [UNKNOWN_COMMANDS[0], UNKNOWN_COMMANDS[1]],
    )
    assert.equal(gated[0].approvalRequired, false, 'the clean one drops out of the prompt')
    assert.equal(gated[1].approvalRequired, true, 'the murky one stays')
    assert.equal(judgeAutoAllowNote(gated).includes('1 条命令'), true)
    await assert.rejects(() => gated[1].beforeExec(), (error) => error.code === 'COMMAND_APPROVAL_REQUIRED')
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
})

// ---------------- thresholds against MEASURED verdicts ----------------

/**
 * Real answers from the live endpoint (jev-1.13.0, 2026-09-21), one call per
 * command. The defaults were chosen from THIS table, so the table is the
 * regression: if a threshold is loosened, these assertions name the exact real
 * command whose prompt would silently disappear.
 *
 *   command                    readOnly  impact     conf(impact/min)  score  safe  priv
 *   lsnrctl status               0.91    none       0.85 / 0.78       0.26   0.98  0.12
 *   showmount -e <ip>            0.91    none       0.82 / 0.52       0.58   n/a   0.08
 *   jstack <pid>                 0.47    none       0.76 / 0.43       1.87   n/a   0.29
 *   sapcontrol -function Stop    0.02    transient  0.27 / 0.77       3.73   n/a   0.72
 */
const MEASURED = [
  {
    command: 'lsnrctl status',
    allow: true,
    verdict: verdict({ readOnly: 0.91, safeProbability: 0.98, confidence: 0.78, riskScore: 0.26, needsPrivilege: 0.12 }),
  },
  {
    // Read-only in reality, but the model is unsure (weakest confidence 0.52):
    // it keeps its prompt. Lowering minConfidence below ~0.5 flips this one.
    command: 'showmount -e 10.0.0.9',
    allow: false,
    verdict: verdict({ readOnly: 0.91, safeProbability: null, confidence: 0.52, riskScore: 0.58, needsPrivilege: 0.08 }),
  },
  {
    // Attaching to a JVM can pause it — 0.47 read-only is a real signal.
    command: 'jstack 12345',
    allow: false,
    verdict: verdict({ readOnly: 0.47, safeProbability: null, confidence: 0.43, riskScore: 1.87, needsPrivilege: 0.29 }),
  },
  {
    command: 'sapcontrol -function Stop',
    allow: false,
    verdict: verdict({
      readOnly: 0.02,
      impact: 'transient',
      riskScore: 3.73,
      safeProbability: null,
      confidence: 0.27,
      needsPrivilege: 0.72,
    }),
  },
]

test('the defaults separate real cases exactly as measured', () => {
  const report = MEASURED.map((entry) => {
    const decision = decideAutoAllow(entry.verdict, { command: entry.command, ruleId: 'unknown.command' }, AUTO)
    return { command: entry.command, allow: decision.allow, reason: decision.reason }
  })
  for (const [index, entry] of MEASURED.entries()) {
    assert.equal(
      report[index].allow,
      entry.allow,
      entry.command + ' → ' + (report[index].allow ? 'auto-allowed' : 'prompts: ' + report[index].reason),
    )
  }
  // The one that must pass says WHY, so the audit line is readable.
  assert.ok(report[0].allow)
  assert.ok(MEASURED.filter((e) => !e.allow).length === 3)
})

// ---------------- audit trail ----------------

/** Menu screen the fake bastion paints on connect (KoKo's asset picker). */
const MENU_SCREEN = [
  '┌──────────────────────────────────────────┐',
  '│  JumpServer · 堡垒机 / KoKo 终端          │',
  '│  1) app01                                 │',
  '│  2) app02                                 │',
  '│  请输入资产名或编号：                       │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
  }
  write(text) {
    this.written.push(text)
    const m = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (m !== null) {
      this._emit('\n__DSH_JS_PROBE_' + m[1] + '\nH=app01\nU=root\nP=/root\n__DSH_JS_PROBE_END_' + m[1] + '\n[root@app01 ~]# ')
    }
  }
  onData(cb) {
    this.cbs.push(cb)
  }
  onError() {}
  onClose(cb) {
    this.closeCbs.push(cb)
  }
  close() {
    for (const cb of this.closeCbs) cb()
  }
  _emit(text) {
    for (const cb of this.cbs) cb(text)
  }
}

test('an auto-allowed command lands in the audit trail with its verdict', async () => {
  const wire = new FakeWire()
  const audits = []
  const manager = new SessionManager(
    {
      getConfig: () => ({
        enabled: true,
        enableAudit: true,
        host: '127.0.0.1',
        port: 22,
        username: 'u',
        connectTimeout: 5,
        commandTimeout: 30,
        assetCacheTtlSeconds: 60,
        idleTimeout: 30,
        listAssets: false,
        batchConcurrency: 1,
        maxSessions: 1,
        permissionMode: 'AUTO',
      }),
      resolvePassword: async () => 'p',
      onAudit: async (record) => audits.push(record),
      onLog: () => undefined,
      wireFactory: async () => wire,
    },
  )
  const connectP = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 20)
  await connectP
  if (manager.status().state !== SessionState.ASSET_SHELL) {
    const enter = manager.enter('192.168.148.36')
    setTimeout(() => wire._emit('\n[root@app01 ~]# '), 20)
    await enter
  }

  const note = riskJudgeAuditLine(verdict(), true, 'readOnly 0.91 · 置信 0.78')
  await manager.exec({
    command: 'lsnrctl status',
    risk: 'UNKNOWN',
    classification: { risk: 'UNKNOWN', reason: 'no semantic rule', ruleId: 'unknown.command' },
    approvalRequired: false,
    approvalResult: 'none',
    riskJudge: note,
  })

  const record = audits.find((a) => a.command === 'lsnrctl status')
  assert.ok(record !== undefined, 'the command should have been audited')
  assert.equal(record.riskJudge, note, 'the audit must carry WHY it ran unattended')
  assert.equal(record.approvalRequired, false)
  // …and the stored record must still satisfy the storage schema.
  const stored = toStructuredAuditRecord(record)
  assert.ok(stored.riskJudge.startsWith('AUTO_ALLOWED'))

  // A command the classifier decided on its own carries no judge line at all.
  await manager.exec({
    command: 'uptime',
    risk: 'READ',
    classification: { risk: 'READ', ruleId: 'read.uptime' },
    approvalRequired: false,
    approvalResult: 'none',
  })
  const plain = audits.find((a) => a.command === 'uptime')
  assert.equal(plain.riskJudge, undefined)
})
