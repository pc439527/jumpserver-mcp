/**
 * V0.5.9 — refusals are audited, not just thrown.
 *
 * Why it exists: until V0.5.9 the audit trail only contained commands that
 * actually ran. A command stopped by the rules, or refused because nobody
 * approved it, left NO trace — so "who tried to run what, and was stopped" was
 * unanswerable. That is a compliance blind spot, not a cosmetic gap.
 *
 * What is asserted here:
 *  - every refusal path writes exactly one record (BLOCKED = the rules said no,
 *    DENIED = no approval);
 *  - the record names WHY (refusalReason), and satisfies the storage schema;
 *  - a broken audit sink can never change the gate's decision — the refusal
 *    must still be a refusal.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { SessionManager } from '../../lib/jumpserver/session-manager.js'
import { SessionState } from '../../lib/jumpserver/state-machine.js'
import {
  gateCommand,
  gateCommandForNavigation,
  gateCommandsForNavigation,
} from '../../lib/security/permission-gate.js'
import { toStructuredAuditRecord } from '../../lib/security/audit.js'
import { APPROVAL_DENIED_REASON } from '../../lib/jumpserver/errors.js'
import { UNKNOWN_COMMAND } from '../helpers/unknown-command.mjs'

const STATUS = { state: 'ASSET_SHELL', target: '192.168.148.36', hostname: 'app01' }

/**
 * The DENIED path only exists for commands the rules cannot classify: UNKNOWN
 * under AUTO asks for approval, UNKNOWN under READ_ONLY is blocked outright.
 * The sample therefore comes from the shared, self-validating fixture — see
 * tests/helpers/unknown-command.mjs for why it must not be picked by hand.
 */
const UNKNOWN_CMD = UNKNOWN_COMMAND

/**
 * Gate services with a recording stand-in for the manager: the gate is the
 * unit under test, so only `status()` and `recordDenied()` matter here.
 */
function services(permissionMode, status = STATUS, onDenied = undefined) {
  const denied = []
  return {
    denied,
    services: {
      getConfig: () => ({ permissionMode }),
      manager: {
        status: () => status,
        recordDenied: async (input) => {
          denied.push(input)
          if (onDenied !== undefined) await onDenied(input)
        },
      },
    },
  }
}

const exec = (confirm = false) => ({ name: 'jumpserver_exec', callId: 1, signal: new AbortController().signal, confirm })

// ---------------- BLOCKED: the rules said no ----------------

test('exec gate: a blocked command is recorded as BLOCKED, with the rule reason', async () => {
  const { services: svc, denied } = services('READ_ONLY')
  await assert.rejects(
    () => gateCommand(svc, exec(), 'rm -rf /tmp/x'),
    (error) => error.code === 'COMMAND_BLOCKED',
  )
  assert.equal(denied.length, 1, 'exactly one record — a refusal must not be logged twice')
  const record = denied[0]
  assert.equal(record.kind, 'blocked')
  assert.equal(record.operation, 'exec')
  assert.equal(record.command, 'rm -rf /tmp/x')
  assert.ok(
    record.risk === 'MODIFY' || record.risk === 'DANGEROUS',
    'the record must carry the classification that caused the refusal, got ' + record.risk,
  )
  assert.ok(record.reason.length > 0, 'a refusal without a reason is useless')
  assert.equal(record.toolCallId, '1', 'the record must be traceable to the MCP request')
})

test('run gate: a blocked command is recorded as BLOCKED', async () => {
  const { services: svc, denied } = services('READ_ONLY')
  await assert.rejects(
    () => gateCommandForNavigation(svc, exec(), 'rm -rf /tmp/x'),
    (error) => error.code === 'COMMAND_BLOCKED',
  )
  assert.equal(denied.length, 1)
  assert.equal(denied[0].operation, 'run')
  assert.equal(denied[0].kind, 'blocked')
})

test('batch gate: one blocked command is isolated AND recorded', async () => {
  const { services: svc, denied } = services('READ_ONLY')
  const gated = await gateCommandsForNavigation(svc, exec(), ['uptime', 'rm -rf /tmp/x', 'df -h'])
  assert.equal(gated.length, 3)
  assert.equal(gated[0].blocked, undefined)
  assert.equal(gated[1].blocked.code, 'COMMAND_BLOCKED')
  assert.equal(gated[2].blocked, undefined)
  assert.equal(denied.length, 0, 'batch拒绝由manager统一记录，gate不得重复写入')
})

test('a permitted command writes nothing to the refusal trail', async () => {
  const { services: svc, denied } = services('AUTO')
  const gated = await gateCommand(svc, exec(), 'uptime')
  assert.equal(gated.approvalRequired, false)
  assert.equal(denied.length, 0)
})

// ---------------- DENIED: nobody approved ----------------

test('exec gate: an unapproved command is recorded as DENIED', async () => {
  const { services: svc, denied } = services('AUTO')
  await assert.rejects(
    () => gateCommand(svc, exec(), UNKNOWN_CMD),
    (error) => error.code === 'COMMAND_APPROVAL_REQUIRED',
  )
  assert.equal(denied.length, 1)
  assert.equal(denied[0].kind, 'denied')
  assert.equal(denied[0].operation, 'exec')
  assert.equal(denied[0].reason, APPROVAL_DENIED_REASON)
})

test('exec gate: an APPROVED command is not a refusal', async () => {
  const { services: svc, denied } = services('AUTO')
  const gated = await gateCommand(svc, exec(true), UNKNOWN_CMD)
  assert.equal(gated.approvalRequired, true)
  assert.equal(denied.length, 0, 'confirm:true is agreement, not a refusal')
})

test('C7：审批detail提供脱敏拆分建议，复合依赖语法不建议', async () => {
  const { services: svc } = services('AUTO')
  await assert.rejects(() => gateCommand(svc, exec(), 'touch /tmp/a; uptime'), (error) => {
    assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
    assert.match(error.detail, /拆分诊断建议/)
    assert.match(error.detail, /重新提交完整门禁/)
    return true
  })
  await assert.rejects(() => gateCommand(svc, exec(), 'touch /tmp/a && uptime'), (error) => {
    assert.equal(error.detail, undefined)
    return true
  })
})

// ---------------- the record survives storage ----------------

test('a refusal record satisfies the stored audit schema', async () => {
  const { services: svc, denied } = services('READ_ONLY')
  await assert.rejects(() => gateCommand(svc, exec(), 'rm -rf /tmp/x'), () => true)
  const stored = toStructuredAuditRecord({
    timestamp: new Date().toISOString(),
    operation: denied[0].operation,
    gateway: 'gw:2222',
    target: null,
    hostname: null,
    command: denied[0].command,
    actor: 'AGENT',
    risk: denied[0].risk,
    classification: denied[0].classification,
    result: denied[0].kind === 'denied' ? 'DENIED' : 'BLOCKED',
    refusalReason: denied[0].reason,
    approvalRequired: denied[0].kind === 'denied',
    approvalResult: denied[0].kind === 'denied' ? 'denied' : 'none',
    exitCode: null,
    durationMs: null,
    permissionMode: 'READ_ONLY',
  })
  assert.equal(stored.result, 'BLOCKED')
  assert.ok(stored.refusalReason.length > 0)
})

test('a broken audit sink cannot turn a refusal into an approval', async () => {
  const { services: svc } = services('READ_ONLY', STATUS, async () => {
    throw new Error('disk full')
  })
  await assert.rejects(
    () => gateCommand(svc, exec(), 'rm -rf /tmp/x'),
    (error) => {
      // The point: still COMMAND_BLOCKED, not a swallowed error or a pass.
      assert.equal(error.code, 'COMMAND_BLOCKED')
      return true
    },
  )
})

// ---------------- manager paths (run / batch) ----------------

const MENU_SCREEN = [
  '┌──────────────────────────────────────────┐',
  '│  JumpServer · 堡垒机 / KoKo 终端          │',
  '│  1) app01                                 │',
  '│  2) app02                                 │',
  '│  请输入资产名或编号：                       │',
  '└──────────────────────────────────────────┘',
  'Opt> ',
].join('\n')

/** Answers the enter prompt from write(), so no timer races the detector. */
class FakeWire {
  constructor() {
    this.written = []
    this.cbs = []
    this.closeCbs = []
  }
  write(text) {
    this.written.push(text)
    if (/^(192\.168\.148\.36|app01)$/.test(text.trim())) {
      this._emit('\n[root@app01 ~]# ')
      return
    }
    const m = /__DSH_JS_PROBE_([0-9a-fA-F]+)/.exec(text)
    if (m !== null) {
      this._emit('\n__DSH_JS_PROBE_' + m[1] + '\nH=app01\nU=root\nP=/root\n__DSH_JS_PROBE_END_' + m[1] + '\n[root@app01 ~]# ')
      return
    }
    const done = /__DSH_JS_DONE_([0-9a-fA-F]+)/.exec(text)
    if (done !== null) this._emit('\n__DSH_JS_DONE_' + done[1] + (text.includes("command -v 'missingtool'") ? ':1' : ':0') + '\n[root@app01 ~]# ')
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

async function connectedManager(audits) {
  const wire = new FakeWire()
  const manager = new SessionManager({
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
  })
  const connecting = manager.connect()
  setTimeout(() => wire._emit(MENU_SCREEN), 20)
  await connecting
  return { manager, wire }
}

test('run: a refused beforeExec leaves a DENIED record and still fails', async () => {
  const audits = []
  const { manager } = await connectedManager(audits)
  const { services: svc } = services('AUTO')

  const gated = await gateCommandForNavigation(svc, exec(), UNKNOWN_CMD)
  assert.equal(gated.approvalRequired, true)
  assert.equal(typeof gated.beforeExec, 'function')

  await assert.rejects(
    () =>
      manager.run({
        target: '192.168.148.36',
        command: UNKNOWN_CMD,
        risk: gated.risk,
        classification: gated.classification,
        approvalRequired: gated.approvalRequired,
        approvalResult: 'pending',
        beforeExec: gated.beforeExec,
      }),
    (error) => {
      assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED', 'the refusal must still be a refusal')
      return true
    },
  )

  const denied = audits.filter((a) => a.result === 'DENIED')
  assert.equal(denied.length, 1, 'the manager path must record the denial exactly once')
  assert.equal(denied[0].command, UNKNOWN_CMD)
  assert.equal(denied[0].approvalResult, 'denied')
  assert.equal(denied[0].refusalReason, APPROVAL_DENIED_REASON)
  // …and nothing was executed: the PTY never received the command.
  assert.equal(audits.some((a) => a.result === 'SUCCESS' && a.command === UNKNOWN_CMD), false)
  await manager.close()
})

test('混合批次：前后只读均落线，被拒条不落线且逐条审计一次', async () => {
  const audits = []
  const { manager, wire } = await connectedManager(audits)
  const { services: svc, denied } = services('READ_ONLY')
  const commands = ['hostname', 'rm -rf /tmp/never-run', 'uptime']
  try {
    const gated = await gateCommandsForNavigation(svc, exec(), commands)
    const result = await manager.runTargetBatch({
      target: '192.168.148.36',
      commands: gated.map((g, i) => ({ command: commands[i], risk: g.risk, classification: g.classification,
        blocked: g.blocked, approvalRequired: g.approvalRequired, beforeExec: g.beforeExec })),
    })
    assert.equal(result.commands.length, 3)
    assert.equal(result.commands[0].commandStatus, 'SUCCESS')
    assert.equal(result.commands[1].error.code, 'COMMAND_BLOCKED')
    assert.equal(result.commands[2].commandStatus, 'SUCCESS')
    const writes = wire.written.join('\n')
    assert.ok(writes.includes('hostname'))
    assert.ok(writes.includes('uptime'))
    assert.equal(writes.includes('never-run'), false)
    assert.equal(denied.length, 0, 'gate不重复记录manager拥有的逐条审计')
    const perCommand = audits.filter((a) => a.operation === 'run-batch-cmd')
    assert.equal(perCommand.length, 3)
    assert.equal(perCommand.filter((a) => a.command === commands[1]).length, 1)
    assert.equal(perCommand[1].result, 'BLOCKED')
    assert.equal(perCommand[1].errorCode, 'COMMAND_BLOCKED')
    assert.ok(perCommand[1].refusalReason)
  } finally { await manager.close() }
})

test('C4：不存在命令不请求审批且不执行，后续命令继续', async () => {
  const audits = []
  const { manager, wire } = await connectedManager(audits)
  let approvals = 0
  try {
    const result = await manager.runTargetBatch({ target: '192.168.148.36', commands: [
      { command: 'missingtool -v', risk: 'UNKNOWN', beforeExec: async () => { approvals++ } },
      { command: 'uptime', risk: 'READ' },
    ] })
    assert.equal(result.commands[0].error.code, 'COMMAND_NOT_FOUND')
    assert.equal(result.commands[1].commandStatus, 'SUCCESS')
    assert.equal(approvals, 0)
    assert.equal(wire.written.some((text) => text.includes('missingtool -v')), false)
    assert.equal(audits.filter((a) => a.command === 'missingtool -v').length, 1)
  } finally { await manager.close() }
})

test('batch: a refused command is DENIED in the audit, not a generic error', async () => {
  const audits = []
  const { manager } = await connectedManager(audits)
  const { services: svc } = services('AUTO')

  const gated = await gateCommandsForNavigation(svc, exec(), [UNKNOWN_CMD])
  await manager.runTargetBatch({
    target: '192.168.148.36',
    commands: [
      {
        command: UNKNOWN_CMD,
        risk: gated[0].risk,
        classification: gated[0].classification,
        approvalRequired: true,
        approvalResult: 'pending',
        beforeExec: gated[0].beforeExec,
      },
    ],
  })

  const denied = audits.filter((a) => a.result === 'DENIED')
  assert.equal(denied.length, 1, '"stopped" must be distinguishable from "broke"')
  assert.equal(denied[0].approvalResult, 'denied')
  assert.equal(denied[0].refusalReason, APPROVAL_DENIED_REASON)
  await manager.close()
})
