/**
 * V0.5.7 risk judge tests — advisory-only semantic second opinion for UNKNOWN
 * commands (Jev / TypeSafe AI).
 *
 * The whole point of this layer is that it can never widen what runs, so the
 * tests assert the FAILURE paths harder than the happy path: disabled, no key,
 * timeout, non-2xx, malformed body, and a verdict that must never leak into a
 * non-UNKNOWN approval prompt.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  judgeCommandRisk,
  redactCommandForJudge,
  resetRiskJudgeCache,
  riskJudgeNote,
  riskJudgeSummary,
} from '../../lib/security/risk-judge.js'
import { gateCommand } from '../../lib/security/permission-gate.js'
import { UNKNOWN_COMMAND } from '../helpers/unknown-command.mjs'

const API_KEY_ENV = 'TYPESAFE_API_KEY'
process.env[API_KEY_ENV] = 'test-key'

function judgeCfg(overrides = {}) {
  return {
    enabled: true,
    endpoint: 'http://127.0.0.1:1/v1/systemone',
    apiKeyEnv: API_KEY_ENV,
    apiKeyFile: '',
    model: 'jev-latest',
    timeoutMs: 1500,
    cacheTtlSeconds: 3600,
    redactNetwork: true,
    ...overrides,
  }
}

/**
 * A verbatim-shaped System One answer. Every number here was MEASURED against
 * the live endpoint (`lsnrctl status`) — an invented fixture is what let the
 * V0.5.7 parser read the rubric as 1..5 when the API returns an expectation on
 * 0..4, and every verdict silently landed in the safest band.
 *   readOnly 0.91 · impact none (0.85) · risk 0.26 (0.78) · privilege 0.12
 */
const GOOD_ANSWERS = {
  answers: {
    read_only: { noul: 0.91 },
    impact: {
      choice: 'none',
      confidence: 0.85,
      probabilities: { none: 0.89, transient: 0.11, persistent: 0, destructive: 0 },
    },
    risk_level: { score: 0.26, confidence: 0.78, probabilities: { 0: 0.75, 1: 0.23, 2: 0.02, 3: 0, 4: 0 } },
    needs_privilege: { noul: 0.12 },
  },
}

/**
 * One mock System One endpoint. `mode` selects the failure being simulated.
 * Callers MUST await close() in a finally block — a leaked listener keeps the
 * event loop alive and hangs the whole node:test run.
 */
async function startMock(mode = 'ok') {
  const state = { hits: 0, bodies: [] }
  const server = createServer((req, res) => {
    state.hits += 1
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      state.bodies.push({ headers: req.headers, body })
      const send = () => {
        if (mode === 'status') {
          res.writeHead(500, { 'Content-Type': 'application/json' })
          res.end('{}')
          return
        }
        if (mode === 'malformed') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end('<html>not json</html>')
          return
        }
        if (mode === 'empty') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end('{"answers":{}}')
          return
        }
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(GOOD_ANSWERS))
      }
      if (mode === 'timeout') setTimeout(send, 400)
      else send()
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  return {
    endpoint: 'http://127.0.0.1:' + address.port + '/v1/systemone',
    state,
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

function fakeServices(riskJudge) {
  return {
    getConfig: () => ({ permissionMode: 'AUTO', riskJudge }),
    manager: {
      status: () => ({ state: 'ASSET_SHELL', target: '192.168.148.36', hostname: 'app01' }),
    },
  }
}

const exec = () => ({ name: 'jumpserver_run', callId: 1, signal: new AbortController().signal, confirm: false })

test('redactCommandForJudge: credentials are always masked', () => {
  const out = redactCommandForJudge('mysql -u root -pS3cret! --password=hunter2')
  assert.ok(!out.includes('S3cret!'))
  assert.ok(!out.includes('hunter2'))
})

test('redactCommandForJudge: IPs, FQDNs and home accounts are masked, system paths survive', () => {
  const out = redactCommandForJudge('scp /home/appadm/dump.dmp appadm@db01.corp:/backup/ && ls -l /etc/passwd')
  assert.ok(!out.includes('192.168'))
  assert.ok(!out.includes('db01.corp'))
  assert.ok(!out.includes('appadm/'))
  assert.ok(out.includes('/etc/passwd'), 'system paths carry the semantics and must survive')
})

test('judgeCommandRisk: disabled judge returns null and never sends a request', async () => {
  const mock = await startMock()
  try {
    resetRiskJudgeCache()
    const verdict = await judgeCommandRisk(UNKNOWN_COMMAND, judgeCfg({ enabled: false, endpoint: mock.endpoint }))
    assert.equal(verdict, null)
    assert.equal(mock.state.hits, 0)
  } finally {
    await mock.close()
  }
})

test('judgeCommandRisk: missing credential returns null and never sends a request', async () => {
  const mock = await startMock()
  const saved = process.env[API_KEY_ENV]
  try {
    resetRiskJudgeCache()
    delete process.env[API_KEY_ENV]
    const verdict = await judgeCommandRisk(UNKNOWN_COMMAND, judgeCfg({ endpoint: mock.endpoint }))
    assert.equal(verdict, null)
    assert.equal(mock.state.hits, 0)
  } finally {
    process.env[API_KEY_ENV] = saved
    await mock.close()
  }
})

test('judgeCommandRisk: the env var wins over the key file', async () => {
  const mock = await startMock()
  const dir = mkdtempSync(join(tmpdir(), 'riskjudge-'))
  try {
    const file = join(dir, 'api_key')
    writeFileSync(file, 'file-key\n', 'utf8')
    resetRiskJudgeCache()
    await judgeCommandRisk('hdb info', judgeCfg({ endpoint: mock.endpoint, apiKeyFile: file }))
    assert.equal(mock.state.bodies[0].headers.authorization, 'Bearer test-key')
  } finally {
    rmSync(dir, { recursive: true, force: true })
    await mock.close()
  }
})

test('judgeCommandRisk: falls back to the key file when the env var is empty', async () => {
  const mock = await startMock()
  const dir = mkdtempSync(join(tmpdir(), 'riskjudge-'))
  const saved = process.env[API_KEY_ENV]
  try {
    const file = join(dir, 'api_key')
    writeFileSync(file, 'file-key\r\n', 'utf8')
    delete process.env[API_KEY_ENV]
    resetRiskJudgeCache()
    const verdict = await judgeCommandRisk('hdb info', judgeCfg({ endpoint: mock.endpoint, apiKeyFile: file }))
    assert.ok(verdict !== null)
    assert.equal(mock.state.bodies[0].headers.authorization, 'Bearer file-key', 'trailing whitespace must be stripped')
  } finally {
    process.env[API_KEY_ENV] = saved
    rmSync(dir, { recursive: true, force: true })
    await mock.close()
  }
})

test('judgeCommandRisk: an unreadable key file degrades to null, never throws', async () => {
  const mock = await startMock()
  const saved = process.env[API_KEY_ENV]
  try {
    delete process.env[API_KEY_ENV]
    resetRiskJudgeCache()
    const missing = join(tmpdir(), 'riskjudge-definitely-absent', 'nope.key')
    assert.equal(await judgeCommandRisk('hdb info', judgeCfg({ endpoint: mock.endpoint, apiKeyFile: missing })), null)
    assert.equal(mock.state.hits, 0)
  } finally {
    process.env[API_KEY_ENV] = saved
    await mock.close()
  }
})

test('judgeCommandRisk: parses a typed verdict and sends a redacted state', async () => {
  const mock = await startMock()
  try {
    resetRiskJudgeCache()
    const verdict = await judgeCommandRisk('sshpass -p pw1 ssh appadm@192.168.148.61 hostname', judgeCfg({ endpoint: mock.endpoint }))
    assert.ok(verdict !== null)
    assert.equal(verdict.readOnly, 0.91)
    assert.equal(verdict.impact, 'none')
    // 0.26 is an EXPECTATION on the 0..4 rubric, so it sits in band 0.
    assert.equal(verdict.riskLevel, '随时可执行')
    assert.equal(verdict.safeProbability, 0.98, 'P(band 0)+P(band 1) is what auto-allow trusts')
    // The weakest answer decides the reported confidence (impact 0.85, rubric 0.78).
    assert.equal(verdict.confidence, 0.78)
    assert.equal(verdict.cached, false)

    const sent = JSON.parse(mock.state.bodies[0].body)
    assert.ok(!sent.state.includes('pw1'), 'credential must not leave the process')
    assert.ok(!sent.state.includes('192.168.148.61'), 'target IP must not leave the process')
    assert.ok(sent.state.includes('hostname'), 'the command itself is what is being judged')
    assert.ok(sent.model === 'jev-latest')
    assert.equal(Object.keys(sent.questions).length, 4)
    assert.equal(mock.state.bodies[0].headers.authorization, 'Bearer test-key')
  } finally {
    await mock.close()
  }
})

test('judgeCommandRisk: a repeated command is served from cache', async () => {
  const mock = await startMock()
  try {
    resetRiskJudgeCache()
    const cfg = judgeCfg({ endpoint: mock.endpoint })
    await judgeCommandRisk('hdb info', cfg)
    const second = await judgeCommandRisk('hdb info', cfg)
    assert.equal(mock.state.hits, 1)
    assert.equal(second.cached, true)
  } finally {
    await mock.close()
  }
})

test('judgeCommandRisk: timeout degrades to null', async () => {
  const mock = await startMock('timeout')
  try {
    resetRiskJudgeCache()
    const verdict = await judgeCommandRisk('hdb info', judgeCfg({ endpoint: mock.endpoint, timeoutMs: 100 }))
    assert.equal(verdict, null)
  } finally {
    await mock.close()
  }
})

test('judgeCommandRisk: non-2xx degrades to null', async () => {
  const mock = await startMock('status')
  try {
    resetRiskJudgeCache()
    assert.equal(await judgeCommandRisk('hdb info', judgeCfg({ endpoint: mock.endpoint })), null)
  } finally {
    await mock.close()
  }
})

test('judgeCommandRisk: malformed or incomplete payload degrades to null', async () => {
  for (const mode of ['malformed', 'empty']) {
    const mock = await startMock(mode)
    try {
      resetRiskJudgeCache()
      assert.equal(await judgeCommandRisk('hdb info', judgeCfg({ endpoint: mock.endpoint })), null)
    } finally {
      await mock.close()
    }
  }
})

test('judgeCommandRisk: an unreachable endpoint degrades to null', async () => {
  resetRiskJudgeCache()
  // Port 1 on loopback refuses immediately.
  const verdict = await judgeCommandRisk('hdb info', judgeCfg({ timeoutMs: 300 }))
  assert.equal(verdict, null)
})

test('riskJudgeNote: empty for no verdict, always disclaims the gate', () => {
  assert.deepEqual(riskJudgeNote(null), [])
  const note = riskJudgeNote({
    readOnly: 0.91,
    impact: 'none',
    riskScore: 0.26,
    riskLevel: '随时可执行',
    safeProbability: 0.98,
    needsPrivilege: 0,
    confidence: 0.78,
    cached: false,
    latencyMs: 12,
  })
  const text = note.join('\n')
  assert.ok(text.includes('不参与放行判定'))
  assert.ok(text.includes('不能代替人工确认'))
})

test('riskJudgeNote: an auto-allow refusal says so instead of claiming neutrality', () => {
  const verdict = {
    readOnly: 0.62,
    impact: 'transient',
    riskScore: 2,
    riskLevel: '需知会属主',
    safeProbability: 0.4,
    needsPrivilege: 0.5,
    confidence: 0.6,
    cached: false,
    latencyMs: 20,
  }
  const neutral = riskJudgeNote(verdict).join('\n')
  assert.ok(neutral.includes('不参与放行判定'))
  const withAuto = riskJudgeNote(verdict, { autoAllowEnabled: true, autoAllowRefusal: '只读把握 0.62 < 0.9' }).join('\n')
  // With auto-allow on, a prompt that appears must explain why the command was
  // NOT cleared automatically — otherwise the two cases look identical.
  assert.ok(withAuto.includes('自动放行未通过'))
  assert.ok(withAuto.includes('只读把握 0.62 < 0.9'))
  assert.ok(withAuto.includes('仍需人工确认'))
})

test('riskJudgeSummary: one line, used for batch prompts', () => {
  const summary = riskJudgeSummary({
    readOnly: 0.4,
    impact: 'persistent',
    riskScore: 3,
    riskLevel: '需变更窗口',
    safeProbability: null,
    needsPrivilege: 0.9,
    confidence: 0.5,
    cached: false,
    latencyMs: 0,
  })
  assert.ok(!summary.includes('\n'))
  assert.ok(summary.includes('需变更窗口'))
  assert.ok(summary.includes('持久状态改变'))
  // 0-based expectation rendered as the 1-based band humans think in.
  assert.ok(summary.includes('风险档 4/5'))
})

test('gate: an UNKNOWN command gets the advisory note appended', async () => {
  const mock = await startMock()
  try {
    resetRiskJudgeCache()
    const services = fakeServices(judgeCfg({ endpoint: mock.endpoint }))
    await assert.rejects(
      () => gateCommand(services, exec(), UNKNOWN_COMMAND),
      (error) => {
        assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
        assert.ok(error.message.includes('语义副驾'), 'advisory block missing')
        assert.ok(error.message.includes('不参与放行判定'), 'the copy must not imply the model decided')
        assert.ok(error.message.includes('是否允许本次执行'), 'the human question must survive')
        return true
      },
    )
    assert.equal(mock.state.hits, 1)
  } finally {
    await mock.close()
  }
})

test('C9：MODIFY可获取模型参考但仍要求人工审批', async () => {
  const mock = await startMock()
  try {
    resetRiskJudgeCache()
    const services = fakeServices(judgeCfg({ endpoint: mock.endpoint }))
    await assert.rejects(
      () => gateCommand(services, exec(), 'rm -rf /tmp/x'),
      (error) => {
        assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
        assert.match(error.message, /仅供参考，不参与放行判定/)
        return true
      },
    )
    assert.equal(mock.state.hits, 1, 'MODIFY模型意见仅用于审批参考')
  } finally {
    await mock.close()
  }
})

test('gate: a disabled judge leaves the approval copy exactly as before', async () => {
  const mock = await startMock()
  try {
    resetRiskJudgeCache()
    const services = fakeServices(judgeCfg({ enabled: false, endpoint: mock.endpoint }))
    await assert.rejects(
      () => gateCommand(services, exec(), UNKNOWN_COMMAND),
      (error) => {
        assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
        assert.ok(!error.message.includes('语义副驾'))
        assert.ok(error.message.includes('无法确认该命令是否为只读'))
        return true
      },
    )
    assert.equal(mock.state.hits, 0)
  } finally {
    await mock.close()
  }
})

test('gate: a broken judge still produces the plain UNKNOWN prompt', async () => {
  const mock = await startMock('status')
  try {
    resetRiskJudgeCache()
    const services = fakeServices(judgeCfg({ endpoint: mock.endpoint }))
    await assert.rejects(
      () => gateCommand(services, exec(), UNKNOWN_COMMAND),
      (error) => {
        assert.equal(error.code, 'COMMAND_APPROVAL_REQUIRED')
        assert.ok(!error.message.includes('语义副驾'))
        return true
      },
    )
    assert.equal(mock.state.hits, 1)
  } finally {
    await mock.close()
  }
})
