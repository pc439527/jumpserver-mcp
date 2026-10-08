/**
 * V0.5.2: the tool table has a PRICE, and the price is paid every conversation.
 *
 * An MCP host injects the whole `tools/list` payload into the model's context
 * before the first user message, so every byte here is a permanent tax on every
 * chat — including chats that never touch JumpServer. That makes the payload a
 * resource with a budget, and budgets need a gate or they drift one
 * well-meaning description at a time.
 *
 * What this file is NOT: a target of "as small as possible". Trimming a
 * description that tells the model WHICH tool to pick costs far more than the
 * hundred bytes it saves — a wrong tool choice burns thousands of tokens and a
 * retry. So the ceiling is deliberately loose enough to allow prose edits and
 * tight enough that adding tools or fattening parameters has to be a decision
 * someone makes on purpose.
 *
 * Measured numbers:
 *   V0.5.2 (23 tools, no account selection)         21,673 B (~5,418 tokens)
 *   V0.5.3 (23 tools, accountIndex/accountByTarget) 23,499 B (~5,875 tokens)
 *
 * The V0.5.3 bump is the cost of the KoKo `ID>` selection plumbing: 7
 * multi-target tools gained `accountByTarget` and 3 single-target tools gained
 * `accountIndex`. Each entry is ~100 B; the rest is the leading prose in the
 * schemas. The budget ceiling follows deliberately.
 *
 * The remaining large lever is CONSOLIDATION — merging the six multi-target
 * survey tools (inspect / compare / topology / profile_run / baseline_capture /
 * baseline_compare = 7.6 KB, 35% of the payload) behind one `mode` parameter.
 * That would save roughly 3-4 KB but renames the entire public tool surface, so
 * it is a product decision, not a mechanical one, and is deliberately NOT taken
 * here. This test exists so the number stays visible either way.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MISSING_CONFIG, openServer, BLANK_CONNECTION_ENV } from '../helpers/mcp.mjs'

/** Ceiling for `JSON.stringify(tools)`, in bytes. ~5% headroom over V0.5.3. */
const PAYLOAD_BUDGET_BYTES = 24500

/** No single tool may cost more than this (largest today: jumpserver_inspect). */
const PER_TOOL_BUDGET_BYTES = 1700

function bytesOf(text) {
  return Buffer.byteLength(text)
}

async function measure() {
  // config.example.json is not needed: the tool table is published even with no
  // configuration at all (that is the whole point of the deferred refusal).
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    return server.tools
  } finally {
    server.close()
  }
}

test('the published tool table stays inside its context budget', async () => {
  const tools = await measure()
  const payload = JSON.stringify(tools)
  const size = bytesOf(payload)
  assert.ok(
    size <= PAYLOAD_BUDGET_BYTES,
    'tools/list payload is ' + size + ' B, over the ' + PAYLOAD_BUDGET_BYTES + ' B budget — ' +
      'every conversation pays for this. Either trim, or raise the budget deliberately.',
  )
})

test('no single tool carries an outsized share of the payload', async () => {
  const tools = await measure()
  for (const tool of tools) {
    const size = bytesOf(tool.description ?? '') + bytesOf(JSON.stringify(tool.inputSchema ?? {}))
    assert.ok(size <= PER_TOOL_BUDGET_BYTES, tool.name + ' costs ' + size + ' B, over the per-tool budget')
  }
})

test('every byte of the payload is accounted for by a description or a schema', async () => {
  const tools = await measure()
  const described = tools.reduce(
    (sum, t) => sum + bytesOf(t.description ?? '') + bytesOf(JSON.stringify(t.inputSchema ?? {})),
    0,
  )
  const payload = bytesOf(JSON.stringify(tools))

  // The difference is the wrapper: `name`, `title`, `annotations`, `execution`
  // and the JSON punctuation between them (~190 B per tool, ~17% today). The
  // assertion is a METER SANITY CHECK, not a budget: if the two ways of
  // counting stop roughly agreeing, the numbers this file gates on are wrong.
  const overhead = (payload - described) / payload
  assert.ok(
    overhead >= 0 && overhead < 0.25,
    'wrapper overhead is ' + Math.round(overhead * 100) + '% of ' + payload + ' B — the meter disagrees with itself',
  )
  assert.ok(
    described / payload > 0.7,
    'descriptions + schemas are only ' + Math.round((described / payload) * 100) + '% of the payload — ' +
      'something else has become expensive and this budget does not model it',
  )
})
