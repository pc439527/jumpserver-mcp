/**
 * V0.6.1 (B-1 / B-4 / B-5) — the argument-shape and tool-surface contracts,
 * observed END TO END over real MCP stdio.
 *
 * WHY THIS FILE EXISTS
 *
 * N-04 (2026-10-22): `jumpserver_batch` "反复报 `/tasks: must be array`" while
 * `jumpserver_run` worked fine. The batch tool was never broken — the
 * ARGUMENT SHAPE was. And the SDK validates arguments with zod BEFORE the
 * handler runs (`McpServer.validateToolInput` -> `safeParseAsync`), so a
 * string in an array slot never reaches connector code: the tool looks dead
 * while the connector is fine.
 *
 * The unit tests in `arg-normalize.test.mjs` freeze the normalization rules.
 * THIS file freezes the OBSERVABLE contract:
 *
 *  1. a comma separated string in a `targets` slot is ACCEPTED and behaves
 *     exactly like the array form (B-1);
 *  2. the `tasks` slot accepts the array, the single object, the JSON string
 *     and the nested shape (B-1);
 *  3. a list argument of the WRONG type produces an error that says HOW to
 *     call the tool (B-5);
 *  4. `jumpserver_status` reports the tool surface and the console ownership
 *     (B-4) — the answer to "the host says connected but there are zero
 *     sub-tools".
 *
 * Reading end-to-end matters here: the failing layer in N-04 was the SDK's
 * validation, which no unit test of the connector could have observed.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { MISSING_CONFIG, openServer, BLANK_CONNECTION_ENV } from '../helpers/mcp.mjs'

const require = createRequire(import.meta.url)

/**
 * The published input schema of a tool, straight off `tools/list`.
 */
function schemaOf(tools, name) {
  const tool = tools.find((t) => t.name === name)
  assert.ok(tool !== undefined, 'tool ' + name + ' is not published')
  return tool.inputSchema
}

/**
 * The error text the SDK produced for a rejected call.
 */
function errorText(result) {
  if (result?.isError !== true) return null
  const content = result?.content
  if (!Array.isArray(content)) return null
  return content.map((c) => c?.text ?? '').join('\n')
}

test('B-1: the published schemas admit BOTH the array form and the string form', async () => {
  // This is the contract that actually matters, and it was found the hard
  // way: the host validates tool arguments with AJV BEFORE the MCP call is
  // sent (`validateParams` in the host CLI bundle, `new Ajv({allErrors:true,
  // coerceTypes:true})`). `coerceTypes` does NOT turn a string into an
  // array, so a published array-only schema makes the call fail in the host
  // with "must be array" and the connector never sees the argument.
  //
  // So the published schema MUST publish a union that admits the string.
  // The array branch is still there and still carries the item bounds, so
  // the model keeps seeing "an array of strings" as the primary shape.
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    for (const name of ['jumpserver_inspect', 'jumpserver_topology', 'jumpserver_profile_run', 'jumpserver_compare', 'jumpserver_baseline_capture']) {
      const schema = schemaOf(server.tools, name)
      const targets = schema.properties.targets
      assert.ok(Array.isArray(targets.anyOf), name + '.targets must publish a union that admits the string form')
      const arrayBranch = targets.anyOf.find((b) => b.type === 'array')
      const stringBranch = targets.anyOf.find((b) => b.type === 'string')
      assert.ok(arrayBranch !== undefined, name + '.targets must keep the array branch')
      assert.ok(stringBranch !== undefined, name + '.targets must admit the string branch')
      assert.equal(arrayBranch.items.type, 'string', name + '.targets items must still be strings')
    }
    const batch = schemaOf(server.tools, 'jumpserver_batch')
    assert.ok(Array.isArray(batch.properties.tasks.anyOf), 'batch.tasks must publish a union')
    const tasksArray = batch.properties.tasks.anyOf.find((b) => b.type === 'array')
    assert.ok(tasksArray !== undefined)
    assert.ok(Array.isArray(tasksArray.items.properties.commands.anyOf), 'batch.tasks[].commands must publish a union')
  } finally {
    server.close()
  }
})

test('B-1: the published schemas pass the host-side AJV gate for both forms', async () => {
  // Reproduces the host's own validator against the REAL published schema
  // of every list-shaped argument. This is the gate that produced the N-04
  // "must be array" rejection, so it is the contract that has to hold.
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const Ajv = require('ajv')
    const cases = [
      ['jumpserver_inspect', { targets: '1.1.1.1,2.2.2.2' }],
      ['jumpserver_inspect', { targets: ['1.1.1.1', '2.2.2.2'] }],
      ['jumpserver_compare', { targets: '1.1.1.1,2.2.2.2' }],
      ['jumpserver_topology', { targets: '1.1.1.1' }],
      ['jumpserver_batch', { tasks: '[{"target":"1.1.1.1","commands":["uptime"]}]' }],
      ['jumpserver_batch', { tasks: [{ target: '1.1.1.1', commands: ['uptime'] }] }],
    ]
    for (const [name, args] of cases) {
      const schema = schemaOf(server.tools, name)
      const validate = new Ajv({ allErrors: true, coerceTypes: true }).compile(schema)
      const ok = validate(args)
      assert.equal(ok, true, name + ' must pass the host AJV gate for ' + JSON.stringify(args) + ' — errors: ' + JSON.stringify(validate.errors))
    }
  } finally {
    server.close()
  }
})

test('B-1: a comma separated targets string is ACCEPTED (it used to be rejected outright)', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    // With no configuration the call cannot reach the bastion, but it MUST
    // get past ARGUMENT VALIDATION — that is the N-04 failure point. The
    // error we get back must therefore be a CONNECTION error, never
    // "Input validation error".
    const { result, text } = await server.call('jumpserver_inspect', { targets: '1.1.1.1,2.2.2.2' })
    // The call MUST get past argument validation. Whatever the outcome after
    // that (here: no configuration), it must not be a schema rejection — that
    // is the N-04 failure.
    assert.doesNotMatch(text, /Input validation error/, 'the string form was rejected by the schema')
    assert.doesNotMatch(String(errorText(result) ?? ''), /Input validation error/)
    assert.match(text, /code: CONFIG_INCOMPLETE/, 'the call must have reached the handler')
  } finally {
    server.close()
  }
})

test('B-1: the string form and the array form fail IDENTICALLY (same validation path)', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const fromString = await server.call('jumpserver_inspect', { targets: '1.1.1.1,2.2.2.2' })
    const fromArray = await server.call('jumpserver_inspect', { targets: ['1.1.1.1', '2.2.2.2'] })
    assert.equal(fromString.text, fromArray.text, 'the two forms must reach the same code path')
  } finally {
    server.close()
  }
})

test('B-1: a single target string is accepted too', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_inspect', { targets: '1.1.1.1' })
    assert.doesNotMatch(text, /Input validation error/)
    assert.match(text, /code: CONFIG_INCOMPLETE/, 'the call must have reached the handler')
  } finally {
    server.close()
  }
})

test('B-1: the batch tasks slot accepts the nested shape N-04 reported', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_batch', {
      tasks: [[{ target: '1.1.1.1', commands: ['uptime'] }]],
    })
    assert.doesNotMatch(text, /must be array/, 'the nested tasks shape must be accepted')
    assert.doesNotMatch(text, /Input validation error/)
    assert.match(text, /code: CONFIG_INCOMPLETE/, 'the call must have reached the handler')
  } finally {
    server.close()
  }
})

test('B-1: the batch tasks slot accepts a JSON string', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_batch', {
      tasks: '[{"target":"1.1.1.1","commands":["uptime"]}]',
    })
    assert.doesNotMatch(text, /must be array/)
    assert.doesNotMatch(text, /Input validation error/)
    assert.match(text, /code: CONFIG_INCOMPLETE/, 'the call must have reached the handler')
  } finally {
    server.close()
  }
})

test('B-1: a single task OBJECT is accepted', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_batch', {
      tasks: { target: '1.1.1.1', commands: ['uptime'] },
    })
    assert.doesNotMatch(text, /must be array/)
    assert.doesNotMatch(text, /Input validation error/)
    assert.match(text, /code: CONFIG_INCOMPLETE/, 'the call must have reached the handler')
  } finally {
    server.close()
  }
})

test('B-1: a task\'s commands accept a newline separated string', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_batch', {
      tasks: [{ target: '1.1.1.1', commands: 'uptime\ndf -h' }],
    })
    assert.doesNotMatch(text, /Input validation error/)
    assert.match(text, /code: CONFIG_INCOMPLETE/, 'the call must have reached the handler')
  } finally {
    server.close()
  }
})

test('B-5: a wrong-typed list argument explains HOW to call the tool', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { result } = await server.call('jumpserver_inspect', { targets: 42 })
    const text = errorText(result)
    assert.ok(text !== null, 'a wrong-typed argument must produce an error')
    assert.match(text, /comma-separated string/, 'the error must state the accepted string form')
    assert.match(text, /targets/, 'the error must name the offending field')
  } finally {
    server.close()
  }
})

test('B-4: jumpserver_status reports the tool surface', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_status', {})
    assert.match(text, /tools: 23\/23 registered/, 'the status must report the published tool count')
    assert.match(text, /console: role=/, 'the status must report the console ownership')
  } finally {
    server.close()
  }
})

test('B-4: the tool count in the status matches the published tool table', async () => {
  const server = await openServer({ configPath: MISSING_CONFIG, env: BLANK_CONNECTION_ENV })
  try {
    const { text } = await server.call('jumpserver_status', {})
    const match = /tools: (\d+)\/(\d+) registered/.exec(text)
    assert.ok(match !== null, 'no tool count in the status output: ' + text)
    assert.equal(Number(match[1]), server.tools.length, 'the status reports a different tool count than tools/list published')
    assert.equal(Number(match[2]), 23, 'the expected always-on tool count drifted')
  } finally {
    server.close()
  }
})
