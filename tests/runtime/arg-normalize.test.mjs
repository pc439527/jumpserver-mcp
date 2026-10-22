/**
 * B-2 — the argument normalizers, unit-tested.
 *
 * These functions are the LOAD-BEARING part of the N-04 fix: they decide what
 * a "list" argument means when the client sends something that is not a list.
 * The behaviour is therefore a contract, and this file freezes it:
 *
 *   - comma / semicolon / tab / newline separated strings are split;
 *   - a SPACE is not a separator (asset names may contain spaces);
 *   - empty items are dropped, duplicates removed, order preserved;
 *   - a nested array is flattened one level;
 *   - commands split on NEWLINES only (a command may contain commas and
 *     spaces — `df -h | sort` is one command, not two);
 *   - `tasks` accepts an array, a single object, a JSON string, and a nested
 *     array (the shape N-04 reported).
 *
 * The published JSON Schema DOES admit the string form — see the "THE
 * POINT" test below. That is not cosmetic: the host validates the tool
 * arguments with AJV BEFORE the MCP call is sent, and `coerceTypes: true`
 * does not turn a string into an array. A published array-only schema
 * therefore rejects the call in the host, and this module's normalization
 * never runs.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { z } from 'zod'
import { toJsonSchemaCompat } from '@modelcontextprotocol/sdk/server/zod-json-schema-compat.js'
import { normalizeObjectSchema } from '@modelcontextprotocol/sdk/server/zod-compat.js'
import {
  commandListSchema,
  normalizeCommandList,
  normalizeStringList,
  normalizeTaskList,
  optionalStringListSchema,
  splitListText,
  stringListSchema,
  taskListSchema,
} from '../../lib/runtime/arg-normalize.js'

const require = createRequire(import.meta.url)

test('a comma separated string becomes a list', () => {
  assert.deepEqual(normalizeStringList('1.1.1.1,2.2.2.2'), ['1.1.1.1', '2.2.2.2'])
})

test('semicolons, tabs and newlines separate too', () => {
  assert.deepEqual(normalizeStringList('a;b'), ['a', 'b'])
  assert.deepEqual(normalizeStringList('a\tb'), ['a', 'b'])
  assert.deepEqual(normalizeStringList('a\nb'), ['a', 'b'])
})

test('surrounding whitespace and empty items are dropped', () => {
  assert.deepEqual(normalizeStringList('  1.1.1.1 , , 2.2.2.2  '), ['1.1.1.1', '2.2.2.2'])
  assert.deepEqual(normalizeStringList(''), [])
  assert.deepEqual(normalizeStringList('   '), [])
})

test('a space is NOT a separator — asset names may contain spaces', () => {
  assert.deepEqual(splitListText('Web Server 01'), ['Web Server 01'])
  assert.deepEqual(normalizeStringList('Web Server 01'), ['Web Server 01'])
})

test('but a whitespace separated list of IPv4 literals IS expanded', () => {
  assert.deepEqual(normalizeStringList('1.1.1.1 2.2.2.2'), ['1.1.1.1', '2.2.2.2'])
})

test('a non-IP whitespace list stays one item', () => {
  assert.deepEqual(normalizeStringList('Web Server 01'), ['Web Server 01'])
})

test('duplicates are removed and the first occurrence wins', () => {
  assert.deepEqual(normalizeStringList('1.1.1.1,2.2.2.2,1.1.1.1'), ['1.1.1.1', '2.2.2.2'])
  assert.deepEqual(normalizeStringList(['b', 'a', 'b']), ['b', 'a'])
})

test('an array of strings passes through, trimmed', () => {
  assert.deepEqual(normalizeStringList([' 1.1.1.1 ', '2.2.2.2']), ['1.1.1.1', '2.2.2.2'])
})

test('a nested array is flattened one level', () => {
  assert.deepEqual(normalizeStringList([['1.1.1.1', '2.2.2.2'], '3.3.3.3']), ['1.1.1.1', '2.2.2.2', '3.3.3.3'])
})

test('an empty array stays empty', () => {
  assert.deepEqual(normalizeStringList([]), [])
})

test('a non-string, non-array value is left untouched so zod reports the type error', () => {
  assert.equal(normalizeStringList(42), 42)
  assert.equal(normalizeStringList(null), null)
  assert.equal(normalizeStringList(undefined), undefined)
  const obj = { a: 1 }
  assert.equal(normalizeStringList(obj), obj)
})

test('commands split on NEWLINES only — commas and spaces belong to the command', () => {
  assert.deepEqual(normalizeCommandList('df -h | sort'), ['df -h | sort'])
  assert.deepEqual(normalizeCommandList('a, b'), ['a, b'])
  assert.deepEqual(normalizeCommandList('uptime\ndf -h'), ['uptime', 'df -h'])
  assert.deepEqual(normalizeCommandList('  uptime  \n\n  df -h  '), ['uptime', 'df -h'])
})

test('commands keep duplicates — running the same command twice is legal', () => {
  assert.deepEqual(normalizeCommandList('uptime\nuptime'), ['uptime', 'uptime'])
})

test('tasks accept an array of task objects', () => {
  const tasks = normalizeTaskList([{ target: '1.1.1.1', commands: ['uptime'] }])
  assert.deepEqual(tasks, [{ target: '1.1.1.1', commands: ['uptime'] }])
})

test('tasks accept a single task object', () => {
  const tasks = normalizeTaskList({ target: '1.1.1.1', commands: ['uptime'] })
  assert.deepEqual(tasks, [{ target: '1.1.1.1', commands: ['uptime'] }])
})

test('tasks accept a JSON string', () => {
  const tasks = normalizeTaskList('[{"target":"1.1.1.1","commands":["uptime"]}]')
  assert.deepEqual(tasks, [{ target: '1.1.1.1', commands: ['uptime'] }])
})

test('tasks accept the NESTED shape that produced "/tasks: must be array"', () => {
  const tasks = normalizeTaskList([[{ target: '1.1.1.1', commands: ['uptime'] }]])
  assert.deepEqual(tasks, [{ target: '1.1.1.1', commands: ['uptime'] }])
})

test('a task\'s commands are normalized in every accepted shape', () => {
  assert.deepEqual(
    normalizeTaskList([{ target: '1.1.1.1', commands: 'uptime\ndf -h' }]),
    [{ target: '1.1.1.1', commands: ['uptime', 'df -h'] }],
  )
  assert.deepEqual(
    normalizeTaskList([{ target: '1.1.1.1', commands: [['uptime']] }]),
    [{ target: '1.1.1.1', commands: ['uptime'] }],
  )
})

test('a task target is trimmed', () => {
  assert.deepEqual(
    normalizeTaskList([{ target: '  1.1.1.1  ', commands: ['uptime'] }]),
    [{ target: '1.1.1.1', commands: ['uptime'] }],
  )
})

test('an unparseable tasks string is left untouched so zod reports it', () => {
  assert.equal(normalizeTaskList('not json'), 'not json')
  assert.equal(normalizeTaskList('{broken'), '{broken')
})

test('the schema accepts the string form and yields the same array', () => {
  const schema = stringListSchema({ min: 1, max: 20, field: 'targets', example: '1.1.1.1' })
  const fromString = schema.safeParse('1.1.1.1,2.2.2.2')
  const fromArray = schema.safeParse(['1.1.1.1', '2.2.2.2'])
  assert.equal(fromString.success, true)
  assert.equal(fromArray.success, true)
  assert.deepEqual(fromString.data, fromArray.data)
})

test('the schema rejects an empty list with the B-5 hint', () => {
  const schema = stringListSchema({ min: 1, max: 20, field: 'targets', example: '1.1.1.1' })
  const result = schema.safeParse([])
  assert.equal(result.success, false)
  assert.match(result.error.issues[0].message, /comma-separated string/)
  assert.match(result.error.issues[0].message, /targets/)
})

test('the schema rejects a wrong type with the B-5 hint', () => {
  const schema = stringListSchema({ min: 1, max: 20, field: 'targets', example: '1.1.1.1' })
  const result = schema.safeParse(42)
  assert.equal(result.success, false)
  assert.match(result.error.issues[0].message, /comma-separated string/)
})

test('the optional schema still accepts undefined', () => {
  const schema = optionalStringListSchema({ field: 'targets', example: '1.1.1.1' })
  const result = schema.safeParse(undefined)
  assert.equal(result.success, true)
  assert.equal(result.data, undefined)
})

test('the command schema accepts a newline separated string', () => {
  const schema = commandListSchema({ field: 'commands' })
  const result = schema.safeParse('uptime\ndf -h')
  assert.equal(result.success, true)
  assert.deepEqual(result.data, ['uptime', 'df -h'])
})

test('THE POINT: the published JSON Schema admits the string form, because the host gates on it', () => {
  // The host validates the tool arguments with AJV BEFORE the MCP call is
  // sent (app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs -> validateParams).
  // `coerceTypes: true` does NOT turn a string into an array, so a published
  // array-only schema makes the connector's normalization dead code: the host
  // rejects the call with "must be array" and the connector never sees it.
  //
  // This test freezes that finding: the published schema MUST accept a
  // string, and it must be a real JSON-Schema union (not a zod-only trick).
  const tolerant = normalizeObjectSchema({
    targets: stringListSchema({ min: 1, max: 20, field: 'targets', example: '1.1.1.1' }).describe('Target IPs or asset names (max 20).'),
  })
  const options = { strictUnions: true, pipeStrategy: 'input' }
  const published = toJsonSchemaCompat(tolerant, options)
  const targets = published.properties.targets

  assert.ok(Array.isArray(targets.anyOf), 'targets must publish an anyOf that admits the string form')
  const arrayBranch = targets.anyOf.find((b) => b.type === 'array')
  const stringBranch = targets.anyOf.find((b) => b.type === 'string')
  assert.ok(arrayBranch !== undefined, 'the array branch must survive')
  assert.ok(stringBranch !== undefined, 'the string branch must survive')
  assert.equal(arrayBranch.items.type, 'string')
  assert.equal(arrayBranch.minItems, 1)
  assert.equal(arrayBranch.maxItems, 20)
})

test('the published schema passes the host-side AJV gate for the string form', () => {
  // Reproduces the host's own validator (ajv 8, allErrors + coerceTypes)
  // against the published schema. This is the gate that produced the N-04
  // "must be array" rejection.
  const Ajv = require('ajv')
  const published = toJsonSchemaCompat(
    normalizeObjectSchema({ targets: stringListSchema({ min: 1, max: 20, field: 'targets', example: '1.1.1.1' }) }),
    { strictUnions: true, pipeStrategy: 'input' },
  )
  const validate = new Ajv({ allErrors: true, coerceTypes: true }).compile(published)

  assert.equal(validate({ targets: '1.1.1.1,2.2.2.2' }), true, 'the string form must pass the host gate')
  assert.equal(validate({ targets: ['1.1.1.1'] }), true, 'the array form must pass the host gate')
})

test('the connector still normalizes the string into an array, and the bounds still apply', () => {
  // The published union is only the admission ticket — the connector's own
  // parse must still hand the handler a `string[]` and still enforce the
  // bounds against the NORMALIZED list.
  const schema = stringListSchema({ min: 2, max: 20, field: 'targets', example: '1.1.1.1' })
  const ok = schema.safeParse('1.1.1.1,2.2.2.2')
  assert.equal(ok.success, true)
  assert.deepEqual(ok.data, ['1.1.1.1', '2.2.2.2'])

  // A string that expands to ONE item must still trip `min(2)`. The string
  // branch of the union must not become a way around the bounds — that would
  // be a fail-closed violation (compare needs >= 2 targets).
  const tooFew = schema.safeParse('1.1.1.1')
  assert.equal(tooFew.success, false)
  assert.match(tooFew.error.issues[0].message, /comma-separated string/)
})

test('the string form cannot bypass the max bound either', () => {
  const schema = stringListSchema({ min: 1, max: 3, field: 'targets', example: '1.1.1.1' })
  assert.equal(schema.safeParse('a,b,c').success, true)
  assert.equal(schema.safeParse('a,b,c,d').success, false)
  assert.equal(schema.safeParse(['a', 'b', 'c', 'd']).success, false)
})

test('the tasks schema rejects a string that is not JSON, and keeps min(1)', () => {
  const schema = taskListSchema({
    element: z.object({ target: z.string(), commands: z.array(z.string()) }),
    field: 'tasks',
    example: '[{"target":"1.1.1.1","commands":["uptime"]}]',
  })
  // A JSON string is accepted and normalized.
  const ok = schema.safeParse('[{"target":"a","commands":["uptime"]}]')
  assert.equal(ok.success, true)
  assert.equal(Array.isArray(ok.data), true)
  assert.equal(ok.data.length, 1)
  // A non-JSON string must NOT slip through the string branch.
  assert.equal(schema.safeParse('not json').success, false)
  // `min(1)` must still apply to the string form: "[]" normalizes to [].
  assert.equal(schema.safeParse('[]').success, false)
})
