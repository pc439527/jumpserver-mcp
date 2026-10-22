/**
 * V0.6.1 (B-1/B-5) — argument normalization for array-shaped tool inputs.
 *
 * WHY THIS EXISTS
 *
 * A client (WorkBuddy's MCP call layer, or any other host) sometimes hands an
 * array-shaped argument as a STRING, or hands the whole `tasks` array as a
 * JSON string, or nests one level deeper than the schema allows. The MCP SDK
 * validates the arguments with zod BEFORE the handler runs
 * (`McpServer.validateToolInput` -> `safeParseAsync`), so a string in an
 * array slot is rejected as `InvalidParams` and the handler NEVER SEES IT.
 * The tool then looks "broken" while the connector itself is fine.
 *
 * The real-world case is N-04 (2026-10-22): `jumpserver_batch` kept failing
 * with `/tasks: must be array` while `jumpserver_run` worked fine — the batch
 * path was never broken, only the ARGUMENT SHAPE was.
 *
 * WHY THE PUBLISHED SCHEMA MUST ACCEPT THE STRING TOO
 *
 * The FIRST gate is NOT in this connector. The host validates the tool
 * arguments with AJV BEFORE the MCP call is ever sent:
 *
 *   app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs
 *     async validateParams(t, i, s) {
 *       ... this.ajv ??= i(new t({ allErrors: !0, coerceTypes: !0 }))
 *       ... return { content: `Parameter validation failed for tool "${s}": ${t}` }
 *     }
 *
 * `coerceTypes: true` only coerces NUMBERS (and booleans) — it does NOT
 * turn a string into an array. Verified against the same ajv 8.20.0:
 *
 *   {type:'array', items:{type:'string'}}  +  "1.1.1.1,2.2.2.2"  =>  FAIL
 *                                                               "must be array"
 *   {anyOf:[{type:'array'...},{type:'string'}]} + "1.1.1.1,2.2.2.2" => PASS
 *
 * "must be array" is AJV's wording; zod would say "Expected array, received
 * string". The N-04 reports quoted exactly `must be array`, which places the
 * rejection in the HOST, before the request reaches us.
 *
 * CONSEQUENCE: a published array-only schema makes this module's
 * normalization DEAD CODE — the host rejects the call and the connector
 * never sees the argument. The published schema therefore has to accept
 * the string form itself (`anyOf`), and the normalization below turns it
 * into an array before the connector's own bounds checks run.
 *
 * WHY `z.preprocess` IS STILL NEEDED
 *
 * `anyOf` in the published schema is only the ADMISSION ticket. Once the
 * host lets the call through, the value is still a string (AJV does not
 * rewrite it), and the connector's own zod parse would hand a string to
 * the handler. The preprocess below normalizes it to an array FIRST, so
 * the handler always receives `string[]` and the `.min()` / `.max()`
 * bounds are enforced against the NORMALIZED list — a string that
 * expands to zero items is still rejected.
 *
 * SEPARATORS — deliberately conservative
 *
 * Hard separators: comma, semicolon, tab, CR, LF.
 * A SPACE is NOT a separator, because asset names may contain spaces
 * ("Web Server 01") and splitting on whitespace would silently shred them.
 * The one exception: a segment whose whitespace-split parts are ALL IPv4
 * literals is expanded, so "1.1.1.1 2.2.2.2" still works.
 */
import { z } from 'zod'

/** IPv4 literal (dotted quad, 0-255 not enforced here — the bastion decides). */
const IPV4_LITERAL = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/

/** Hard separators. Whitespace-within-a-name is preserved on purpose. */
const HARD_SEPARATORS = /[,;\t\r\n]+/

/**
 * Split one text segment into list items.
 * Exported for the unit tests (B-2) — the behaviour is the contract.
 */
export function splitListText(value: string): string[] {
  const parts = value.split(HARD_SEPARATORS)
  const out: string[] = []
  for (const raw of parts) {
    const trimmed = raw.trim()
    if (trimmed.length === 0) continue
    // A segment that is a whitespace-separated list of IPv4 literals is
    // expanded; anything else keeps its spaces (asset names).
    if (trimmed.includes(' ')) {
      const parts2 = trimmed.split(/\s+/)
      if (parts2.length > 1 && parts2.every((p) => IPV4_LITERAL.test(p))) {
        for (const p of parts2) out.push(p)
        continue
      }
    }
    out.push(trimmed)
  }
  return out
}

/**
 * Normalize a list-of-strings argument.
 *
 * - string  -> split on the separators above
 * - array   -> each element stringified and trimmed, blanks dropped
 * - other   -> returned untouched so zod reports the type error with the
 *              schema's own message (never silently coerced)
 *
 * Duplicates are removed, order preserved: inspecting the same host twice
 * wastes a session slot and, on `jumpserver_compare`, would collapse a
 * 2-element request into 1 and trip the `min(2)` guard — which is the
 * fail-closed outcome we want, not a silent pass.
 */
export function normalizeStringList(value: unknown): unknown {
  if (typeof value === 'string') {
    const items = splitListText(value)
    return dedupe(items)
  }
  if (Array.isArray(value)) {
    const items: string[] = []
    for (const element of value) {
      if (element === null || element === undefined) continue
      // A nested array is flattened one level — the same shape N-04 reported
      // for `commands`. Flattening beats stringifying it into "a,b".
      if (Array.isArray(element)) {
        for (const inner of element) {
          if (inner === null || inner === undefined) continue
          const innerText = typeof inner === 'string' ? inner : String(inner)
          const innerTrimmed = innerText.trim()
          if (innerTrimmed.length === 0) continue
          items.push(innerTrimmed)
        }
        continue
      }
      const text = typeof element === 'string' ? element : String(element)
      const trimmed = text.trim()
      if (trimmed.length === 0) continue
      items.push(trimmed)
    }
    return dedupe(items)
  }
  return value
}

/**
 * Normalize a list of SHELL COMMANDS.
 *
 * Unlike a target list, a command must not be split on commas or spaces —
 * `df -h | sort` and `a,b` are single commands. So:
 * - string  -> split on NEWLINES only (one command per line)
 * - array   -> each element stringified and trimmed, blanks dropped
 */
export function normalizeCommandList(value: unknown): unknown {
  if (typeof value === 'string') {
    const items = value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
    return items
  }
  if (Array.isArray(value)) {
    const items: string[] = []
    for (const element of value) {
      if (element === null || element === undefined) continue
      if (Array.isArray(element)) {
        for (const inner of element) {
          if (inner === null || inner === undefined) continue
          const innerText = typeof inner === 'string' ? inner : String(inner)
          const innerTrimmed = innerText.trim()
          if (innerTrimmed.length === 0) continue
          items.push(innerTrimmed)
        }
        continue
      }
      const text = typeof element === 'string' ? element : String(element)
      const trimmed = text.trim()
      if (trimmed.length === 0) continue
      items.push(trimmed)
    }
    return items
  }
  return value
}

/**
 * Normalize the `tasks` argument of `jumpserver_batch`.
 *
 * Accepted shapes:
 * - array of task objects                      (the documented one)
 * - one task object                           -> wrapped into a 1-element array
 * - a JSON string                              -> parsed, then handled as above
 * - an array whose ELEMENTS are arrays         -> flattened one level
 *   (the "参数被当作嵌套数组" shape reported in N-04)
 *
 * Each task's `commands` is normalized with `normalizeCommandList`.
 * Anything that cannot be understood is returned untouched so zod reports a
 * precise type error instead of us guessing.
 */
export function normalizeTaskList(value: unknown): unknown {
  let source: unknown = value
  if (typeof source === 'string') {
    const trimmed = source.trim()
    if (trimmed.length === 0) return source
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
      try {
        source = JSON.parse(trimmed) as unknown
      } catch {
        return source
      }
    } else {
      return source
    }
  }
  if (source !== null && typeof source === 'object' && !Array.isArray(source)) {
    // A single task object.
    source = [source]
  }
  if (!Array.isArray(source)) return source

  const flat: unknown[] = []
  for (const element of source) {
    if (Array.isArray(element)) {
      for (const inner of element) flat.push(inner)
    } else {
      flat.push(element)
    }
  }
  const tasks: unknown[] = []
  for (const element of flat) {
    if (element !== null && typeof element === 'object' && !Array.isArray(element)) {
      const task = element as Record<string, unknown>
      const commands = task['commands']
      const normalized: Record<string, unknown> = { ...task }
      if (commands !== undefined) normalized['commands'] = normalizeCommandList(commands)
      const target = task['target']
      if (typeof target === 'string') normalized['target'] = target.trim()
      tasks.push(normalized)
      continue
    }
    tasks.push(element)
  }
  return tasks
}

function dedupe(items: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const item of items) {
    if (seen.has(item)) continue
    seen.add(item)
    out.push(item)
  }
  return out
}

/**
 * The hint shown when a list argument fails validation.
 *
 * B-5: the SDK turns a zod failure into
 *   "Input validation error: Invalid arguments for tool X: <message>"
 * so the message is the only place a caller can be told HOW to call it.
 */
export function listArgHint(field: string, example: string): string {
  return field + ' must be an array of strings (e.g. ["' + example + '"]); a single comma-separated string is also accepted (e.g. "' + example + '")'
}

/**
 * The hint shown when a list argument has the wrong TYPE (a number, an
 * object, …). A plain string never reaches this — it is normalized first.
 */
export function listArgTypeHint(field: string, example: string): string {
  return field + ' must be an array of strings (e.g. ["' + example + '"]); a single comma-separated string is also accepted (e.g. "' + example + '")'
}

/**
 * Build a list-of-strings schema that tolerates the string form.
 *
 * The published JSON Schema is an `anyOf` of [array, string] — the host's
 * AJV gate runs BEFORE the connector sees the call, so the published schema
 * is the only thing that can admit the string form. The normalization itself
 * lives in a `z.preprocess` INSIDE the array branch, so:
 *
 *   - the host lets the call through (the string branch admits it);
 *   - the connector rewrites the string into an array FIRST;
 *   - the `.min()` / `.max()` bounds are then enforced against the
 *     NORMALIZED list — "a,,b" still has to survive the bounds, and a
 *     string that expands to zero items is still rejected.
 *
 * The string branch of the union is unreachable during the connector's own
 * parse (the preprocess always produces an array for a string input); it
 * exists purely so the published schema admits the string form.
 *
 * B-5: the SDK validates BEFORE the handler and reports
 *   "Input validation error: Invalid arguments for tool X: <zod message>"
 * so these messages are the only place a caller can learn HOW to call the
 * tool. The union-level error map carries the hint for every rejection.
 */
export function stringListSchema(options: {
  min?: number
  max?: number
  field: string
  example: string
}): z.ZodType<string[]> {
  const hint = listArgHint(options.field, options.example)
  const typeHint = listArgTypeHint(options.field, options.example)
  let base = z.array(z.string(), { invalid_type_error: typeHint })
  if (options.min !== undefined) {
    base = base.min(options.min, { message: hint })
  }
  if (options.max !== undefined) {
    base = base.max(options.max, { message: hint })
  }
  return tolerantUnion(base, normalizeStringList, hint) as unknown as z.ZodType<string[]>
}

/** The optional flavour of `stringListSchema`. */
export function optionalStringListSchema(options: {
  max?: number
  field: string
  example: string
}): z.ZodType<string[] | undefined> {
  const hint = listArgHint(options.field, options.example)
  const typeHint = listArgTypeHint(options.field, options.example)
  let base = z.array(z.string(), { invalid_type_error: typeHint })
  if (options.max !== undefined) {
    base = base.max(options.max, { message: hint })
  }
  return tolerantUnion(base, normalizeStringList, hint, { optional: true }) as unknown as z.ZodType<string[] | undefined>
}

/**
 * Same as `stringListSchema` but for shell commands (newline-separated).
 */
export function commandListSchema(options: { field: string }): z.ZodType<string[]> {
  const hint = options.field + ' must be an array of strings; a single string is accepted and is split on newlines (one command per line)'
  const base = z.array(z.string(), { invalid_type_error: hint })
  return tolerantUnion(base, normalizeCommandList, hint) as unknown as z.ZodType<string[]>
}

/**
 * A list of enum values that also tolerates the string form
 * ("network,process" -> ["network","process"]).
 */
export function enumListSchema<T extends readonly [string, ...string[]]>(options: {
  values: T
  field: string
}): z.ZodType<T[number][] | undefined> {
  const hint = options.field + ' must be an array of ' + options.values.join('/') + ' values; a single comma-separated string is also accepted'
  const base = z.array(z.enum(options.values), { invalid_type_error: hint })
  return tolerantUnion(base, normalizeStringList, hint, { optional: true }) as unknown as z.ZodType<T[number][] | undefined>
}

/**
 * The `tasks` argument of `jumpserver_batch`.
 *
 * The host's AJV gate sees the published schema, so the array-only form
 * would reject a client that sends the whole task list as a JSON string —
 * which is exactly the N-04 failure. The published schema is therefore
 * `anyOf: [array, string]`, and the preprocess turns the string (or a
 * single object, or a nested array) into the array form before the
 * connector's own bounds are checked.
 */
export function taskListSchema<T extends z.ZodTypeAny>(options: {
  element: T
  field: string
  example: string
}): z.ZodType<z.infer<T>[]> {
  const hint = options.field + ' must be an array of task objects, e.g. [{"target":"1.1.1.1","commands":["uptime"]}]; a single JSON string is also accepted'
  const base = z.array(options.element).min(1, { message: hint })
  // The preprocess sits OUTSIDE the union for the same reason as
  // `tolerantUnion`: a string must be normalized BEFORE the bounds are
  // checked, otherwise the string branch would skip `min(1)` entirely.
  //
  // The string branch additionally requires the text to LOOK like JSON. The
  // published schema stays `anyOf: [{type:'array'}, {type:'string'}]` (the
  // host's AJV gate only cares about the type), but the connector rejects
  // "not json" instead of handing a garbage string to the handler.
  return z.preprocess(
    normalizeTaskList,
    z.union(
      [
        base,
        z.string().refine(
          (value) => {
            const text = value.trim()
            return text.startsWith('[') || text.startsWith('{')
          },
          { message: hint }
        ),
      ],
      { errorMap: () => ({ message: hint }) }
    )
  ) as unknown as z.ZodType<z.infer<T>[]>
}

/**
 * The shared shape of every tolerant list schema.
 *
 * `base` is the array schema (with its bounds). It is wrapped in a
 * `z.preprocess` so a string is normalized into an array BEFORE the bounds
 * are checked, and the whole thing is unioned with `z.string()` so the
 * published JSON Schema admits the string form at the host's AJV gate.
 *
 * The union-level error map replaces zod's default "Invalid input" with the
 * caller's hint, so a wrong-typed argument still explains how to call it.
 */
function tolerantUnion(
  base: z.ZodType<string[]>,
  normalize: (value: unknown) => unknown,
  hint: string,
  options: { optional?: boolean } = {}
): z.ZodType<string[]> {
  // The preprocess sits OUTSIDE the union on purpose.
  //
  // If it sat inside the array branch, a string would match the union's
  // `z.string()` branch and never reach the array branch — so `min` / `max`
  // would be silently skipped for the string form. That is a fail-closed
  // violation: `jumpserver_compare` requires at least 2 targets, and
  // "1.1.1.1" (one target) must be rejected, not accepted.
  //
  // With the preprocess outside, a string is normalized into an array FIRST
  // and then always validated by the array branch, bounds included. The
  // published schema is unchanged: `anyOf: [{type:'array',…}, {type:'string'}]`.
  const union = z.preprocess(
    normalize,
    z.union([base, z.string()], { errorMap: () => ({ message: hint }) })
  ) as unknown as z.ZodType<string[]>
  // The optional wrapper goes OUTSIDE the union: `z.optional()` inside the
  // union publishes `anyOf: [{not:{}}, …]` (about 30 wasted bytes per
  // optional field) while `isSchemaOptional` and the `required` list stay
  // correct either way. Verified against the SDK's own helpers.
  return options.optional === true ? (union.optional() as unknown as z.ZodType<string[]>) : union
}
