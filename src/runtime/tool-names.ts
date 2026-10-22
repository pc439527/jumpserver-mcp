/**
 * V0.6.1 (B-4) — the tool surface, made OBSERVABLE.
 *
 * THE FAILURE THIS FIXES
 *
 * "WorkBuddy says the connector is connected, but `mcp__jumpserver` has zero
 * sub-tools." That symptom has three possible causes that look identical from
 * the outside:
 *
 *   1. the host's tool table was built BEFORE the connector was (re)loaded —
 *      the tool table is fixed at session start, so a rebuilt connector is
 *      invisible until a NEW conversation is opened;
 *   2. the connector process is alive but its tool registration failed
 *      part-way (a schema that throws during registration kills the rest);
 *   3. the host dropped the connector entirely.
 *
 * From inside a conversation, the model could answer NONE of these — the
 * status tool said "connection: complete" and stopped there. So the model
 * either guessed ("restart the host") or reported a vague "the tools are not
 * working".
 *
 * What this module makes possible:
 *   - `jumpserver_status` can report how many tools THIS process actually
 *     registered, how many it was supposed to register, and which are missing;
 *   - `--doctor` can verify that the COMPILED build really publishes the tool
 *     surface, without starting a server or opening a socket.
 *
 * The expected names live here so the runtime, the doctor and the tests all
 * agree on one list. `tests/runtime/tool-annotations.test.mjs` freezes the
 * ANNOTATIONS; this file freezes the NAMES the doctor checks the build for.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'

/** Registered on every start (23 tools). */
export const ALWAYS_TOOL_NAMES: readonly string[] = [
  'jumpserver_status',
  'jumpserver_console_rotate_token',
  'jumpserver_connect',
  'jumpserver_enter',
  'jumpserver_assets',
  'jumpserver_exec',
  'jumpserver_run',
  'jumpserver_batch',
  'jumpserver_leave',
  'jumpserver_close',
  'jumpserver_snapshot',
  'jumpserver_audit',
  'jumpserver_inspect',
  'jumpserver_topology',
  'jumpserver_profile_run',
  'jumpserver_compare',
  'jumpserver_baseline_capture',
  'jumpserver_baseline_compare',
  'jumpserver_interrupt',
  'jumpserver_job_start',
  'jumpserver_job_read',
  'jumpserver_job_stop',
  'jumpserver_jobs',
]

/** Registered only when `requireArm: true` (2 tools). */
export const CONDITIONAL_TOOL_NAMES: readonly string[] = [
  'jumpserver_arm',
  'jumpserver_disarm',
]

const registered = new Set<string>()

/**
 * Record a tool registration. Called by the wrapper installed by
 * `trackToolRegistrations` — never by hand.
 */
export function noteToolRegistered(name: string): void {
  registered.add(name)
}

/**
 * Wrap `server.registerTool` so every registration is RECORDED.
 *
 * The SDK keeps its own registry in a private field, and reading a private
 * field is exactly the kind of coupling that breaks on the next SDK bump.
 * Wrapping the public method is both cheaper and more honest: what is
 * recorded is what was actually registered, not what somebody believes was
 * registered.
 *
 * Call this ONCE, right after the McpServer is constructed — before any
 * `registerTool` call, including the ones made by the ops-tool module.
 */
export function trackToolRegistrations(server: McpServer): void {
  // The SDK's registerTool is generic over the schema types; the wrapper only
  // needs the name, so the assignment is done through a narrow structural
  // type instead of pretending the SDK's signature is something it is not.
  const target = server as unknown as { registerTool: (name: string, config: unknown, cb: unknown) => unknown }
  const original = target.registerTool.bind(target)
  target.registerTool = (name: string, config: unknown, cb: unknown): unknown => {
    noteToolRegistered(name)
    return original(name, config, cb)
  }
}
/** The tool names this process actually registered. */
export function registeredToolNames(): string[] {
  return [...registered].sort()
}

/** How many tools this process registered. */
export function registeredToolCount(): number {
  return registered.size
}

/**
 * The always-on tools that are NOT registered in this process.
 * A non-empty result means registration failed part-way — the connector is
 * broken in a way `connection: complete` cannot show.
 */
export function missingAlwaysToolNames(): string[] {
  return ALWAYS_TOOL_NAMES.filter((name) => !registered.has(name))
}

/** Test seam: forget every registration. */
export function resetToolRegistry(): void {
  registered.clear()
}
