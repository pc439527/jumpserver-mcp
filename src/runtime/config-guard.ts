/**
 * V0.5.2 — the config-completeness gate.
 *
 * Before this, a missing connection value was a BOOT failure: `createRuntime`
 * threw `ConfigIncompleteError`, `main()` caught it and called
 * `process.exit(1)`. The MCP handshake therefore never completed, and the host
 * could only say "the server failed to start" — pointing the user at the logs
 * instead of at the empty form they needed to fill in.
 *
 * Now the runtime always boots, and the refusal is deferred to the tool that
 * actually needs the bastion. Consequences that are worth stating explicitly:
 *
 *  - `initialize` and `tools/list` succeed with no configuration at all, so a
 *    reviewer's smoke run and a fresh install both see a working server.
 *  - The message a user sees inside a tool call is byte-identical to the one
 *    printed at startup, because both come from `configIncompleteMessage()`.
 *  - Only the tools that need a connection refuse. `jumpserver_status` and
 *    `jumpserver_console_rotate_token` must stay answerable — they are how a
 *    user diagnoses exactly this problem.
 */
import { configIncompleteMessage } from '../config/schema.js'
import type { ResultValue } from './tools-common.js'
import type { Runtime } from './runtime.js'

/** Error code for "the connector is running but not configured yet". */
export const CONFIG_INCOMPLETE = 'CONFIG_INCOMPLETE'

/** The structured refusal a connect-needing tool returns while unconfigured. */
export function configIncompleteValue(problems: readonly string[]): ResultValue {
  return {
    ok: false,
    code: CONFIG_INCOMPLETE,
    message: configIncompleteMessage(problems),
    missing: [...problems],
  } as unknown as ResultValue
}

/**
 * Returns the refusal when the connection is still incomplete, else null.
 * Call this INSTEAD of assuming `getConfig().host` is a real host.
 */
export function requireConfigured(runtime: Runtime): ResultValue | null {
  const problems = runtime.configProblems()
  return problems.length === 0 ? null : configIncompleteValue(problems)
}
