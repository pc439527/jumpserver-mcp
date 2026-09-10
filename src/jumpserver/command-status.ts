/**
 * V0.4.5: ONE mapping from `commandStatus` to a structured error.
 *
 * `commandStatus` is produced by the session layer (session.ts ExecOutcome) and
 * travels through exec / batch / runbook / compare / inspect. Before V0.4.5
 * every consumer invented its own error:
 *
 *   exec    -> COMMAND_EXIT_NONZERO / COMMAND_TIMEOUT / CONNECTION_LOST
 *   compare -> COMMAND_EXIT_NONZERO for EVERYTHING (TIMEOUT, CONNECTION_LOST,
 *              UNKNOWN all masqueraded as a non-zero exit), so a caller that
 *              switched on the code could not tell a wedged shell from a
 *              missing binary.
 *
 * Having one function means a status can never be decoded two different ways.
 */

/** Every commandStatus value the session layer may emit. */
export type CommandStatus = 'SUCCESS' | 'EXIT_NONZERO' | 'TIMEOUT' | 'INTERRUPTED' | 'CONNECTION_LOST' | 'UNKNOWN'

export interface CommandFailure {
  code: string
  message: string
}

/** True when the status means "the command did not succeed". */
export function isCommandFailure(commandStatus: string): boolean {
  return commandStatus !== 'SUCCESS'
}

/**
 * Decode a commandStatus into a structured error, or null for SUCCESS.
 * Never throws for an unknown status — a future status string degrades to
 * COMMAND_STATUS_UNKNOWN instead of being silently reported as a success.
 */
export function commandStatusToError(
  commandStatus: string,
  detail: { exitCode?: number | null; executionState?: string | null } = {},
): CommandFailure | null {
  const executionState = detail.executionState ?? null
  const tail = executionState !== null ? ' (executionState=' + executionState + ')' : ''
  switch (commandStatus) {
    case 'SUCCESS':
      return null
    case 'EXIT_NONZERO':
      return {
        code: 'COMMAND_EXIT_NONZERO',
        message: 'command exited with code ' + String(detail.exitCode ?? '?'),
      }
    case 'TIMEOUT':
      return {
        code: 'COMMAND_TIMEOUT',
        message: 'command timed out before completing' + tail,
      }
    case 'INTERRUPTED':
      return {
        code: 'COMMAND_INTERRUPTED',
        message: 'command was interrupted (Ctrl+C) before completing' + tail,
      }
    case 'CONNECTION_LOST':
      return {
        code: 'CONNECTION_LOST',
        message: 'SSH connection was lost during command execution',
      }
    default:
      return {
        code: 'COMMAND_STATUS_UNKNOWN',
        message: 'command outcome could not be determined (commandStatus=' + String(commandStatus) + ')' + tail,
      }
  }
}
