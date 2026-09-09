/**
 * MCP-local replacement for @deepseek-ai/dsh-tools' ToolRunContext.
 * One instance per tool call, built in server.ts from the MCP request extra.
 */
export interface ToolRunContext {
  /** Tool name being executed (audit + approval routing). */
  readonly name: string
  /** MCP request id (audit correlation). */
  readonly callId: string | number
  /** Aborted when the MCP client cancels the request. */
  readonly signal: AbortSignal
  /**
   * MCP-idiomatic approval: when true the human approval step is skipped
   * because the user already approved through the conversation. Only set
   * this after the user explicitly agreed to the listed command(s).
   */
  readonly confirm: boolean
}
