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
  /**
   * V0.4.3: transport session id, when the host provides one. With the stdio
   * transport it is undefined and process isolation is the scope; a
   * multiplexing host (HTTP/SSE, or one process serving several
   * conversations) sets it, and it becomes the conversation key.
   */
  readonly sessionId?: string
}
