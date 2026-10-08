/** Session state machine (V0.1). Illegal transitions collapse to UNKNOWN - never guess. */
export enum SessionState {
  DISCONNECTED = 'DISCONNECTED',
  CONNECTING = 'CONNECTING',
  JUMPSERVER_MENU = 'JUMPSERVER_MENU',
  ENTERING_ASSET = 'ENTERING_ASSET',
  ASSET_SHELL = 'ASSET_SHELL',
  COMMAND_RUNNING = 'COMMAND_RUNNING',
  UNKNOWN = 'UNKNOWN',
  ERROR = 'ERROR',
}

/** Legal transitions. Use nextState() so an illegal move becomes UNKNOWN. */
export const LEGAL_TRANSITIONS: Record<SessionState, ReadonlySet<SessionState>> = {
  [SessionState.DISCONNECTED]: new Set([SessionState.CONNECTING]),
  [SessionState.CONNECTING]: new Set([SessionState.JUMPSERVER_MENU, SessionState.ERROR]),
  [SessionState.JUMPSERVER_MENU]: new Set([SessionState.ENTERING_ASSET, SessionState.DISCONNECTED]),
  // V0.5.5: ENTERING_ASSET is not a one-way door. KoKo bounces back to its own
  // menu prompt when it cannot dial the asset (`... error: 网络不通（连接超时）`
  // followed by `[Host]> `), and the transport can also die mid-dial. Both are
  // real screens/states, not illegal moves: without them a single unreachable
  // asset collapsed the session to UNKNOWN and forced a full reconnect before
  // the model could look at any other asset.
  [SessionState.ENTERING_ASSET]: new Set([
    SessionState.ASSET_SHELL,
    SessionState.JUMPSERVER_MENU,
    SessionState.DISCONNECTED,
    SessionState.UNKNOWN,
    SessionState.ERROR,
  ]),
  [SessionState.ASSET_SHELL]: new Set([
    SessionState.COMMAND_RUNNING,
    SessionState.JUMPSERVER_MENU,
    SessionState.UNKNOWN,
    SessionState.DISCONNECTED,
  ]),
  [SessionState.COMMAND_RUNNING]: new Set([SessionState.ASSET_SHELL, SessionState.UNKNOWN, SessionState.DISCONNECTED]),
  [SessionState.UNKNOWN]: new Set([SessionState.DISCONNECTED, SessionState.CONNECTING]),
  [SessionState.ERROR]: new Set([SessionState.DISCONNECTED]),
}

export function canTransition(from: SessionState, to: SessionState): boolean {
  return LEGAL_TRANSITIONS[from]?.has(to) ?? false
}

/**
 * Resolve the target state for a requested move: the requested state when
 * legal; otherwise UNKNOWN (never the requested state).
 */
export function nextState(from: SessionState, to: SessionState): SessionState {
  if (canTransition(from, to)) return to
  return SessionState.UNKNOWN
}
