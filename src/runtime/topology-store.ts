/**
 * Last-known topology / inspect result, shared with the embedded console so
 * the 拓扑 tab can render what the model just collected (the console itself
 * never talks to the bastion).
 */
export interface StoredTopology {
  updatedAt: number
  group: string | null
  profiles: string[]
  targets: string[]
  nodes: unknown[]
  edges: unknown[]
  warnings: string[]
  durationMs: number
}

export class TopologyStore {
  private current: StoredTopology | null = null

  set(value: StoredTopology): void {
    this.current = value
  }

  get(): StoredTopology | null {
    return this.current
  }
}
