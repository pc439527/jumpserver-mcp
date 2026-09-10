/**
 * Last-known asset list, shared with the embedded console's 资产 tab.
 *
 * The console never talks to the bastion — it can only render what the model
 * last fetched via jumpserver_assets. This store is that hand-off point: the
 * tool writes, the console reads. Kept deliberately dumb (a snapshot + time).
 */
import type { AssetEntry } from '../jumpserver/asset-list.js'

export interface StoredAssets {
  updatedAt: number
  /** Filter/group the listing was produced with (null = unfiltered). */
  filter: string | null
  group: string | null
  reportedTotal: number | null
  health: string
  assets: AssetEntry[]
}

export class AssetStore {
  private current: StoredAssets | null = null

  set(value: StoredAssets): void {
    this.current = value
  }

  get(): StoredAssets | null {
    return this.current
  }

  clear(): void {
    this.current = null
  }
}
