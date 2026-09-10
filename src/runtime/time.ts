/**
 * Audit/display timezone (V0.4.0).
 *
 * Storage stays UTC — audit records must remain comparable across hosts and
 * must never be rewritten. Only the DISPLAY layer converts, using the
 * configured IANA zone (`timeZone` in config.json, default Asia/Shanghai).
 */
export const DEFAULT_TIME_ZONE = 'Asia/Shanghai'

/** Sentinel: use the MCP host's own zone instead of a fixed one. */
export const LOCAL_TIME_ZONE = 'local'

const formatters = new Map<string, Intl.DateTimeFormat>()

function formatterFor(timeZone: string): Intl.DateTimeFormat {
  const cached = formatters.get(timeZone)
  if (cached !== undefined) return cached
  const zone = timeZone === LOCAL_TIME_ZONE ? Intl.DateTimeFormat().resolvedOptions().timeZone : timeZone
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: zone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
  formatters.set(timeZone, fmt)
  return fmt
}

/** Resolve the effective IANA zone for a config value ('local' => host zone). */
export function resolveTimeZone(configured?: string): string {
  if (configured === undefined || configured.length === 0) return DEFAULT_TIME_ZONE
  if (configured === LOCAL_TIME_ZONE) return Intl.DateTimeFormat().resolvedOptions().timeZone
  return configured
}

/** True when the zone is usable; an unknown IANA name must fall back, not throw. */
export function isValidTimeZone(timeZone: string): boolean {
  if (timeZone === LOCAL_TIME_ZONE) return true
  try {
    new Intl.DateTimeFormat('en-CA', { timeZone })
    return true
  } catch {
    return false
  }
}

/**
 * Render an ISO timestamp as 'YYYY-MM-DD HH:MM:SS' in the given zone.
 * Never throws: unparseable input falls back to the raw (UTC) string slice so
 * a display bug can never hide an audit record.
 */
export function formatAuditTime(value: unknown, timeZone: string): string {
  const raw = String(value ?? '')
  if (raw.length === 0) return '-'
  const ms = Date.parse(raw)
  if (!Number.isFinite(ms)) return raw.replace('T', ' ').slice(0, 19)
  try {
    return formatterFor(timeZone).format(new Date(ms)).replace(',', '')
  } catch {
    // Unknown zone: fall back to UTC rather than showing nothing.
    return new Date(ms).toISOString().replace('T', ' ').slice(0, 19)
  }
}
