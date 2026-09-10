/**
 * Host inventory parsing (V0.4.0): turn the raw text of the fixed probes into
 * one structured HostInventory per target.
 *
 * Every parser is defensive: a format it does not understand yields an empty
 * result (plus a warning when the probe actually ran), never a wrong value.
 * Facts the parser could not establish stay null — "unknown" must never be
 * presented as if it had been measured.
 */

export interface ListenEntry {
  proto: string
  address: string
  port: number
  process: string | null
}

export interface ConnectionEntry {
  remoteIp: string
  remotePort: number | null
  state: string
  process: string | null
}

export interface ProcessEntry {
  pid: number
  ppid: number | null
  user: string | null
  cpu: number | null
  mem: number | null
  etime: string | null
  cmd: string
}

export interface InterfaceEntry {
  name: string
  addrs: string[]
}

export interface DiskEntry {
  fs: string
  size: string
  used: string
  avail: string
  usePct: number | null
  mount: string
}

export interface NginxUpstream {
  name: string
  servers: Array<{ host: string; port: number | null }>
}

export interface JavaProcess {
  pid: number | null
  main: string | null
  args: string | null
}

export interface ContainerEntry {
  id: string
  image: string
  name: string
  status: string
  ports: string
}

export interface HostInventory {
  target: string
  hostname: string | null
  reachable: boolean
  error: string | null
  profiles: string[]
  os: { id: string | null; name: string | null; version: string | null }
  kernel: string | null
  uptime: string | null
  load: number[] | null
  cores: number | null
  memory: { totalMb: number | null; usedMb: number | null; availableMb: number | null; usedPct: number | null }
  disks: DiskEntry[]
  interfaces: InterfaceEntry[]
  defaultRoute: string | null
  listening: ListenEntry[]
  connections: ConnectionEntry[]
  hosts: Array<{ ip: string; names: string[] }>
  processes: ProcessEntry[]
  services: string[]
  java: JavaProcess[]
  containers: ContainerEntry[]
  nginx: { upstreams: NginxUpstream[]; proxies: string[]; serverNames: string[] } | null
  roles: string[]
  warnings: string[]
}

export function emptyInventory(target: string, profiles: string[], error: string | null = null): HostInventory {
  return {
    target,
    hostname: null,
    reachable: error === null,
    error,
    profiles,
    os: { id: null, name: null, version: null },
    kernel: null,
    uptime: null,
    load: null,
    cores: null,
    memory: { totalMb: null, usedMb: null, availableMb: null, usedPct: null },
    disks: [],
    interfaces: [],
    defaultRoute: null,
    listening: [],
    connections: [],
    hosts: [],
    processes: [],
    services: [],
    java: [],
    containers: [],
    nginx: null,
    roles: [],
    warnings: [],
  }
}

const IPV4 = /(\d{1,3}(?:\.\d{1,3}){3})/

export function parseHostname(text: string): string | null {
  const line = text.trim().split('\n')[0]?.trim()
  return line !== undefined && line.length > 0 && !line.includes(' ') ? line : null
}

export function parseOsRelease(text: string): { id: string | null; name: string | null; version: string | null } {
  const out = { id: null as string | null, name: null as string | null, version: null as string | null }
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq).trim()
    let value = line.slice(eq + 1).trim()
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1)
    if (key === 'ID') out.id = value
    else if (key === 'NAME') out.name = value
    else if (key === 'VERSION' || key === 'VERSION_ID') out.version = out.version ?? value
  }
  return out
}

export function parseUptime(text: string): { uptime: string | null; load: number[] | null } {
  const line = text.trim()
  const at = line.indexOf('up ')
  let uptime: string | null = null
  if (at >= 0) {
    const rest = line.slice(at + 3)
    const comma = rest.indexOf(',')
    uptime = (comma > 0 ? rest.slice(0, comma) : rest).trim() || null
  }
  const loadIdx = line.toLowerCase().indexOf('load average')
  let load: number[] | null = null
  if (loadIdx >= 0) {
    const nums = line.slice(loadIdx).match(/[\d.]+/g)
    if (nums !== null && nums.length >= 3) load = nums.slice(0, 3).map((n) => Number(n))
  }
  return { uptime, load }
}

export function parseLoadavg(text: string): number[] | null {
  const parts = text.trim().split(/\s+/)
  if (parts.length < 3) return null
  const nums = parts.slice(0, 3).map((p) => Number(p))
  return nums.every((n) => Number.isFinite(n)) ? nums : null
}

export function parseMemory(text: string): HostInventory['memory'] {
  const out: HostInventory['memory'] = { totalMb: null, usedMb: null, availableMb: null, usedPct: null }
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.toLowerCase().startsWith('mem:')) {
      const nums = line.match(/\d+/g)
      // `free -m` Mem line: total used free shared buff/cache available (6 numbers).
      // Older `free` and some BusyBox builds only emit total/used/free (3 numbers);
      // in that case available falls back to "free".
      if (nums === null || nums.length < 3) return out
      const total = Number(nums[0])
      const used = Number(nums[1])
      out.totalMb = total
      out.usedMb = used
      out.availableMb = nums.length >= 6 ? Number(nums[nums.length - 1]) : Number(nums[2])
      out.usedPct = total > 0 ? Math.round((used / total) * 100) : null
      return out
    }
  }
  return out
}

export function parseDisks(text: string): DiskEntry[] {
  const out: DiskEntry[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line.startsWith('/')) continue
    const parts = line.split(/\s+/)
    if (parts.length < 6) continue
    const usePctRaw = parts[4] ?? ''
    const pct = Number(String(usePctRaw).replace('%', ''))
    out.push({
      fs: parts[0] ?? '?',
      size: parts[1] ?? '?',
      used: parts[2] ?? '?',
      avail: parts[3] ?? '?',
      usePct: Number.isFinite(pct) ? pct : null,
      mount: parts[5] ?? '?',
    })
  }
  return out.slice(0, 12)
}

/** `ip -o addr` -> one entry per interface with its non-loopback, non-link-local
 *  addresses. The interface row is kept even if every addr on it was filtered
 *  (e.g. a pure loopback), so callers can still see "lo" with addrs=[] instead
 *  of silently dropping the interface. */
export function parseIpAddr(text: string): InterfaceEntry[] {
  const map = new Map<string, string[]>()
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.length === 0) continue
    const match = /^\d+:\s+([^\s:]+)/.exec(line)
    if (match === null) continue
    const name = match[1] ?? '?'
    const addrMatch = /\binet6?\s+([^\s/]+)/.exec(line)
    if (addrMatch === null) continue
    const addr = addrMatch[1]
    if (addr === undefined) continue
    const list = map.get(name) ?? []
    if (
      !list.includes(addr) &&
      !addr.startsWith('127.') &&
      !addr.startsWith('::1') &&
      !addr.toLowerCase().startsWith('fe80')
    ) {
      list.push(addr)
    }
    map.set(name, list)
  }
  return [...map.entries()].map(([name, addrs]) => ({ name, addrs }))
}

export function parseDefaultRoute(text: string): string | null {
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line.startsWith('default')) continue
    const match = /via\s+([^\s]+)/.exec(line)
    if (match !== null && match[1] !== undefined) return match[1]
  }
  return null
}

/** `ss -lntp` -> listening sockets (process name kept when ss shows it). */
export function parseListen(text: string): ListenEntry[] {
  const out: ListenEntry[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.length === 0 || line.toLowerCase().startsWith('state') || line.toLowerCase().startsWith('netid')) continue
    const parts = line.split(/\s+/)
    if (parts.length < 4) continue
    const proto = (parts[0] ?? '?').toLowerCase()
    const local = parts[3] ?? parts[2] ?? ''
    const colon = local.lastIndexOf(':')
    if (colon < 0) continue
    const address = local.slice(0, colon).replace(/^\[/, '').replace(/\]$/, '')
    const port = Number(local.slice(colon + 1))
    if (!Number.isFinite(port)) continue
    const procMatch = /users:\(\("([^"]+)"/.exec(line) ?? /"([^"]+)"/.exec(line)
    out.push({ proto, address, port, process: procMatch !== null ? (procMatch[1] ?? null) : null })
  }
  // de-duplicate (ss prints one row per listen backlog/process)
  const seen = new Set<string>()
  return out.filter((e) => {
    const key = e.proto + ':' + e.address + ':' + e.port + ':' + (e.process ?? '')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/** `ss -tnp` -> established/outgoing connections (remote ip/port + process). */
export function parseConnections(text: string): ConnectionEntry[] {
  const out: ConnectionEntry[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.length === 0 || line.toLowerCase().startsWith('state') || line.toLowerCase().startsWith('netid')) continue
    const parts = line.split(/\s+/)
    if (parts.length < 4) continue
    const state = (parts[0] ?? '?').toUpperCase()
    if (state !== 'ESTAB' && state !== 'ESTABLISHED') continue
    const peer = parts[4] ?? parts[3] ?? ''
    const match = IPV4.exec(peer)
    if (match === null) continue
    const colon = peer.lastIndexOf(':')
    const port = colon >= 0 ? Number(peer.slice(colon + 1).replace(/[^\d]/g, '')) : null
    const procMatch = /users:\(\("([^"]+)"/.exec(line)
    out.push({
      remoteIp: match[1] ?? '?',
      remotePort: Number.isFinite(port ?? NaN) ? (port as number) : null,
      state: 'ESTABLISHED',
      process: procMatch !== null ? (procMatch[1] ?? null) : null,
    })
  }
  const seen = new Set<string>()
  return out.filter((e) => {
    const key = e.remoteIp + ':' + (e.remotePort ?? '') + ':' + (e.process ?? '')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function parseHosts(text: string): Array<{ ip: string; names: string[] }> {
  const out: Array<{ ip: string; names: string[] }> = []
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim()
    if (line.length === 0) continue
    const parts = line.split(/\s+/)
    const ip = parts[0] ?? ''
    if (!IPV4.test(ip) || ip.startsWith('127.')) continue
    out.push({ ip, names: parts.slice(1) })
  }
  return out
}

/** `ps -eo pid,ppid,user,%cpu,%mem,etime,args` */
export function parsePs(text: string): ProcessEntry[] {
  const out: ProcessEntry[] = []
  const lines = text.split('\n')
  for (let i = 1; i < lines.length; i++) {
    const line = (lines[i] ?? '').trim()
    if (line.length === 0) continue
    const parts = line.split(/\s+/)
    if (parts.length < 7) continue
    const pid = Number(parts[0])
    if (!Number.isFinite(pid)) continue
    out.push({
      pid,
      ppid: Number.isFinite(Number(parts[1])) ? Number(parts[1]) : null,
      user: parts[2] ?? null,
      cpu: Number.isFinite(Number(parts[3])) ? Number(parts[3]) : null,
      mem: Number.isFinite(Number(parts[4])) ? Number(parts[4]) : null,
      etime: parts[5] ?? null,
      cmd: parts.slice(6).join(' '),
    })
  }
  return out
}

export function parseServices(text: string): string[] {
  const out: string[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.length === 0) continue
    if (line.startsWith('UNIT') || line.startsWith('LOAD') || line.includes('LOAD   ACTIVE')) continue
    const match = /^([a-zA-Z0-9_.\-@%]+\.service)/.exec(line)
    if (match !== null && match[1] !== undefined) out.push(match[1])
    else if (/^\S+\s+loaded\s+active\s+running/.test(line)) out.push(line.split(/\s+/)[0] ?? '?')
  }
  return [...new Set(out)].slice(0, 200)
}

/** `jps -lv`: "<pid> <main class> <args>" */
export function parseJps(text: string): JavaProcess[] {
  const out: JavaProcess[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line.length === 0) continue
    const match = /^(\d+)\s+(\S+)(.*)$/.exec(line)
    if (match === null) continue
    out.push({
      pid: Number(match[1]),
      main: match[2] ?? null,
      args: (match[3] ?? '').trim().length > 0 ? match[3]!.trim().slice(0, 400) : null,
    })
  }
  return out
}

/** `docker ps` (default table layout).
 *  The header position varies by KoKo/docker version; the safest split is by
 *  2+ spaces, which matches the column boundaries `docker ps` prints. */
export function parseDockerPs(text: string): ContainerEntry[] {
  const lines = text.split('\n').filter((l) => l.trim().length > 0)
  if (lines.length < 2) return []
  const header = lines[0] ?? ''
  const columns = header.trim().split(/\s{2,}/).map((c) => c.trim())
  const idx = (name: string): number => columns.findIndex((c) => c.toUpperCase() === name.toUpperCase())
  const idAt = idx('CONTAINER ID')
  const imageAt = idx('IMAGE')
  const nameAt = idx('NAMES')
  const statusAt = idx('STATUS')
  const portsAt = idx('PORTS')
  const out: ContainerEntry[] = []
  for (const line of lines.slice(1)) {
    const cells = line.trim().split(/\s{2,}/)
    if (cells.length < 3) continue
    const get = (i: number): string => (i >= 0 && i < cells.length ? (cells[i] ?? '').trim() : '')
    out.push({
      id: get(idAt).slice(0, 12),
      image: get(imageAt),
      name: get(nameAt),
      status: get(statusAt),
      ports: get(portsAt),
    })
  }
  return out.slice(0, 60)
}

/** nginx config (`nginx -T`): upstream blocks, proxy_pass targets, server_name. */
export function parseNginxConfig(text: string): { upstreams: NginxUpstream[]; proxies: string[]; serverNames: string[] } {
  const upstreams: NginxUpstream[] = []
  const upstreamPattern = /upstream\s+([A-Za-z0-9_.\-]+)\s*\{([^}]*)\}/g
  let m: RegExpExecArray | null
  while ((m = upstreamPattern.exec(text)) !== null) {
    const name = m[1] ?? '?'
    const body = m[2] ?? ''
    const servers: Array<{ host: string; port: number | null }> = []
    const serverPattern = /server\s+([^\s;]+)(?::(\d+))?/g
    let s: RegExpExecArray | null
    while ((s = serverPattern.exec(body)) !== null) {
      const host = s[1]
      if (host === undefined || host.startsWith('unix:')) continue
      servers.push({ host, port: s[2] !== undefined ? Number(s[2]) : null })
    }
    upstreams.push({ name, servers })
  }
  const proxies: string[] = []
  const proxyPattern = /proxy_pass\s+([^;]+);/g
  while ((m = proxyPattern.exec(text)) !== null) {
    const value = (m[1] ?? '').trim()
    if (value.length > 0) proxies.push(value)
  }
  const serverNames: string[] = []
  const namePattern = /server_name\s+([^;]+);/g
  while ((m = namePattern.exec(text)) !== null) {
    const value = (m[1] ?? '').trim()
    if (value.length > 0 && value !== '_') serverNames.push(value)
  }
  return {
    upstreams,
    proxies: [...new Set(proxies)].slice(0, 50),
    serverNames: [...new Set(serverNames)].slice(0, 50),
  }
}

/** Role detection: only from evidence that is actually present. */
export function detectRoles(inv: HostInventory): string[] {
  const roles = new Set<string>()
  const cmds = inv.processes.map((p) => p.cmd.toLowerCase()).join('\n')
  const has = (needle: string): boolean => cmds.includes(needle)
  const listens = (port: number): boolean => inv.listening.some((l) => l.port === port)

  if (has('nginx') || inv.nginx !== null) roles.add('nginx')
  if (inv.nginx !== null && inv.nginx.upstreams.length > 0) roles.add('reverse-proxy')
  if (has('httpd') || has('apache2')) roles.add('httpd')
  if (has('tomcat') || has('catalina')) roles.add('tomcat')
  if (has('resin') || has('weaver')) roles.add('resin')
  if (inv.java.length > 0 || has('java ')) roles.add('java')
  if (has('mysqld') || listens(3306)) roles.add('mysql')
  if (has('redis-server') || listens(6379)) roles.add('redis')
  if (has('postgres') || listens(5432)) roles.add('postgresql')
  if (has('mongod') || listens(27017)) roles.add('mongodb')
  if (has('dockerd') || inv.containers.length > 0) roles.add('container-host')
  if (has('kubelet')) roles.add('kubernetes-node')
  if (has('elasticsearch')) roles.add('elasticsearch')
  if (has('rabbitmq')) roles.add('rabbitmq')
  if (listens(22)) roles.add('ssh')
  if (roles.size === 0) roles.add('generic-host')
  return [...roles]
}

/** Apply one probe's output onto the inventory (keyed by probe id). */
export function applyProbe(inv: HostInventory, id: string, output: string, exitCode: number | null): void {
  const text = output ?? ''
  const ok = exitCode === null || exitCode === 0
  switch (id) {
    case 'hostname':
      inv.hostname = parseHostname(text)
      return
    case 'os-release':
      if (ok) inv.os = parseOsRelease(text)
      return
    case 'kernel':
      inv.kernel = text.trim().split('\n')[0]?.trim() ?? null
      return
    case 'uptime': {
      const parsed = parseUptime(text)
      inv.uptime = parsed.uptime
      inv.load = parsed.load
      return
    }
    case 'loadavg': {
      const parsed = parseLoadavg(text)
      if (parsed !== null) inv.load = parsed
      return
    }
    case 'nproc': {
      const n = Number(text.trim().split('\n')[0]?.trim())
      if (Number.isFinite(n)) inv.cores = n
      return
    }
    case 'memory':
      inv.memory = parseMemory(text)
      return
    case 'disk':
      inv.disks = parseDisks(text)
      return
    case 'addr':
      inv.interfaces = parseIpAddr(text)
      return
    case 'route':
      inv.defaultRoute = parseDefaultRoute(text)
      return
    case 'listen':
      inv.listening = parseListen(text)
      return
    case 'conns':
      inv.connections = parseConnections(text)
      return
    case 'hosts':
      inv.hosts = parseHosts(text)
      return
    case 'ps':
      inv.processes = parsePs(text)
      return
    case 'services':
      inv.services = parseServices(text)
      return
    case 'jps':
      inv.java = parseJps(text)
      return
    case 'docker-ps':
      inv.containers = parseDockerPs(text)
      return
    case 'nginx-conf': {
      if (!ok || text.trim().length === 0) return
      const parsed = parseNginxConfig(text)
      if (parsed.upstreams.length === 0 && parsed.proxies.length === 0 && parsed.serverNames.length === 0) return
      inv.nginx = parsed
      return
    }
    default:
      return
  }
}
