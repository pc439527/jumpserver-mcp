import type { CommandRisk } from '../config/types.js'

/**
 * V0.3.1 command classifier (version 2).
 *
 * Risk model (single fact source for gating, approval copy and audit):
 *   READ             - CONFIRMED read-only (a semantic rule matched)
 *   PRIVILEGED_READ  - CONFIRMED read-only, needs sudo/root (sudo cat ...)
 *   UNKNOWN          - the classifier has NO semantic rule; the command is
 *                      NOT claimed to modify anything ("无法确认只读", not
 *                      "检测到修改")
 *   MODIFY           - CONFIRMED state change (mutating verb / write redirect)
 *   DANGEROUS        - host-destructive / irreversible
 *
 * Pipeline (per command):
 *   1. whole-command DANGEROUS phrases            -> DANGEROUS
 *   2. opaque shell syntax ($(..), \`..\`, bash -c, python -c ...) -> UNKNOWN
 *      (not analyzable => never claimed read-only, never claimed modifying)
 *   3. whole-command CONFIRMED mutation (mutating verbs, in-place sed,
 *      write redirection, verb-scoped service/package rules) -> MODIFY
 *   4. per-segment semantic classification        -> READ / PRIVILEGED_READ /
 *                                                    UNKNOWN (worst wins)
 * Wrapping (env/timeout/nice, any depth) and sudo NEVER downgrade the inner
 * command's risk: the inner command goes through the SAME full pipeline.
 */

export const CLASSIFIER_VERSION = 3

export type Confidence = 'HIGH' | 'LOW'

export interface Classification {
  risk: CommandRisk
  /** Human-readable why (also lands in the audit and approval copy). */
  reason: string
  /** Semantic rule id, e.g. 'systemctl.status' / 'docker.compose.up' / 'unknown.command'. */
  ruleId: string
  confidence: Confidence
  /** The exact command as classified. */
  command: string
  /** Whitespace-collapsed command (audit/normalization). */
  normalizedCommand: string
  classifierVersion: number
}

// ---------------- whole-command DANGEROUS ----------------

const DANGEROUS_COMMANDS: RegExp[] = [
  /\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)*\/(?:\s|\*|$)/, // rm -rf /
  /\bmkfs(?:\.\w+)?\b/,
  /\bwipefs\b/,
  /\bdd\b/,
  /\bshutdown\b|\breboot\b|\bpoweroff\b|\bhalt\b/,
  /\biptables\s+-[FX]\b/,
  /\biptables\s+-P\b/, // set a chain policy — can lock the host out
  /\bDROP\s+DATABASE\b|\bTRUNCATE\s+TABLE\b/i,
  /:\s*\(\s*\)\s*\{[^}]*\|/, // fork bomb :(){ :|:& };:
  /\bkill\s+-9\s+-1\b/,
  /\bchmod\s+-[a-zA-Z]*R[a-zA-Z]*[^&|;]*\s+0*777\s+\//, // chmod -R 777 /
  /\b(?:yes|yum|dnf)\s+\|\s+.*\b(?:rm|mkfs|shutdown|reboot)\b/i, // piped destructive (conservative)
]

const DANGEROUS_REASON = (source: string): string => 'dangerous pattern: ' + source

// ---------------- opaque syntax -> UNKNOWN ----------------

/** Shell constructs the classifier cannot analyze: never claimed read-only,
 *  never claimed modifying either. UNKNOWN keeps READ_ONLY closed and AUTO/
 *  FULL_ACCESS prompting, with honest copy. */
const OPAQUE_SYNTAX_PATTERN =
  /\$\(|\`|\b(?:bash|sh|su|sudo)\s+-c\b|\bpython3?\s+-c\b|\bperl\s+-e\b|\bsystem\s*\(/i

// ---------------- whole-command CONFIRMED mutation ----------------

/** Plain modifier verbs (word-boundary, anywhere in the masked command).
 *  mount/sed/tar are handled by dedicated rules below. */
const MODIFY_VERBS =
  /\b(?:rm|mv|cp|touch|mkdir|rmdir|install|chmod|chown|chgrp|ln|kill|pkill|killall|tee|truncate|umount|useradd|userdel|usermod|groupadd|groupdel|groupmod|crontab|at|systemd-run|unzip|gunzip|chroot|git|svn|make|cmake|npm|yarn|pnpm|pip|pip3|apt|apt-get|yum|dnf|zypper|pacman|setfacl|chattr|chacl|restorecon|semanage|mkuser|htpasswd|vipw|vigr|cgcreate|nulloep|newgrp)\b/i

const SYSTEMCTL_MODIFY = /\bsystemctl\b[^&|;]*\s(?:start|stop|restart|reload|reload-or-restart|try-restart|condrestart|force-reload|enable|disable|reenable|mask|unmask|daemon-reload|daemon-reexec|kill|reset-failed|set-default|set-property|edit|add-wants|add-requires|preset|preset-all|isolate|switch-root|halt|poweroff|reboot|kexec|suspend|hibernate|hybrid-sleep|freeze|exit|rescue|emergency)\b/
const SERVICE_MODIFY = /\bservice\b[^&|;]*\s(?:start|stop|restart|reload|force-reload|condrestart|try-restart)\b/
const PKG_MODIFY = /\b(?:apt|apt-get|yum|dnf|zypper|pacman|apk)\b[^&|;]*\s(?:install|remove|purge|erase|update|upgrade|full-upgrade|dist-upgrade|distro-sync|autoremove|downgrade|reinstall|clean|autoclean|makecache|download|source)\b/
const SED_INPLACE = /\bsed\b[^&|;]*\s-{1,2}i[a-zA-Z]*(?:\.\S+)?\b/
const TAR_EXTRACT = /\btar\b[^&|;]*\s-x[a-zA-Z]*\b/
const TAR_CREATE = /\btar\b[^&|;]*\s-c[a-zA-Z]*\b/
const SU_EXEC = /\b(?:su|sudo)\s+(?:-c|--command)\b/
const HOSTNAMECTL_MODIFY = /\bhostnamectl\b[^&|;]*\s(?:set-|transient\b|pretty\b)/
const TIMEDATECTL_MODIFY = /\btimedatectl\b[^&|;]*\s(?:set-|ntp\b)/
const LOGINCTL_MODIFY = /\bloginctl\b[^&|;]*\s(?:terminate-|kill-|lock-|unlock-|set-|enable-linger|disable-linger)/
const LOCALECTL_MODIFY = /\blocalectl\b[^&|;]*\s(?:set-)\b/
const RESOLVECTL_MODIFY = /\bresolvectl\b[^&|;]*\s(?:flush-caches|reset-statistics|set-|dnssec\s+(?:on|off|allow-downgrade))\b/
const NMCli_MODIFY = /\bnmcli\b[^&|;]*\s(?:device|connection|general|radio|networking)\s+(?:disconnect|up|down|modify|delete|add|edit|set|reapply|reload|connect|on|off|enable|disable)\b/
const ETHTOOL_MODIFY = /\bethtool\b[^&|;]*\s-(?:s|K|G|A|C|N|W|L|S|coalesce|features|pause|ring|channels|offload|eee|fec)\b/
const IPTABLES_MODIFY = /\biptables\s+-[ADIRZ]\b/

/** Write-redirection operator with an optional FD prefix: ">", "2>", ">>", "2>>". */
const REDIRECT_OP = /(?:^|\b)(\d{1,2})?\s*[>»]{1,2}\s*([^;|>\s»]*)/g

/**
 * Read-only FD redirections must NOT be classified as file writes.
 * Allowed (return null): 2>&1, 1>&2, 2>/dev/null, 2>>/dev/null, >/dev/null.
 * Still MODIFY (return the target): "> file", ">> app.log", ">&file", "command >".
 * Quoted regions are masked first, so 'echo "> x"' stays data.
 */
export function hasFileWriteRedirection(command: string): string | null {
  const masked = maskQuoted(command)
  REDIRECT_OP.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = REDIRECT_OP.exec(masked)) !== null) {
    const target = (m[2] ?? '').trim()
    if (target.length === 0) return ''
    if (/^&\d+$/.test(target)) continue
    if (target === '/dev/null') continue
    return target
  }
  return null
}

// ---------------- semantic reader registry ----------------

/**
 * Reader rule for one first token:
 *  - 'any'                              the command is a confirmed reader,
 *                                       any arguments stay READ
 *  - ReadonlySet<string>                the first significant (non-option,
 *                                       non-assignment) argument must be one
 *                                       of the verbs; anything else for a
 *                                       known tool -> UNKNOWN (not MODIFY)
 *  - object with special()              dedicated semantic function:
 *                                       returns a Classification-ish decision
 *                                       or null to fall through to the verb set
 */
type ReaderRule =
  | 'any'
  | ReadonlySet<string>
  | {
      verbs?: ReadonlySet<string>
      special?: (tokens: string[], segment: string) => CommandRisk | null
    }

const SYSTEMCTL_READ: ReadonlySet<string> = new Set([
  'status', 'show', 'cat', 'list-units', 'list-unit-files', 'list-timers', 'list-sockets',
  'list-dependencies', 'list-jobs', 'list-machines', 'list-mounts', 'list-paths',
  'is-active', 'is-enabled', 'is-failed', 'is-system-running', 'is-running', 'is-degraded',
  'is-verified', 'get-default', 'show-environment', 'version', 'help', 'dump', 'list-timers',
  'list-sockets', 'show-environment', 'list-verbs',
])

const DOCKER_READ: ReadonlySet<string> = new Set([
  'ps', 'logs', 'inspect', 'stats', 'images', 'info', 'version', 'top', 'port', 'history',
  'diff', 'events', 'system', 'network', 'volume', 'container', 'image', 'secret',
  'config', 'service', 'stack', 'plugin', 'compose',
])

const KUBECTL_READ: ReadonlySet<string> = new Set([
  'get', 'describe', 'logs', 'top', 'cluster-info', 'api-resources', 'api-versions',
  'explain', 'events', 'version', 'options', 'diff', 'plugin', 'auth', 'config', 'certificate',
])

const DOCKER_COMPOSE_READ: ReadonlySet<string> = new Set(['ps', 'logs', 'config', 'images', 'top', 'version', 'events', 'ls', 'list'])
const DOCKER_COMPOSE_MODIFY: ReadonlySet<string> = new Set(['up', 'down', 'start', 'stop', 'restart', 'build', 'pull', 'push', 'run', 'exec', 'rm', 'kill', 'pause', 'unpause', 'create', 'scale', 'attach', 'cp', 'exec'])
const DOCKER_SUB_READ: ReadonlySet<string> = new Set(['ls', 'inspect', 'stats', 'top', 'info', 'df', 'prune']) // prune is modify, kept out
const DOCKER_SUB_VERBS: ReadonlySet<string> = new Set([
  'system', 'network', 'volume', 'container', 'image', 'secret', 'config', 'service', 'stack', 'plugin',
])
const DOCKER_SUB_MODIFY: ReadonlySet<string> = new Set([
  'create', 'rm', 'rmi', 'run', 'start', 'stop', 'restart', 'kill', 'update', 'rename', 'commit',
  'save', 'load', 'pull', 'push', 'build', 'tag', 'prune', 'connect', 'disconnect', 'attach',
  'cp', 'export', 'import', 'exec', 'scale', 'rollback', 'deploy', 'remove', 'leave', 'join',
])
/** docker plain lifecycle verbs (two-argument form: "docker run ..." / "docker start ..."). */
const DOCKER_MODIFY_VERBS: ReadonlySet<string> = new Set([
  'run', 'start', 'stop', 'restart', 'kill', 'rm', 'rmi', 'exec', 'build', 'push', 'pull', 'tag',
  'commit', 'save', 'load', 'update', 'rename', 'attach', 'cp', 'export', 'import', 'create',
  'pause', 'unpause', 'login', 'logout', 'swarm', 'stack deploy',
])

const KUBECTL_MODIFY: ReadonlySet<string> = new Set([
  'apply', 'create', 'delete', 'edit', 'scale', 'patch', 'rollout', 'exec', 'port-forward',
  'drain', 'cordon', 'uncordon', 'taint', 'label', 'annotate', 'autoscale', 'set', 'replace',
  'run', 'expose', 'cp', 'attach', 'auth', 'config',
])
const KUBECTL_READ_SPECIAL: ReadonlySet<string> = new Set(['can-i', 'view', 'current-context', 'use-context'])

const RESOLVECTL_READ: ReadonlySet<string> = new Set(['status', 'statistics', 'show', 'query', 'monitor'])
const LOCALECTL_READ: ReadonlySet<string> = new Set(['status', 'show', 'list-locales', 'list-keymaps', 'list-x11-keymap-layouts', 'list-x11-keymap-variants'])
const BRIDGE_READ: ReadonlySet<string> = new Set(['link', 'vlan', 'fdb', 'mdb'])
const OPENSSL_READ: ReadonlySet<string> = new Set(['version', 's_client', 's_time', 'ciphers', 'list', 'help'])
const APT_READ: ReadonlySet<string> = new Set(['list', 'show', 'search', 'policy', 'madison'])
const APT_MODIFY: ReadonlySet<string> = new Set(['install', 'remove', 'purge', 'update', 'upgrade', 'full-upgrade', 'dist-upgrade', 'autoremove', 'clean', 'autoclean', 'download', 'source'])
const YUM_READ: ReadonlySet<string> = new Set(['list', 'info', 'repolist', 'search', 'provides', 'deplist', 'check-update', 'history', 'groups'])
const YUM_MODIFY: ReadonlySet<string> = new Set(['install', 'remove', 'erase', 'purge', 'update', 'upgrade', 'distro-sync', 'distupgrade', 'downgrade', 'reinstall', 'autoremove', 'clean', 'makecache'])
const YUM_HISTORY_MODIFY: ReadonlySet<string> = new Set(['undo', 'rollback'])

/**
 * Confirmed state-writers that are NOT readers: matches here are MODIFY even
 * though the classifier has no read rule for them (wget/scp/rsync write files
 * or remote state by default — never UNKNOWN, never READ).
 */
const KNOWN_MODIFY_TOKENS: ReadonlySet<string> = new Set(['wget', 'scp', 'rsync', 'nc', 'socat', 'telnet', 'watchdog', 'fwupdate', 'passwd', 'chpasswd', 'newusers'])

const READ_RULES: Record<string, ReaderRule> = {
  // ---- confirmed pure readers: any arguments stay read ----
  hostname: 'any', uptime: 'any', date: 'any', whoami: 'any', pwd: 'any', uname: 'any',
  who: 'any', w: 'any', id: 'any', groups: 'any', nproc: 'any', lscpu: 'any',
  ps: 'any', free: 'any', vmstat: 'any', iostat: 'any', mpstat: 'any', pidstat: 'any', sar: 'any',
  df: 'any', du: 'any', ls: 'any', stat: 'any', cat: 'any', head: 'any', tail: 'any',
  grep: 'any', awk: 'any', wc: 'any', sort: 'any', cut: 'any', uniq: 'any', tr: 'any',
  find: 'any', journalctl: 'any', dmesg: 'any', ss: 'any', netstat: 'any', lsof: 'any',
  ping: 'any', traceroute: 'any', host: 'any', dig: 'any', nslookup: 'any', getent: 'any',
  hostnamectl: 'any', timedatectl: 'any', sysctl: 'any', lsblk: 'any', blkid: 'any',
  last: 'any', lastlog: 'any', loginctl: 'any', ip: 'any', curl: 'any', echo: 'any',
  printenv: 'any', clear: 'any', history: 'any',
  nginx: new Set(['v', 'V', 't', 'T']),
  httpd: new Set(['v', 'V', 't', 'T', 'S']),
  apachectl: new Set(['S', 't', 'v', 'V']),
  jcmd: new Set(['l']),
  // V0.4.0: jps only lists JVM processes (-l/-v/-m are display flags).
  jps: 'any',
  java: new Set(['version']),
  node: new Set(['v', 'version']),
  python3: new Set(['V', 'version']),
  python: new Set(['V', 'version']),
  which: 'any', type: 'any', readlink: 'any', realpath: 'any',
  rpm: new Set(['q', 'qa', 'qi', 'ql', 'qf', 'qp', 'V', 'K']),
  dpkg: new Set(['l', 'L', 's', 'S', 'V', 'p']),
  'dpkg-query': 'any',
  'apt-cache': 'any',
  crictl: new Set(['ps', 'pods', 'images', 'stats', 'info', 'version', 'logs', 'inspect', 'top']),
  podman: new Set(['ps', 'images', 'stats', 'info', 'version', 'logs', 'inspect', 'top']),
  supervisorctl: new Set(['status']),
  'systemd-analyze': 'any',
  lsmod: 'any', ethtool: 'any',
  // ---- V0.3.1: newly recognised read-only diagnostics (previously MODIFY) ----
  findmnt: 'any', pstree: 'any', pmap: 'any', lsns: 'any',
  file: 'any', strings: 'any',
  sha1sum: 'any', sha256sum: 'any', sha512sum: 'any', md5sum: 'any', cksum: 'any',
  namei: 'any', getfacl: 'any', lsattr: 'any', lspci: 'any', lsusb: 'any',
  ulimit: 'any', locale: 'any', 'localedef': new Set(['--list-archive']),
  getconf: 'any', 'systemd-detect-virt': 'any', diff: 'any', cmp: 'any', comm: 'any',
  nfsstat: 'any', true: 'any', 'false': 'any', cal: 'any', 'lsb_release': 'any',
  iptables: new Set(['L', 'S', 't', 'h']),
  fuser: 'any',
  watch: { special: watchSpecial },
  strace: { special: straceSpecial },
  ltrace: { special: straceSpecial },
  tcpdump: { special: tcpdumpSpecial },
  // ---- verb-scoped tools (special semantic rules) ----
  systemctl: SYSTEMCTL_READ,
  docker: { verbs: DOCKER_READ, special: dockerSpecial },
  kubectl: { verbs: KUBECTL_READ, special: kubectlSpecial },
  mount: { special: mountSpecial },
  sed: 'any', // -i / --in-place forms are caught by SED_INPLACE before this
  numactl: { verbs: new Set(['hardware', 'show', 'display']), special: numactlSpecial },
  nmcli: { verbs: new Set(['device', 'connection', 'general', 'radio', 'networking']), special: nmcliSpecial },
  resolvectl: RESOLVECTL_READ,
  localectl: LOCALECTL_READ,
  bridge: BRIDGE_READ,
  openssl: OPENSSL_READ,
  yum: { verbs: YUM_READ, special: yumSpecial },
  dnf: { verbs: YUM_READ, special: yumSpecial },
  apt: { verbs: APT_READ, special: aptSpecial },
  'apt-get': { verbs: APT_READ, special: aptSpecial },
  tar: { special: tarSpecial },
  service: { special: serviceSpecial },
  fdisk: new Set(['l']),
  top: new Set(['bn1', 'b', 'n1', 'h']),
}

/** Runtime guard: a Rule that is a Set-of-verbs (the values are created with new Set). */
function isVerbSet(rule: ReaderRule): rule is ReadonlySet<string> {
  return rule instanceof Set
}

/** strip watch/strace option flags (with their value-taking options) and return the inner command. */
function stripWatchlikeOptions(tokens: string[], valueTaking: ReadonlySet<string>): string {
  let i = 1
  for (; i < tokens.length; i++) {
    const t = tokens[i]!
    if (t === '--') {
      i += 1
      break
    }
    if (/^--?[a-zA-Z][a-zA-Z-]*$/.test(t)) {
      const bare = t.replace(/^-+/, '')
      if (valueTaking.has(bare)) {
        const nx = tokens[i + 1]
        if (nx !== undefined && !/^--?[a-zA-Z]/.test(nx) && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(nx)) i += 1
      }
      continue
    }
    break
  }
  return tokens.slice(i).join(' ')
}

/** watch re-executes its command argument: classify the INNER command with the FULL pipeline. */
function watchSpecial(tokens: string[], segment: string): CommandRisk | null {
  const inner = stripWatchlikeOptions(tokens, new Set(['n', 'interval', 'd', 'differences']))
  if (inner.trim().length === 0) return null
  return classifyInnerFully(inner)
}

/** strace/ltrace run their argument: -o writes a trace file, -p attaches; inner is fully classified. */
function straceSpecial(tokens: string[], segment: string): CommandRisk | null {
  const flags = tokens.slice(1).join(' ')
  if (/(?:^|\s)-(?:o|output)\b/.test(flags)) return 'MODIFY'
  if (/(?:^|\s)-p(?:\s|$)/.test(flags)) return 'MODIFY'
  const inner = stripWatchlikeOptions(tokens, new Set(['e', 'p', 'o', 'f', 'T', 'r', 't', 's', 'S', 'c', 'C', 'I', 'x', 'X', 'output']))
  if (inner.trim().length === 0) return 'READ'
  return classifyInnerFully(inner)
}

/** tcpdump -c bounded capture is READ; -w writes a capture file. */
function tcpdumpSpecial(tokens: string[], segment: string): CommandRisk | null {
  const flags = tokens.slice(1).join(' ')
  if (/(?:^|\s)-(?:w|z|C|W)\b/.test(flags)) return 'MODIFY'
  if (/(?:^|\s)-c(?:\.\d+)?(?:\s|$)/.test(flags)) return 'READ'
  return null
}

/** docker + docker compose semantic classification. */
function dockerSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const verb = tokens[1]
  if (verb === undefined) return 'READ' // bare 'docker' prints help
  if (verb === 'compose') {
    const sub = tokens[2]
    if (sub === undefined) return null // 'docker compose' alone -> UNKNOWN
    if (DOCKER_COMPOSE_READ.has(sub)) return 'READ'
    if (DOCKER_COMPOSE_MODIFY.has(sub)) return 'MODIFY'
    return null
  }
  if (DOCKER_SUB_VERBS.has(verb)) {
    const sub = tokens[2]
    if (sub === undefined) return null
    if (sub === 'ls' || sub === 'inspect' || sub === 'df' || sub === 'info' || sub === 'stats' || sub === 'top') return 'READ'
    if (DOCKER_SUB_MODIFY.has(sub)) return 'MODIFY'
    return null
  }
  if (DOCKER_READ.has(verb)) return 'READ'
  if (DOCKER_MODIFY_VERBS.has(verb)) return 'MODIFY'
  return null
}

/** kubectl semantic classification (auth can-i / config view are the read sub-forms). */
function kubectlSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const verb = tokens[1]
  if (verb === undefined) return 'READ' // bare 'kubectl' prints help
  if (verb === 'auth') {
    const sub = tokens[2]
    if (sub === 'can-i') return 'READ'
    if (sub === 'reconcile') return 'MODIFY'
    return null
  }
  if (verb === 'config') {
    const sub = tokens[2]
    if (sub === 'view' || sub === 'current-context' || sub === 'use-context') return 'READ'
    if (sub !== undefined && (sub.startsWith('set') || sub === 'unset' || sub === 'delete-context' || sub === 'delete-cluster' || sub === 'delete-user')) return 'MODIFY'
    return null
  }
  if (KUBECTL_READ.has(verb)) return 'READ'
  if (KUBECTL_MODIFY.has(verb)) return 'MODIFY'
  return null
}

/** mount: only the listing form is READ; anything with a positional arg mounts. */
function mountSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const rest = tokens.slice(1)
  if (rest.length === 0) return 'READ' // bare 'mount' lists
  for (const t of rest) {
    if (t.startsWith('-')) continue
    return 'MODIFY' // a device / mountpoint -> mount operation
  }
  // only flags: -l / -v / -h listing forms are safe, -a / -o / -t / -r / -w alter
  const flags = rest.join(' ')
  if (/-(?:l|v|h|n)(?:\s|$)/.test(flags) && !/-(?:a|o|t|r|w|U|L|B|R|bind|remount|move)\b/.test(flags)) return 'READ'
  return 'MODIFY'
}

/** numactl: --hardware/--show are read; any policy application is not a plain read. */
function numactlSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const rest = tokens.slice(1).join(' ')
  if (/--(?:hardware|show|display)\b/.test(rest) || /^\s*-(?:H|s)\b/.test(' ' + rest)) return 'READ'
  return null
}

/** nmcli: device/connection/general show|status forms are READ. */
function nmcliSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const group = tokens[1]
  const sub = tokens[2]
  if (group === 'general' && (sub === 'status' || sub === 'permissions' || sub === 'hostname')) return 'READ'
  if ((group === 'device' || group === 'connection') && (sub === 'show' || sub === 'status')) return 'READ'
  if (sub === 'list') return 'READ'
  if (NMCli_MODIFY.test(tokens.join(' '))) return 'MODIFY'
  return null
}

/** yum/dnf: query forms READ; history undo/rollback MODIFY; install etc via PKG_MODIFY. */
function yumSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const verb = tokens[1]
  if (verb === 'history') {
    const sub = tokens[2]
    if (sub === undefined) return 'READ'
    if (YUM_HISTORY_MODIFY.has(sub)) return 'MODIFY'
    return null
  }
  if (verb !== undefined && YUM_READ.has(verb)) return 'READ'
  if (verb !== undefined && YUM_MODIFY.has(verb)) return 'MODIFY'
  return null
}

/** apt/apt-get: query forms READ; install etc via PKG_MODIFY. */
function aptSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const verb = tokens[1]
  if (verb !== undefined && APT_READ.has(verb)) return 'READ'
  if (verb !== undefined && APT_MODIFY.has(verb)) return 'MODIFY'
  return null
}

/** tar: list forms (t/tf) READ; create/extract confirmed writes. */
function tarSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const verb = tokens[1] ?? ''
  if (/^t/.test(verb)) return 'READ' // tar t / tf / tvf = list
  return null // c/x/etc fall through to TAR_EXTRACT / TAR_CREATE handling below
}

/** service: `service <name> status|list` READ, lifecycle verbs MODIFY
 *  (the verb comes AFTER the unit name: 'service sshd status' / 'service sshd restart'). */
function serviceSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const t1 = tokens[1]
  if (t1 === '--status-all' || t1 === '--status') return 'READ'
  const verb = t1 === 'status' || t1 === 'list' ? t1 : tokens[2]
  if (verb === 'status' || verb === 'list') return 'READ'
  if (verb !== undefined && /^(?:start|stop|restart|reload|force-reload|condrestart|try-restart)$/.test(verb)) return 'MODIFY'
  return null
}

// ---------------- segment-level forbidden args (a reader may not ...) ----------------

const FORBIDDEN_ARGUMENT_PATTERNS: Array<{ match: RegExp; reason: string }> = [
  { match: /\bfind\b[^&|;]*\s-(?:exec|delete|ok)\b/, reason: 'find -exec/-delete mutates' },
  { match: /\bfind\b[^&|;]*\s-f(?:print|printf|ls)\b/, reason: 'find -fprint/-fprintf/-fls writes files' },
  { match: /\bss\b[^&|;]*\s-K\b/, reason: 'ss -K destroys matching sockets' },
  { match: /\bhistory\b[^&|;]*\s-(?:c|w|a|n|d)\b/, reason: 'history option changes the history file/list' },
  { match: /\bsar\b[^&|;]*\s-o\b/, reason: 'sar -o writes an activity file' },
  { match: /\bblkid\b[^&|;]*\s-w\b/, reason: 'blkid -w writes its cache' },
  { match: /\bnfsstat\b[^&|;]*\s-[zZ]\b/, reason: 'nfsstat -z/-Z resets counters' },
  { match: /\bsystemd-analyze\b[^&|;]*\sset-log-(?:level|target)\b/, reason: 'systemd-analyze set-log changes runtime logging state' },
  { match: /\bsysctl\b[^&|;]*\s-(?:w|write)\b/, reason: 'sysctl -w mutates' },
  { match: /\bcurl\b[^&|;]*\s-{1,2}(?:o|output|O|remote-name|T|upload-file|F|form|d|data|data-binary|data-raw|data-urlencode|json)\b/, reason: 'curl writes files / posts data / uploads' },
  { match: /\bcurl\b[^&|;]*\s-X[A-Za-z]+\b/, reason: 'curl -XVERB sends a non-query request' },
  { match: /\bcurl\b[^&|;]*\s(?:-X|--request)\s+\S+(?<!GET|HEAD)\b/i, reason: 'curl non-GET/HEAD mutates' },
  { match: /\bawk\b[^&|;]*\bsystem\s*\(/, reason: 'awk system() may run anything' },
  { match: /\bfuser\b[^&|;]*\s-k\b/, reason: 'fuser -k kills processes' },
  { match: /\bstrace\b[^&|;]*\s-p\b/, reason: 'strace -p attaches to a process' },
  { match: /\b(?:bash|sh)\s+-c\b/, reason: 'shell -c wrapping is not verifiable' },
]

// ---------------- tokenization & quoting ----------------

/** First significant token after stripping a leading env assignment. */
const TRUSTED_SYSTEM_DIRS = new Set(['/bin', '/sbin', '/usr/bin', '/usr/sbin'])
const TRUSTED_COMMAND_ALIASES: Record<string, readonly string[]> = {
  'redis-cli': ['/usr/emp/cachesrv/redis/bin/redis-cli'],
}

export function canonicalExecutable(token: string): string | undefined {
  if (!token.includes('/')) return token
  if (!token.startsWith('/')) return undefined
  const normalized = token.replace(/\/{2,}/g, '/')
  const parts = normalized.split('/').filter(Boolean)
  if (parts.some((part) => part === '.' || part === '..')) return undefined
  const base = parts.at(-1)
  if (base === undefined) return undefined
  const parent = '/' + parts.slice(0, -1).join('/')
  if (TRUSTED_SYSTEM_DIRS.has(parent)) return base
  return TRUSTED_COMMAND_ALIASES[base]?.includes(normalized) === true ? base : undefined
}

function firstToken(segment: string): string | undefined {
  const toks = tokensOf(segment)
  for (const t of toks) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) continue
    return canonicalExecutable(t)
  }
  return undefined
}

/** Whitespace tokens of one segment. */
function tokensOf(segment: string): string[] {
  return segment.split(/\s+/u).filter((t) => t.length > 0)
}

/** Mask quoted regions (and escaped chars) so dangerous-syntax scans ignore quoted content. */
function maskQuoted(command: string): string {
  let out = ''
  let quote: "'" | '"' | null = null
  let i = 0
  while (i < command.length) {
    const ch = command[i]!
    if (quote !== null) {
      out += ch === quote ? quote : 'x'
      if (ch === quote) quote = null
      i++
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      out += ch
      i++
      continue
    }
    if (ch === '\\' && i + 1 < command.length) {
      out += ' '
      i += 2
      continue
    }
    out += ch
    i++
  }
  return out
}

/** Split on ; && || | at quote/escape boundaries (quoted pipes stay intact). */
export function splitSegments(command: string): string[] {
  const segments: string[] = []
  let current = ''
  let quote: "'" | '"' | null = null
  let i = 0
  while (i < command.length) {
    const ch = command[i]!
    if (quote !== null) {
      current += ch
      if (ch === quote) quote = null
      i++
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      current += ch
      i++
      continue
    }
    if (ch === '\\' && i + 1 < command.length) {
      current += ch + command[i + 1]!
      i += 2
      continue
    }
    if (ch === ';' || ch === '&' || ch === '|') {
      if (ch === '&' && i > 0 && command[i - 1] === '>') {
        current += ch
        i++
        continue
      }
      while (i < command.length && (command[i] === ';' || command[i] === '&' || command[i] === '|')) i++
      if (current.trim().length > 0) segments.push(current.trim())
      current = ''
      continue
    }
    current += ch
    i++
  }
  if (current.trim().length > 0) segments.push(current.trim())
  return segments
}

// ---------------- wrapper stripping ----------------

const WRAPPER_TOKENS = new Set(['env', 'timeout', 'nice'])

function isWrapperToken(token: string | undefined): boolean {
  return token !== undefined && WRAPPER_TOKENS.has(token)
}

function stripWrapper(segment: string, wrapper: string): string {
  const toks = tokensOf(segment)
  let i = 1
  for (; i < toks.length; i++) {
    const t = toks[i]!
    if (t === '--') {
      i += 1
      break
    }
    if (/^--?[a-zA-Z][a-zA-Z-]*$/.test(t)) {
      const next = toks[i + 1]
      if (next !== undefined && !/^--?[a-zA-Z]/.test(next) && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(next)) i += 1
      continue
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) continue
    if (wrapper === 'timeout' && /^\d+(\.\d+)?$/.test(t)) continue
    break
  }
  void wrapper
  return toks.slice(i).join(' ')
}

type SemanticVerdict = { risk: CommandRisk; ruleId: string; reason: string; confidence?: Confidence }
const verdict = (risk: CommandRisk, ruleId: string, reason: string, confidence: Confidence = 'HIGH'): SemanticVerdict => ({ risk, ruleId, reason, confidence })
const semanticRead = (ruleId: string, reason: string): SemanticVerdict => verdict('READ', ruleId, reason)

function semanticV21(segment: string): SemanticVerdict | null {
  const tokens = tokensOf(segment)
  const raw = tokens.find((t) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t))
  const command = raw === undefined ? undefined : canonicalExecutable(raw)
  if (command === undefined) return null
  const start = tokens.indexOf(raw!) + 1
  const args = tokens.slice(start)
  const lower = args.map((t) => t.toLowerCase())

  if (command === 'hostname') {
    if (args.some((t) => t === '-F' || t === '--file' || !t.startsWith('-'))) return verdict('MODIFY', 'hostname.set', 'hostname argument or -F changes the system hostname')
    return semanticRead('hostname.show', 'hostname display form is read-only')
  }
  if (command === 'date') {
    if (args.some((t) => t === '-s' || t === '--set' || t.startsWith('--set='))) return verdict('MODIFY', 'date.set', 'date -s/--set changes the system clock')
    return semanticRead('date.show', 'date display form is read-only')
  }
  if (command === 'journalctl') {
    const mut = args.find((t) => t === '--rotate' || t === '--flush' || t === '--sync' || /^--vacuum-(?:size|time|files)=/.test(t))
    if (mut !== undefined) {
      const kind = mut.startsWith('--vacuum-') ? 'vacuum' : mut.slice(2)
      return verdict('MODIFY', 'journalctl.mutate.' + kind, 'journalctl ' + mut + ' changes journal state or files')
    }
    return semanticRead('journalctl.read', 'journalctl query form is read-only')
  }
  if (command === 'dmesg') {
    if (args.some((t) => ['-C', '--clear', '-c', '--read-clear'].includes(t))) return verdict('MODIFY', 'dmesg.clear', 'dmesg clear/read-clear changes the kernel ring buffer')
    if (args.some((t) => t === '-n' || t === '--console-level' || t.startsWith('--console-level='))) return verdict('MODIFY', 'dmesg.console-level', 'dmesg console-level changes kernel console state')
    return semanticRead('dmesg.read', 'dmesg query form is read-only')
  }
  if (command === 'sysctl') {
    if (args.some((t) => ['-w', '--write', '--system', '-p', '--load'].includes(t) || t.startsWith('--load=') || (!t.startsWith('-') && t.includes('=')))) return verdict('MODIFY', 'sysctl.write', 'sysctl write/load form changes kernel runtime parameters')
    return semanticRead('sysctl.read', 'sysctl query form is read-only')
  }
  if (command === 'sort') {
    if (args.some((t) => t === '-o' || t === '--output' || t.startsWith('--output='))) return verdict('MODIFY', 'sort.output', 'sort -o/--output writes a file')
    return semanticRead('sort.stdout', 'sort writes only to stdout')
  }
  if (command === 'uniq') {
    const valueOpts = new Set(['-f', '-s', '-w', '--skip-fields', '--skip-chars', '--check-chars'])
    const positional: string[] = []
    for (let i = 0; i < args.length; i++) { const t = args[i]!; if (valueOpts.has(t)) { i++; continue }; if (!t.startsWith('-')) positional.push(t) }
    if (positional.length >= 2) return verdict('MODIFY', 'uniq.output', 'uniq second positional path is an output file')
    return semanticRead('uniq.stdout', 'uniq has no output file')
  }
  if (command === 'sed') {
    if (args.some((t) => /^-i(?:$|.|[^a-zA-Z])/.test(t) || t === '--in-place' || t.startsWith('--in-place='))) return verdict('MODIFY', 'sed.in-place', 'sed in-place editing writes files')
    if (/(?:^|[\s;{,'/$^*+0-9])[wW]\s+\S/.test(segment)) return verdict('MODIFY', 'sed.script-write', 'sed program contains w/W file output')
    return semanticRead('sed.stdout', 'sed program writes only to stdout')
  }
  if (command === 'awk') {
    if (/\bsystem\s*\(/.test(segment)) return verdict('MODIFY', 'awk.system', 'awk system() executes arbitrary commands')
    if (/[>]{1,2}\s*["']/.test(segment)) return verdict('MODIFY', 'awk.redirect', 'awk program redirects output to a file')
    if (/[>]{1,2}/.test(segment) && !/(?:NR|NF|\$\d+)\s*>[=]?\s*\d/.test(segment)) return verdict('UNKNOWN', 'awk.redirect-ambiguous', 'awk output redirection cannot be excluded', 'LOW')
    return semanticRead('awk.stdout', 'awk program has no file-write construct')
  }
  if (command === 'systemctl') {
    const verb = args.find((t) => !t.startsWith('-'))
    if (verb === undefined) return semanticRead('systemctl.flag-list', 'systemctl flag-only form lists units')
    if (SYSTEMCTL_READ.has(verb)) return semanticRead('systemctl.' + verb, 'systemctl ' + verb + ' is read-only')
    return null
  }
  if (command === 'ip') {
    const significant = lower.filter((t) => !t.startsWith('-'))
    const group = significant[0]
    const sub = significant[1]
    if (group === undefined || ['monitor', 'help'].includes(group)) return semanticRead('ip.show', 'ip display form is read-only')
    const mutation: Record<string, Set<string>> = {
      link: new Set(['set','add','del','delete','replace']), addr: new Set(['add','del','delete','replace','flush','change']), address: new Set(['add','del','delete','replace','flush','change']),
      route: new Set(['add','del','delete','replace','flush','change','append','prepend']), neigh: new Set(['add','del','delete','replace','flush']), neighbour: new Set(['add','del','delete','replace','flush']),
      rule: new Set(['add','del','delete','flush']), maddr: new Set(['add','del','delete']), netns: new Set(['add','del','delete','set']),
    }
    if (sub !== undefined && mutation[group]?.has(sub) === true) return verdict('MODIFY', 'ip.mutate.' + sub, 'ip ' + group + ' ' + sub + ' changes network state')
    const groups = new Set(['addr','address','link','route','neigh','neighbour','rule','maddr','mroute','netns'])
    if (!groups.has(group)) return null
    if (sub === undefined || ['show','list','get','monitor'].includes(sub)) return semanticRead('ip.' + group + '.' + (sub ?? 'show'), 'ip query form is read-only')
    return null
  }
  if (command === 'kubectl') {
    const verb = lower[0]
    const sub = lower[1]
    if (verb === 'config') {
      if (['view','current-context','get-contexts','get-clusters','get-users'].includes(sub ?? '')) return semanticRead('kubectl.config.' + sub, 'kubectl config query is read-only')
      if (sub !== undefined && (sub === 'use-context' || sub === 'unset' || sub === 'rename-context' || sub.startsWith('set-') || sub.startsWith('delete-'))) return verdict('MODIFY', 'kubectl.config.' + sub, 'kubectl config ' + sub + ' writes kubeconfig')
      return null
    }
    if (verb === 'auth') {
      if (sub === 'can-i' || sub === 'whoami') return semanticRead('kubectl.auth.' + sub, 'kubectl auth query is read-only')
      if (sub === 'reconcile') return verdict('MODIFY', 'kubectl.auth.reconcile', 'kubectl auth reconcile changes RBAC resources')
    }
    return null
  }
  if (command === 'ulimit') {
    if (args.some((t) => !t.startsWith('-')) || args.some((t) => /^-[A-Za-z]+\d/.test(t))) return verdict('MODIFY', 'ulimit.set', 'ulimit with a value changes the shell resource limit')
    return semanticRead('ulimit.show', 'ulimit query form is read-only')
  }
  if (command === 'redis-cli') {
    const valued = new Set(['-h','-p','-s','-n','-a','--user','--pass','--cert','--key','--cacert'])
    const words: string[] = []
    for (let i = 0; i < args.length; i++) { const t = args[i]!; if (t.startsWith('-')) { if (valued.has(t) && !t.includes('=')) i++; continue }; words.push(t.toUpperCase()) }
    const cmd = words[0]; const sub = words[1]
    if (cmd === undefined) return semanticRead('redis-cli.help', 'bare redis-cli is non-mutating')
    if (['FLUSHDB','FLUSHALL','SHUTDOWN'].includes(cmd) || (cmd === 'DEBUG' && sub === 'SEGFAULT')) return verdict('DANGEROUS', 'redis-cli.dangerous.' + cmd.toLowerCase(), 'Redis ' + cmd + ' is destructive')
    if (cmd === 'EVAL' || cmd === 'EVALSHA') return verdict('UNKNOWN', 'redis-cli.unknown.' + cmd.toLowerCase(), 'Redis scripts may read or write', 'LOW')
    const read = new Set(['PING','INFO','DBSIZE','TIME','ROLE','COMMAND','GET','MGET','HGET','HGETALL','HMGET','LRANGE','LLEN','SCARD','SMEMBERS','ZRANGE','ZCARD','TTL','PTTL','TYPE','EXISTS','SCAN','SSCAN','HSCAN','ZSCAN','KEYS','RANDOMKEY'])
    const modify = new Set(['SET','SETEX','PSETEX','MSET','DEL','UNLINK','EXPIRE','PEXPIRE','EXPIREAT','PERSIST','HSET','HDEL','LPUSH','RPUSH','LPOP','RPOP','SADD','SREM','ZADD','ZREM','INCR','DECR','SAVE','BGSAVE','BGREWRITEAOF','REPLICAOF','SLAVEOF','MIGRATE','RESTORE'])
    if (cmd === 'CONFIG') { if (sub === 'GET') return semanticRead('redis-cli.read.config-get','Redis CONFIG GET is read-only'); if (sub === 'SET' || sub === 'REWRITE') return verdict('MODIFY','redis-cli.mutate.config-' + sub.toLowerCase(),'Redis CONFIG changes server state') }
    if (cmd === 'CLIENT') { if (sub === 'LIST' || sub === 'INFO') return semanticRead('redis-cli.read.client-' + sub.toLowerCase(),'Redis CLIENT query is read-only'); if (sub === 'KILL' || sub === 'PAUSE') return verdict('MODIFY','redis-cli.mutate.client-' + sub.toLowerCase(),'Redis CLIENT command changes connection state') }
    if (cmd === 'SLOWLOG' && (sub === 'GET' || sub === 'LEN')) return semanticRead('redis-cli.read.slowlog-' + sub.toLowerCase(),'Redis SLOWLOG query is read-only')
    if (cmd === 'MEMORY' && (sub === 'STATS' || sub === 'DOCTOR')) return semanticRead('redis-cli.read.memory-' + sub.toLowerCase(),'Redis MEMORY query is read-only')
    if (cmd === 'ACL') { if (sub !== undefined && ['LIST','GETUSER','WHOAMI'].includes(sub)) return semanticRead('redis-cli.read.acl-' + sub.toLowerCase(),'Redis ACL query is read-only'); if (sub === 'SETUSER' || sub === 'DELUSER') return verdict('MODIFY','redis-cli.mutate.acl-' + sub.toLowerCase(),'Redis ACL command changes users') }
    if (cmd === 'SCRIPT' && (sub === 'FLUSH' || sub === 'LOAD')) return verdict('MODIFY','redis-cli.mutate.script-' + sub.toLowerCase(),'Redis SCRIPT command changes script cache')
    if (read.has(cmd)) return semanticRead('redis-cli.read.' + cmd.toLowerCase(), 'Redis ' + cmd + ' is read-only')
    if (modify.has(cmd)) return verdict('MODIFY','redis-cli.mutate.' + cmd.toLowerCase(),'Redis ' + cmd + ' changes data or server state')
    return verdict('UNKNOWN','redis-cli.unknown','Redis command semantics are unknown','LOW')
  }
  return null
}

// ---------------- classification core ----------------

function classificationOf(risk: CommandRisk, reason: string, ruleId: string, command: string, confidence: Confidence = 'HIGH'): Classification {
  return {
    risk,
    reason,
    ruleId,
    command,
    normalizedCommand: command.trim().replace(/\s+/g, ' '),
    classifierVersion: CLASSIFIER_VERSION,
    confidence,
  }
}

/** Classify one pipeline segment (no sudo/wrapper prefix). Full reader rule. */
function classifyPlainSegment(segment: string, whole: string): Classification {
  const semantic = semanticV21(segment)
  if (semantic !== null) return classificationOf(semantic.risk, semantic.reason, semantic.ruleId, segment, semantic.confidence ?? 'HIGH')
  const token = firstToken(segment)
  const rule = token !== undefined ? READ_RULES[token] : undefined

  if (rule === undefined) {
    // Confirmed state-writers first (wget/scp/rsync...): MODIFY, never UNKNOWN.
    if (token !== undefined && KNOWN_MODIFY_TOKENS.has(token)) {
      return classificationOf('MODIFY', token + ' writes files or remote state by default', token + '.modify', segment)
    }
    // Unknown first token: not claimed modifying. If a mutating verb or write
    // redirect appears anywhere, the whole-command scan already returned MODIFY.
    return classificationOf('UNKNOWN', "command '" + (token ?? '?') + "' has no semantic rule; read-only cannot be confirmed", 'unknown.command', segment, 'LOW')
  }

  const tokens = tokensOf(segment)

  // special() first: it has the most knowledge (docker/kubectl/mount/...)
  const ruleSet = isVerbSet(rule) ? rule : undefined
  const ruleObj = rule !== null && typeof rule === 'object' && 'special' in rule ? rule : undefined
  if (ruleObj !== undefined && ruleObj.special !== undefined) {
    const decided = ruleObj.special(tokens, segment)
    if (decided === 'READ') return classificationOf('READ', segment + ' is read-only', token + '.rule', segment)
    if (decided === 'MODIFY') return classificationOf('MODIFY', token + ' modifies server state', token + '.mutate', segment)
    if (decided === 'DANGEROUS') return classificationOf('DANGEROUS', token + ' is host-destructive', token + '.dangerous', segment)
    if (decided === 'PRIVILEGED_READ') return classificationOf('PRIVILEGED_READ', segment + ' is a privileged read', token + '.rule', segment)
  }

  if (rule === 'any') {
    // segment-level forbidden args still apply to 'any' readers
    for (const { match: m, reason } of FORBIDDEN_ARGUMENT_PATTERNS) {
      if (m.test(segment)) return classificationOf('MODIFY', reason, token + '.forbidden-arg', segment)
    }
    return classificationOf('READ', token + ' is a confirmed reader', token + '.any', segment)
  }

  const verbs = ruleObj !== undefined ? ruleObj.verbs : ruleSet
  const opts = tokens.slice(1).map((o) => o.replace(/^-+/u, ''))
  const matched = verbs !== undefined ? opts.some((o) => verbs.has(o)) : false
  if (matched) {
    for (const { match: m, reason } of FORBIDDEN_ARGUMENT_PATTERNS) {
      if (m.test(segment)) return classificationOf('MODIFY', reason, token + '.forbidden-arg', segment)
    }
    return classificationOf('READ', token + ' verb is read-only', token + '.rule', segment)
  }

  // Known tool, unknown subcommand/verb: the classifier cannot confirm the
  // command is read-only — UNKNOWN (never "claimed modifying").
  return classificationOf('UNKNOWN', token + " verb '" + (opts[0] ?? '') + "' is not a known read form; read-only cannot be confirmed", token + '.unknown-verb', segment, 'LOW')
}

/**
 * Classify one segment handling sudo (-> PRIVILEGED_READ for readers) and
 * wrapper chains (env/timeout/nice at any depth), which NEVER downgrade the
 * inner command. The whole-command scans (danger + mutation) are assumed to
 * have already run over the full command text.
 */
function classifySegment(segment: string): Classification {
  const token = firstToken(segment)
  if (token === 'sudo') {
    const rest = segment.replace(/^sudo\b\s*/u, '')
    if (rest.trim().length === 0) return classificationOf('UNKNOWN', 'bare sudo', 'sudo.bare', segment)
    const inner = classifySegment(rest)
    if (inner.risk === 'READ') {
      return classificationOf('PRIVILEGED_READ', 'privileged read (sudo): ' + inner.ruleId, 'sudo.privileged-read', segment)
    }
    // sudo never downgrades: MODIFY/DANGEROUS/UNKNOWN stay as classified
    return { ...inner, command: segment }
  }
  if (isWrapperToken(token)) {
    const inner = stripWrapper(segment, token!)
    if (inner.trim().length === 0) return classificationOf('READ', 'bare ' + token + ' only lists its environment', token + '.bare', segment)
    const innerClass = classifySegment(inner)
    return { ...innerClass, command: segment }
  }
  return classifyPlainSegment(segment, segment)
}

/**
 * Whole-command scans shared by classifyCommand AND wrapper-like readers
 * (watch/strace execute their argument via sh -c, so the inner text must go
 * through the SAME danger + opaque + mutation pipeline — never just the
 * segment rules). Returns a decisive Classification, or null when the scans
 * do not fire (the caller then runs per-segment classification).
 */
function scanWholeCommand(command: string): Classification | null {
  const trimmed = command.trim()
  if (trimmed.length === 0) return null

  // 1) whole-command dangerous phrases (independent of segmentation)
  for (const pattern of DANGEROUS_COMMANDS) {
    if (pattern.test(trimmed)) return classificationOf('DANGEROUS', DANGEROUS_REASON(pattern.source), 'dangerous.pattern', trimmed)
  }

  const masked = maskQuoted(trimmed)

  // 2) opaque shell syntax -> UNKNOWN (honest: cannot be verified as read-only,
  //    and NOT claimed to modify)
  if (OPAQUE_SYNTAX_PATTERN.test(masked)) {
    return classificationOf('UNKNOWN', 'opaque shell syntax; read-only cannot be confirmed', 'syntax.opaque', trimmed, 'LOW')
  }

  // 3) confirmed mutation anywhere (verb-scoped + plain modifier verbs + write redirect)
  const whole = ' ' + masked + ' '
  const systemctlMutation = whole.match(/\bsystemctl\b[^&|;]*\s(start|stop|restart|reload|reload-or-restart|try-restart|condrestart|force-reload|enable|disable|reenable|mask|unmask|daemon-reload|daemon-reexec|kill|reset-failed|set-default|set-property|edit|add-wants|add-requires|preset|preset-all|isolate|switch-root|halt|poweroff|reboot|kexec|suspend|hibernate|hybrid-sleep|freeze|exit|rescue|emergency)\b/)
  if (systemctlMutation !== null) return classificationOf('MODIFY', 'systemctl ' + systemctlMutation[1] + ' changes server state', 'systemctl.mutate.' + systemctlMutation[1], trimmed)
  if (SED_INPLACE.test(whole)) return classificationOf('MODIFY', 'sed in-place editing writes files', 'sed.in-place', trimmed)
  if (
    SERVICE_MODIFY.test(whole) ||
    PKG_MODIFY.test(whole) ||
    SED_INPLACE.test(whole) ||
    TAR_EXTRACT.test(whole) ||
    TAR_CREATE.test(whole) ||
    SU_EXEC.test(whole) ||
    HOSTNAMECTL_MODIFY.test(whole) ||
    TIMEDATECTL_MODIFY.test(whole) ||
    LOGINCTL_MODIFY.test(whole) ||
    LOCALECTL_MODIFY.test(whole) ||
    RESOLVECTL_MODIFY.test(whole) ||
    NMCli_MODIFY.test(whole) ||
    ETHTOOL_MODIFY.test(whole) ||
    IPTABLES_MODIFY.test(whole) ||
    MODIFY_VERBS.test(whole) ||
    hasFileWriteRedirection(trimmed) !== null
  ) {
    return classificationOf('MODIFY', 'mutating verb or write redirect detected', 'mutation.verb', trimmed)
  }
  return null
}

/** Full classification of an inner command string (watch/strace specials). */
function classifyInnerFully(text: string): CommandRisk {
  const inner = text.replace(/^['"]([\s\S]*)['"]$/, '$1')
  const scanned = scanWholeCommand(inner)
  if (scanned !== null) return scanned.risk
  const segments = splitSegments(inner)
  if (segments.length === 0) return 'UNKNOWN'
  const order: Record<CommandRisk, number> = { READ: 0, PRIVILEGED_READ: 1, UNKNOWN: 2, MODIFY: 3, DANGEROUS: 4 }
  let worst: CommandRisk = 'READ'
  for (const segment of segments) {
    const c = classifySegment(segment)
    if (order[c.risk] > order[worst]) worst = c.risk
  }
  return worst
}

/** Main entry: full pipeline over the whole command. */
export function classifyCommand(command: string): Classification {
  const trimmed = command.trim()
  if (trimmed.length === 0) {
    return classificationOf('UNKNOWN', 'empty command', 'unknown.command', command, 'LOW')
  }

  const scanned = scanWholeCommand(trimmed)
  if (scanned !== null) return scanned

  // 4) every segment must classify; take the worst result (never downgrade)
  const segments = splitSegments(trimmed)
  if (segments.length === 0) {
    return classificationOf('UNKNOWN', 'unparseable command', 'unknown.command', trimmed, 'LOW')
  }
  let worst: Classification | null = null
  const order: Record<CommandRisk, number> = { READ: 0, PRIVILEGED_READ: 1, UNKNOWN: 2, MODIFY: 3, DANGEROUS: 4 }
  for (const segment of segments) {
    const c = classifySegment(segment)
    if (worst === null || order[c.risk] > order[worst.risk]) worst = c
  }
  if (worst === null) return classificationOf('UNKNOWN', 'unparseable command', 'unknown.command', trimmed, 'LOW')
  return worst
}

/**
 * Strict READ_ONLY gate: only plain READ passes; PRIVILEGED_READ / UNKNOWN /
 * MODIFY / DANGEROUS are blocked. (The permission matrix additionally decides
 * whether PRIVILEGED_READ may run in READ_ONLY via privilegedReadInReadOnly.)
 */
export function isReadOnlyAllowed(command: string): { allowed: boolean; reason?: string } {
  const { risk, reason } = classifyCommand(command)
  if (risk === 'READ') return { allowed: true }
  return { allowed: false, reason: reason ?? 'not a confirmed read-only command' }
}

/**
 * Backward-compatible one-segment classifier (wrapper recursion + sudo aware).
 * Returns the classic risk letters; UNKNOWN is returned for unrecognized
 * segments.
 */
export function readClassifySegment(segment: string): CommandRisk {
  return classifySegment(segment).risk
}
