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

/**
 * Compound destructive patterns: matched against the RAW command text (quotes
 * included) because the destructive payload may be a quoted argument of a
 * wrapper (e.g. `bash -c "rm -rf /"`).
 */
const DANGEROUS_COMMANDS: RegExp[] = [
  /\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)*\/(?:\s|\*|$)/, // rm -rf /
  /\bmkfs(?:\.\w+)?\b/,
  /\bwipefs\b/,
  /\bdd\b/,
  /\biptables\s+-[FX]\b/,
  /\biptables\s+-P\b/, // set a chain policy — can lock the host out
  /\bDROP\s+DATABASE\b|\bTRUNCATE\s+TABLE\b/i,
  /:\s*\(\s*\)\s*\{[^}]*\|/, // fork bomb :(){ :|:& };:
  /\bkill\s+-9\s+-1\b/,
  /\bchmod\s+-[a-zA-Z]*R[a-zA-Z]*[^&|;]*\s+0*777\s+\//, // chmod -R 777 /
  /\b(?:yes|yum|dnf)\s+\|\s+.*\b(?:rm|mkfs)\b/i, // piped destructive (conservative)
]

/**
 * Bare destructive VERBS: dangerous as a COMMAND (`shutdown -h now`,
 * `systemctl reboot`) but harmless as a literal argument
 * (`grep -i 'shutdown' /var/log/messages`).
 *
 * The word must not be part of a longer identifier or a path, so
 * `/etc/init.d/rc.shutdown` is NOT a destructive command.
 */
const DANGEROUS_COMMAND_WORDS: readonly string[] = ['shutdown', 'reboot', 'poweroff', 'halt']

/**
 * Destructive executables: only dangerous in the COMMAND POSITION.
 *
 * NOTE: `fdisk` / `sgdisk` / `parted` are deliberately NOT here — the reader
 * registry covers their read-only forms (`fdisk -l` is READ), and their
 * writing forms are already UNKNOWN (fail-closed) there.
 */
const DANGEROUS_EXECUTABLES: ReadonlySet<string> = new Set(['dd', 'wipefs'])

/** Destructive executable name prefixes (mkfs.ext4, mkfs.xfs, ...). */
const DANGEROUS_EXECUTABLE_PREFIXES: readonly string[] = ['mkfs']

/**
 * Tools whose SUBCOMMAND verb is destructive: `systemctl reboot` /
 * `systemctl poweroff` destroy the host just like the bare word does.
 */
const DANGEROUS_VERB_HOSTS: ReadonlySet<string> = new Set(['systemctl', 'service', 'shutdown', 'reboot', 'halt', 'poweroff'])

const DANGEROUS_REASON = (source: string): string => 'dangerous pattern: ' + source

// ---------------- opaque syntax -> UNKNOWN ----------------

/** Shell constructs the classifier cannot analyze: never claimed read-only,
 *  never claimed modifying either. UNKNOWN keeps READ_ONLY closed and AUTO/
 *  FULL_ACCESS prompting, with honest copy. */
const OPAQUE_SYNTAX_PATTERN =
  /\b(?:bash|sh|su|sudo)\s+-c\b|\bpython3?\s+-c\b|\bperl\s+-e\b|\bsystem\s*\(/i

// ---------------- whole-command CONFIRMED mutation ----------------

/** Plain modifier verbs (word-boundary, anywhere in the masked command).
 *  mount/sed/tar are handled by dedicated rules below.
 *
 *  NOTE (V0.7.0): `crontab` is deliberately NOT here. `crontab -l` only lists
 *  the crontab, so matching the word made a read-only query look like a write.
 *  The form is parsed in semanticV21 instead (list / edit / install). */
const MODIFY_VERBS =
  /\b(?:rm|mv|cp|touch|mkdir|rmdir|install|chmod|chown|chgrp|ln|kill|pkill|killall|tee|truncate|umount|useradd|userdel|usermod|groupadd|groupdel|groupmod|at|systemd-run|unzip|gunzip|zip|chroot|git|svn|make|cmake|npm|yarn|pnpm|pip|pip3|apt|apt-get|yum|dnf|zypper|pacman|setfacl|chattr|chacl|restorecon|semanage|mkuser|htpasswd|vipw|vigr|cgcreate|nulloep|newgrp)\b/i

const SYSTEMCTL_MODIFY = /\bsystemctl\b[^&|;]*\s(?:start|stop|restart|reload|reload-or-restart|try-restart|condrestart|force-reload|enable|disable|reenable|mask|unmask|daemon-reload|daemon-reexec|kill|reset-failed|set-default|set-property|edit|add-wants|add-requires|preset|preset-all|isolate|switch-root|halt|poweroff|reboot|kexec|suspend|hibernate|hybrid-sleep|freeze|exit|rescue|emergency)\b/
const SERVICE_MODIFY = /\bservice\b[^&|;]*\s(?:start|stop|restart|reload|force-reload|condrestart|try-restart)\b/
const PKG_MODIFY = /\b(?:apt|apt-get|yum|dnf|zypper|pacman|apk)\b[^&|;]*\s(?:install|remove|purge|erase|update|upgrade|full-upgrade|dist-upgrade|distro-sync|autoremove|downgrade|reinstall|clean|autoclean|makecache|download|source)\b/
const SED_INPLACE = /\bsed\b[^&|;]*\s-{1,2}i[a-zA-Z]*(?:\.\S+)?\b/
/*
 * tar's mode letters can be bundled into ONE short-option cluster
 * (`tar czf out.tar.gz dir` == `tar -c -z -f out.tar.gz`), so the `-` is
 * optional as long as the cluster CONTAINS `c` / `x`.
 */
const TAR_EXTRACT = /\btar\b[^&|;]*\s(?:-[a-zA-Z]*)?x[a-zA-Z]*\b/
const TAR_CREATE = /\btar\b[^&|;]*\s(?:-[a-zA-Z]*)?c[a-zA-Z]*\b/
/**
 * `su`/`sudo` running a command via `-c`.
 *
 * The user may be named between `su` and `-c` (`su - prdadm -c "..."`), so the
 * pattern allows an optional login dash and an optional user name. Missing
 * that gap let a privilege-switching command escape the modifier-verb scan.
 */
const SU_EXEC = /\b(?:su|sudo)\s+(?:-\w+\s+)*(?:-c|--command)\b/
const HOSTNAMECTL_MODIFY = /\bhostnamectl\b[^&|;]*\s(?:set-|transient\b|pretty\b)/
const TIMEDATECTL_MODIFY = /\btimedatectl\b[^&|;]*\s(?:set-|ntp\b)/
const LOGINCTL_MODIFY = /\bloginctl\b[^&|;]*\s(?:terminate-|kill-|lock-|unlock-|set-|enable-linger|disable-linger)/
const LOCALECTL_MODIFY = /\blocalectl\b[^&|;]*\s(?:set-)\b/
const RESOLVECTL_MODIFY = /\bresolvectl\b[^&|;]*\s(?:flush-caches|reset-statistics|set-|dnssec\s+(?:on|off|allow-downgrade))\b/
const NMCli_MODIFY = /\bnmcli\b[^&|;]*\s(?:device|connection|general|radio|networking)\s+(?:disconnect|up|down|modify|delete|add|edit|set|reapply|reload|connect|on|off|enable|disable)\b/
const ETHTOOL_MODIFY = /\bethtool\b[^&|;]*\s-(?:s|K|G|A|C|N|W|L|S|coalesce|features|pause|ring|channels|offload|eee|fec)\b/
const IPTABLES_MODIFY = /\biptables\s+-[ADIRZ]\b/

/**
 * Write-redirection operator with an optional FD prefix: ">", "2>", ">>", "2>>".
 *
 * The prefix must accept a NON-word character before the operator, otherwise
 * `echo 'x' >> file` (the `>` follows a closing quote, not a word character)
 * would not match and the write would be silently classified as READ.
 * `-` and `=` are excluded so that arrows (`->`, `=>`) are not redirections.
 */
const REDIRECT_OP = /(?:^|\b|[^\w>=-])(\d{1,2})?\s*[>»]{1,2}\s*([^;|>\s»]*)/g

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
  // ---- V0.7.0 (C-1): gzip/grep twins and process-listing helpers. These are
  // pure readers: zgrep/zcat only decompress to stdout, pgrep only lists.
  zgrep: 'any', zcat: 'any', zless: 'any', zmore: 'any', zdiff: 'any',
  pgrep: 'any', pidof: 'any',
  // `cd` only changes the shell's working directory: no file is written and no
  // server state changes. It is the standard prefix of a read-only
  // investigation ("cd /data && awk ... && wc -l"), and rejecting it made the
  // whole compound unknown.
  cd: 'any',
  // `printf`/`echo` write to stdout only. A file-writing form would be caught
  // by the write-redirect scan.
  printf: 'any',
  // `[ ... ]` / `test ...` are the POSIX test builtins: they evaluate a
  // condition and print true/false. They run no external program and change
  // nothing. `read` reads one line into a variable — also side-effect free
  // with respect to the host.
  '[': 'any', test: 'any', read: 'any',
  // `bash -n` / `sh -n` parse a script WITHOUT executing it (syntax check).
  // `bash -c` executes and stays in the opaque bucket.
  ifconfig: 'any',
  mysqldumpslow: 'any',
  // `rpcinfo -p` lists the registered RPC programs: read-only. The bare form
  // (`rpcinfo host`) queries a host, also read-only.
  rpcinfo: 'any',
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

/**
 * Global kubectl flags that take a VALUE. A global flag may appear BEFORE the
 * verb (`kubectl -n kube-system patch configmap ...`), so the verb cannot be
 * taken as `tokens[1]`.
 */
const KUBECTL_GLOBAL_VALUE_FLAGS: ReadonlySet<string> = new Set([
  '--namespace', '-n', '--context', '--kubeconfig', '--cluster', '--user',
  '--server', '-s', '--token', '--certificate-authority', '--client-certificate',
  '--client-key', '--request-timeout', '--password', '--as', '--as-group',
  '--tls-server-name',
])

/** Global kubectl flags that take NO value. */
const KUBECTL_GLOBAL_BOOL_FLAGS: ReadonlySet<string> = new Set([
  '--insecure-skip-tls-verify', '--match-server-version', '--warnings-as-errors',
  '--disable-compression', '--alsologtostderr',
])

/**
 * The index of the kubectl VERB token, skipping global flags and their values.
 *
 * `kubectl -n kube-system patch configmap` has its verb at index 3, not 1.
 * Taking `tokens[1]` made every flagged kubectl call fall through to UNKNOWN
 * — including MUTATIONS, which then looked like "unknown" instead of "modify".
 *
 * Returns -1 when no verb can be located (=> the caller keeps the strict path).
 */
function kubectlVerbIndex(tokens: string[]): number {
  let i = 1
  while (i < tokens.length) {
    const t = tokens[i]!
    if (t === '--') return -1
    if (!t.startsWith('-')) return i
    if (t.includes('=')) { i += 1; continue }
    if (KUBECTL_GLOBAL_BOOL_FLAGS.has(t)) { i += 1; continue }
    if (KUBECTL_GLOBAL_VALUE_FLAGS.has(t)) { i += 2; continue }
    // An unknown flag: the next token might be its value, so the verb start
    // cannot be determined => fail closed.
    return -1
  }
  return -1
}

/** kubectl semantic classification (auth can-i / config view are the read sub-forms). */
function kubectlSpecial(tokens: string[], _segment: string): CommandRisk | null {
  const verbIndex = kubectlVerbIndex(tokens)
  if (verbIndex < 0) {
    // The verb cannot be located reliably (unknown global flag) => UNKNOWN.
    return null
  }
  const verb = tokens[verbIndex]
  if (verb === undefined) return 'READ' // bare 'kubectl' prints help
  if (verb === 'auth') {
    const sub = tokens[verbIndex + 1]
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
  // nmcli accepts unique-prefix abbreviations of its object groups
  // (`nmcli dev` == `nmcli device`, `nmcli con` == `nmcli connection`).
  const groupName = group === 'dev' ? 'device' : group === 'con' ? 'connection' : group === 'gen' ? 'general' : group
  if (groupName === 'general' && (sub === 'status' || sub === 'permissions' || sub === 'hostname')) return 'READ'
  if ((groupName === 'device' || groupName === 'connection') && (sub === 'show' || sub === 'status')) return 'READ'
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

// ---------------- exec wrapper: kubectl exec / docker exec ----------------

/**
 * A shell token that keeps BOTH the raw text (quotes included) and the
 * unquoted value. The raw text is needed to rebuild an inner command without
 * losing its inner quoting (e.g. `sh -c 'cat x | grep "y"'`).
 */
interface ShellToken {
  raw: string
  value: string
}

/**
 * Quote-aware tokenizer that keeps each token's raw text.
 * Returns null when quotes are unbalanced (=> not analyzable).
 */
function rawTokens(command: string): ShellToken[] | null {
  const out: ShellToken[] = []
  let i = 0
  while (i < command.length) {
    while (i < command.length && /\s/.test(command[i]!)) i++
    if (i >= command.length) break
    const start = i
    let raw = ''
    let value = ''
    while (i < command.length && !/\s/.test(command[i]!)) {
      const ch = command[i]!
      if (ch === '\\' && i + 1 < command.length) {
        raw += ch + command[i + 1]!
        value += command[i + 1]!
        i += 2
        continue
      }
      if (ch === "'" || ch === '"') {
        const quote = ch
        raw += ch
        i++
        while (i < command.length && command[i] !== quote) {
          if (quote === '"' && command[i] === '\\' && i + 1 < command.length) {
            raw += command[i]! + command[i + 1]!
            value += command[i + 1]!
            i += 2
            continue
          }
          raw += command[i]!
          value += command[i]!
          i++
        }
        if (i >= command.length) return null // unbalanced quote
        raw += quote
        i++
        continue
      }
      raw += ch
      value += ch
      i++
    }
    if (i > start) out.push({ raw, value })
  }
  return out
}

/** Strip one pair of enclosing quotes (the inner content keeps its quotes). */
function stripOuterQuotes(text: string): string {
  const t = text.trim()
  if (t.length >= 2) {
    const first = t[0]!
    const last = t[t.length - 1]!
    if ((first === "'" && last === "'") || (first === '"' && last === '"')) return t.slice(1, -1)
  }
  return t
}

/** docker exec options that consume the following token as their value. */
const DOCKER_EXEC_VALUE_OPTIONS = new Set(['-u', '--user', '-e', '--env', '-w', '--workdir', '--env-file'])

/**
 * Extract the INNER command of an exec wrapper.
 *
 *   kubectl exec [-flags] POD -- CMD [args...]      -> CMD [args...]
 *   docker  exec [-flags] CONTAINER CMD [args...]   -> CMD [args...]
 *
 * Returns null when the segment is not an exec wrapper, or when the inner
 * command cannot be determined unambiguously (fail-closed => the caller keeps
 * the ordinary, stricter classification).
 */
function extractExecInner(segment: string): string | null {
  const tokens = rawTokens(segment)
  if (tokens === null || tokens.length < 3) return null
  const program = tokens[0]!.value
  const verb = tokens[1]!.value
  if (verb !== 'exec') return null

  if (program === 'kubectl') {
    let sep = -1
    for (let i = 2; i < tokens.length; i++) {
      if (tokens[i]!.value === '--') {
        sep = i
        break
      }
    }
    if (sep < 0) return null // no '--' => ambiguous, keep the strict path
    const rest = tokens.slice(sep + 1)
    if (rest.length === 0) return null
    return rest.map((t) => t.raw).join(' ')
  }

  if (program === 'docker') {
    let i = 2
    while (i < tokens.length) {
      const t = tokens[i]!
      if (!t.value.startsWith('-')) break
      const name = t.value.split('=')[0]!
      if (!t.value.includes('=') && DOCKER_EXEC_VALUE_OPTIONS.has(name)) i++
      i++
    }
    if (i >= tokens.length) return null // no container name
    i++ // skip the container name
    const rest = tokens.slice(i)
    if (rest.length === 0) return null
    return rest.map((t) => t.raw).join(' ')
  }

  return null
}

/** FD-only redirections that may trail a `sh -c '<script>'` argument. */
const FD_REDIRECTION_ONLY = /^\d{0,2}(?:>>?|>&|&>)\d{0,2}$/

/**
 * `sh -c '<script>'` / `bash -lc '<script>'` -> the script body.
 * Returns null when the form is a shell invocation that cannot be unwrapped
 * safely (missing script, extra arguments, unbalanced quotes).
 */
function unwrapShellC(inner: string): string | null {
  const tokens = rawTokens(inner)
  if (tokens === null || tokens.length < 2) return null
  const shell = tokens[0]!.value
  if (!['sh', 'bash', 'dash', 'ksh', 'zsh'].includes(shell)) return null
  const flag = tokens[1]!.value
  if (!/^-[a-z]*c$/.test(flag)) return null
  if (tokens.length < 3) return null
  const script = tokens[2]!
  if (script.raw.length === 0) return null
  // trailing arguments after the script: only FD redirections are ignorable
  for (let i = 3; i < tokens.length; i++) {
    if (!FD_REDIRECTION_ONLY.test(tokens[i]!.raw)) return null
  }
  return stripOuterQuotes(script.raw)
}

/**
 * Risk of the inner command of an exec wrapper.
 * The inner command goes through the SAME full pipeline (danger / opaque /
 * mutation / per-segment), so an inner write stays MODIFY and an inner
 * unanalyzable command stays UNKNOWN.
 */
function classifyExecInner(inner: string): CommandRisk {
  const unwrapped = unwrapShellC(inner)
  const effective = unwrapped === null ? inner : unwrapped
  if (effective.trim().length === 0) return 'UNKNOWN'
  return classifyInnerFully(effective)
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

/**
 * Trusted ABSOLUTE paths for known binaries that live outside the system
 * directories (SAP Control Center, bundled JDKs, the PHP/MySQL stack of the
 * panel-based installs, ...).
 *
 * Double condition, deliberately:
 *   1. the BASENAME must be a known tool (an unknown basename is never
 *      accepted, no matter where it lives), and
 *   2. the path must sit under one of the allowed directory prefixes.
 *
 * A bare basename alone is NOT enough (an operator could point PATH at an
 * arbitrary directory), and a trusted directory alone is NOT enough either
 * (the directory may contain other executables).
 */
const TRUSTED_ABSOLUTE_ALIASES: Record<string, readonly string[]> = {
  sapcontrol: ['/usr/sap/hostctrl/exe'],
  saphostexec: ['/usr/sap/hostctrl/exe'],
  saposcol: ['/usr/sap/hostctrl/exe'],
  hdbnsutil: ['/usr/sap'],
  hdbuserstore: ['/usr/sap'],
  hdbbackup: ['/usr/sap'],
  hdbcompress: ['/usr/sap'],
  hdbconsistencycheck: ['/usr/sap'],
  jstat: ['/usr/local/java', '/usr/lib/jvm', '/opt/java'],
  jinfo: ['/usr/local/java', '/usr/lib/jvm', '/opt/java'],
  javap: ['/usr/local/java', '/usr/lib/jvm', '/opt/java'],
  nginx: ['/www/server/nginx/sbin', '/usr/local/nginx/sbin'],
  php: ['/www/server/php'],
  'php-fpm': ['/www/server/php'],
  mysqld: ['/www/server/mysql/bin'],
  jq: ['/usr/local/bin', '/usr/bin'],
}

/** True when `normalized` sits directly under one of the `prefix` directories. */
function isUnderTrustedPrefix(normalized: string, prefixes: readonly string[]): boolean {
  for (const prefix of prefixes) {
    if (normalized.startsWith(prefix + '/')) return true
  }
  return false
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
  if (isUnderTrustedPrefix(normalized, TRUSTED_ABSOLUTE_ALIASES[base] ?? [])) return base
  return TRUSTED_COMMAND_ALIASES[base]?.includes(normalized) === true ? base : undefined
}

/**
 * The command of a `su [-] [user] -c '<command>'` invocation.
 *
 * Returns null when the segment is not such an invocation (a bare `su`, or a
 * form that cannot be parsed unambiguously) — the caller then keeps the
 * fail-closed verdict.
 */
function extractSuCommand(segment: string): string | null {
  const tokens = rawTokens(segment)
  if (tokens === null || tokens.length < 3) return null
  if (tokens[0]!.value !== 'su') return null
  let i = 1
  // optional flags (`-`, `-l`) and the optional user name
  while (i < tokens.length) {
    const v = tokens[i]!.value
    if (v === '-c' || v === '--command') break
    if (v.startsWith('-')) { i++; continue }
    // A bare word here is the user name.
    i++
  }
  if (i >= tokens.length) return null
  const flag = tokens[i]!.value
  if (flag !== '-c' && flag !== '--command') return null
  const cmd = tokens[i + 1]
  if (cmd === undefined) return null
  return stripOuterQuotes(cmd.raw)
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
      // An escaped character is LITERAL data (`\c` is the letter c), so the
      // character itself is kept and only the backslash disappears. Masking
      // it away hid the escaped command name (`\cp` looks like nothing).
      out += command[i + 1]!
      i += 2
      continue
    }
    out += ch
    i++
  }
  return out
}

/**
 * Split on ; && || | at quote/escape boundaries (quoted pipes stay intact).
 *
 * A command substitution `$( ... )` is a NESTED command list: the `;` and `|`
 * inside it belong to the inner command, not to the outer one. Splitting them
 * apart turned `SS=$(grep -E ... file | grep -c x)` into two broken halves.
 * So the substitution body is kept intact and split separately.
 */
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
    // A command substitution: copy it verbatim (with its nested parens) so
    // that the inner `;`/`|` are not treated as outer separators.
    if (ch === '$' && command[i + 1] === '(') {
      let depth = 1
      let j = i + 2
      while (j < command.length && depth > 0) {
        if (command[j] === '(') depth++
        else if (command[j] === ')') depth--
        j++
      }
      current += command.slice(i, Math.min(j, command.length))
      i = j
      continue
    }
    if (ch === '`' && command[i + 1] !== undefined) {
      const end = command.indexOf('`', i + 1)
      if (end >= 0) {
        current += command.slice(i, end + 1)
        i = end + 1
        continue
      }
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

// ---------------- shell control structure ----------------

/**
 * Shell keywords that introduce an EXECUTED command list. The keyword itself
 * runs nothing, the payload does — the payload is classified recursively.
 *
 * `if`/`while`/`until`/`elif` are here too, and that is deliberate: their
 * payload is a CONDITION, but a condition can still be a command
 * (`if shutdown -h now; then ... fi`). Skipping the condition would hide the
 * destructive verb, so the payload is classified instead.
 */
const SHELL_COMMAND_PREFIX: ReadonlySet<string> = new Set(['do', 'then', 'else', 'elif', 'if', 'while', 'until'])

/**
 * Shell keywords that introduce a WORD LIST / expression. Nothing is executed
 * by the keyword itself; a `$(...)` inside such a list was already rejected by
 * the opaque-syntax scan, so the list is inert.
 */
const SHELL_LIST_PREFIX: ReadonlySet<string> = new Set(['for', 'select'])

/** Shell keywords with no payload at all. */
const SHELL_PURE_PREFIX: ReadonlySet<string> = new Set(['done', 'fi', 'esac', 'in'])

/**
 * A single shell word (no unquoted whitespace) — the value of a pure
 * assignment. `$( ... )` counts as one word even with spaces inside it.
 */
const SHELL_ASSIGN_VALUE = /^(?:"[^"]*"|'[^']*'|`[^`]*`|\$\([\s\S]*\)|[^\s'"`();&|<>]+)$/

interface ShellStructure {
  /** 'none' = ordinary command, 'pure' = keyword only, 'list' = word list, 'command' = executed payload */
  kind: 'none' | 'pure' | 'list' | 'command'
  rest: string
}

/**
 * Peel shell control-structure keywords off the front of a segment.
 *
 *   do|then|else|elif|if|while|until  -> the payload is an executed command list
 *   for|select                         -> the payload is a word list (runs nothing)
 *   done|fi|esac|in                    -> no payload
 *   NAME=<one word>                    -> a pure assignment (runs nothing)
 *   ( | {                             -> a group opener, the payload follows
 *
 * Why this matters for safety: the dangerous-command scan used to look at the
 * FIRST WORD of a segment only, so `if shutdown -h now; then ... fi` hid the
 * destructive verb behind a keyword and was NOT flagged. Now the keyword is
 * peeled off before the command position is determined, so the destructive
 * verb is found (see `segmentExecutable`).
 */
/**
 * True when the text consists only of redirections (and the words they
 * point at) — i.e. it runs no command at all.
 *
 * `done < /tmp/list`, `fi > /tmp/out` and `2>&1` are redirections, not
 * commands. Treating them as commands made every `while ... done < file`
 * loop UNKNOWN.
 */
function isRedirectionOnly(text: string): boolean {
  const masked = maskQuoted(text)
  const tokens = masked.split(/\s+/).filter((t) => t.length > 0)
  for (const t of tokens) {
    if (/^\d{0,2}(?:>>?|<<?|&>>?)/.test(t)) continue
    if (/^\d{0,2}$/.test(t)) continue
    if (t === '&') continue
    // The target of a redirection is a path, not a command.
    if (/^[/~.][^\s;|&<>]*$/.test(t)) continue
    return false
  }
  return tokens.length > 0
}

function stripShellStructure(segment: string): ShellStructure {
  let s = segment.trim()
  for (;;) {
    if (s.length === 0) return { kind: 'pure', rest: '' }
    // Group openers are glued to the payload: `(docker ps ...`, `{ ls; }`.
    const opener = s[0]
    if (opener === '(' || opener === '{') {
      s = s.slice(1).trim()
      if (s.length === 0) return { kind: 'pure', rest: '' }
      continue
    }
    const word = s.split(/\s+/)[0]!
    if (SHELL_PURE_PREFIX.has(word)) {
      const rest = s.slice(word.length).trim()
      if (rest.length === 0) return { kind: 'pure', rest: '' }
      // `done < file` / `fi > file`: the keyword is still pure, only a
      // REDIRECTION follows it. A redirection is not a command, so the
      // segment stays a pure keyword.
      if (isRedirectionOnly(rest)) return { kind: 'pure', rest: '' }
      s = rest
      continue
    }
    if (SHELL_COMMAND_PREFIX.has(word)) {
      const rest = s.slice(word.length).trim()
      if (rest.length === 0) return { kind: 'pure', rest: '' }
      return { kind: 'command', rest }
    }
    if (SHELL_LIST_PREFIX.has(word)) return { kind: 'list', rest: '' }
    break
  }
  const assign = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]+)$/.exec(s)
  if (assign !== null && SHELL_ASSIGN_VALUE.test(assign[2]!.trim())) return { kind: 'list', rest: '' }
  return { kind: 'none', rest: s }
}

// ---------------- wrapper stripping ----------------

const WRAPPER_TOKENS = new Set(['env', 'timeout', 'nice', 'time'])

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

/**
 * True when every `>` in the awk program is a COMPARISON operator.
 *
 * In awk, `>` means "greater than" inside an expression
 * (`if(index($0,"x")>0)`, `if(b>15)b=16`) and means "redirect to file" only in
 * a print/printf statement (`print > "f"`).
 *
 * A comparison has an operand on BOTH sides of the operator; a redirect has
 * the print statement before it and a bare filename after it. So a `>` is a
 * comparison when the characters around it both end/start an operand.
 *
 * Anything that does not fit that shape (e.g. `print > f`) makes the function
 * return false, and the caller then keeps the honest UNKNOWN verdict.
 */
function awkComparisonsOnly(segment: string): boolean {
  const masked = maskQuoted(segment)
  for (let i = 0; i < masked.length; i++) {
    const ch = masked[i]!
    if (ch !== '>') continue
    if (masked[i + 1] === '=') continue // >= is always a comparison
    const prev = masked[i - 1] ?? ''
    const next = masked[i + 1] ?? ''
    const prevEndsOperand = /[A-Za-z0-9_$)"'\]}]/.test(prev)
    const nextStartsOperand = /[A-Za-z0-9_$"'(\[{.]/.test(next)
    if (prevEndsOperand && nextStartsOperand) continue
    return false
  }
  return true
}

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
  // V0.5.9: verb-aware rules for the DB / middleware probes that used to fall
  // through to UNKNOWN (they are extremely common on SAP and Oracle estates).
  // Every one of them is fail-closed: an unrecognised verb returns null, which
  // keeps the UNKNOWN verdict rather than guessing.
  if (command === 'sapcontrol') {
    const at = args.findIndex((t) => t === '-function' || t === '--function')
    const fn = at >= 0 ? (args[at + 1] ?? '').toLowerCase() : ''
    if (fn.length === 0) return null
    if (['getprocesslist','getsysteminstancelist','getversioninfo','getalerttree','getqueuestatistic','getprocessparameter','parametervalue','getinstanceproperties','getstartprofiles','getenvironment','enqgetstatistic','enqgetstatistics','getqueuestatistics'].includes(fn)) {
      return semanticRead('sap.sapcontrol.read.' + fn, 'sapcontrol -function ' + fn + ' only reports instance state')
    }
    if (['start','stop','restart','instancesstart','instancesstop','instancestart','instancestop','startinstance','stopinstance','restartinstance','startsystem','stopsystem','setprocessparameter','softshutdown'].includes(fn)) {
      return verdict('MODIFY', 'sap.sapcontrol.mutate.' + fn, 'sapcontrol -function ' + fn + ' changes SAP instance state')
    }
    return null
  }
  if (command === 'hdb' || command === 'HDB') {
    const verb = lower.find((t) => !t.startsWith('-'))
    if (verb === undefined) return null
    if (['info','version','status','proc','getsysteminfo'].includes(verb)) return semanticRead('sap.hdb.' + verb, 'HDB ' + verb + ' only reports HANA instance state')
    if (['start','stop','restart','kill','recover'].includes(verb)) return verdict('MODIFY', 'sap.hdb.mutate.' + verb, 'HDB ' + verb + ' changes the HANA instance')
    return null
  }
  if (command === 'lsnrctl') {
    const verb = lower.find((t) => !t.startsWith('-'))
    // A bare `lsnrctl` opens an interactive shell that can do anything.
    if (verb === undefined) return null
    if (['status','services','version','show','help'].includes(verb)) return semanticRead('oracle.lsnrctl.' + verb, 'lsnrctl ' + verb + ' only queries listener state')
    if (['start','stop','reload','restart','set','save_config','trace'].includes(verb)) return verdict('MODIFY', 'oracle.lsnrctl.mutate.' + verb, 'lsnrctl ' + verb + ' changes listener state or configuration')
    return null
  }
  if (command === 'showmount') {
    const known = ['-e','--exports','-a','--all','-d','--directories','-h','--help','-v','--version','--no-headers']
    if (args.some((t) => t.startsWith('-') && !known.includes(t))) return null
    return semanticRead('nfs.showmount.read', 'showmount only queries the NFS export table')
  }
  if (command === 'jstack') {
    // -F force-attaches and can suspend the JVM; -m needs a debugger attach.
    if (args.some((t) => t === '-F')) return verdict('MODIFY', 'jvm.jstack.force', 'jstack -F force-attaches to a JVM and can pause the target')
    if (args.some((t) => t === '-m')) return verdict('UNKNOWN', 'jvm.jstack.mixed', 'jstack -m needs a debugger attach that can suspend the target', 'LOW')
    if (args.some((t) => t.startsWith('-') && !['-l','-h','-help'].includes(t))) return null
    return semanticRead('jvm.jstack.thread-dump', 'jstack attaches read-only and dumps thread stacks')
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
    // A bare `>` is a COMPARISON in awk (`if(index($0,"x")>0)`), not a
    // redirect. A redirect is `print > file` — the `>` follows a print
    // statement. So the ambiguous case is narrowed to a `>` that appears
    // OUTSIDE of a comparison context, i.e. not between two operands.
    if (/[>]{1,2}/.test(segment) && !awkComparisonsOnly(segment)) return verdict('UNKNOWN', 'awk.redirect-ambiguous', 'awk output redirection cannot be excluded', 'LOW')
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
    // The verb may sit behind global flags (`kubectl -n ns get pods`), so the
    // verb index is resolved the same way as in kubectlSpecial.
    const vi = kubectlVerbIndex(tokens)
    const verb = vi >= 0 ? lower[vi - 1] : undefined
    const sub = vi >= 0 ? lower[vi] : undefined
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
  if (command === 'bash' || command === 'sh' || command === 'dash' || command === 'ksh' || command === 'zsh') {
    // `bash -n script.sh` = SYNTAX CHECK ONLY, the script is never executed.
    // `bash -c '...'` EXECUTES the string and stays in the opaque bucket.
    // `bash script.sh` EXECUTES the script => not a reader.
    if (lower.includes('-n') && !lower.some((t) => /^-[a-z]*c$/.test(t))) {
      return semanticRead('shell.syntax-check', command + ' -n only parses the script, it does not run it')
    }
    return null
  }
  if (command === 'openssl') {
    // `openssl x509 -in cert.pem -noout -subject -dates` only READS the
    // certificate. The writing forms (`-out`, `-outform` to a file) must stay
    // MODIFY, so the presence of an output flag decides.
    const sub = lower.find((t) => !t.startsWith('-'))
    if (sub === 'x509' || sub === 'req' || sub === 'crl' || sub === 'rsa' || sub === 'ec' || sub === 'pkey' || sub === 'dhparam' || sub === 'asn1parse' || sub === 'dgst' || sub === 'passwd') {
      const writes = lower.some((t) => t === '-out' || t === '-outfile' || t === '-keyout' || t === '-signkey' || t === '-outform')
      if (writes) return verdict('MODIFY', 'openssl.write', 'openssl ' + sub + ' writes a key or certificate file')
      return semanticRead('openssl.read', 'openssl ' + sub + ' only reads and prints')
    }
    return null
  }
  if (command === 'crontab') {
    // C-3: parse the FORM, do not match the word.
    //   crontab -l            -> list the current user's crontab   (READ)
    //   crontab -u USER -l    -> list another user's crontab        (READ)
    //   crontab -e / -r       -> edit / remove the crontab           (MODIFY)
    //   bare crontab          -> install a crontab from stdin       (MODIFY)
    // The word `crontab` alone is therefore NOT a modifier verb: it is
    // handled here and removed from the generic modifier-verb scan.
    const listed = lower.some((t) => t === '-l' || t === '--list')
    const edited = lower.some((t) => t === '-e' || t === '--edit' || t === '-r' || t === '--remove')
    if (listed && !edited) return semanticRead('cron.list', 'crontab -l only lists the crontab')
    if (edited) return verdict('MODIFY', 'cron.mutate', 'crontab -e/-r changes the crontab')
    return verdict('MODIFY', 'cron.mutate.install', 'bare crontab installs a crontab from stdin')
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
  // ---- V0.7.0 (C-1): read-only tools that the audit corpus kept hitting as
  // UNKNOWN. Every rule below is fail-closed: an unrecognised verb returns
  // null, which keeps the UNKNOWN verdict instead of guessing READ.
  if (command === 'ipmitool') {
    // `ipmitool <cmd> <sub>`: only the query forms are read-only. The write
    // forms (chassis power off, sel delete, mc reset, raw, flash, ...) change
    // the BMC and MUST NOT be classified as a reader.
    const readSubs = new Set(['elist', 'list', 'info', 'status', 'print', 'get', 'sensor', 'selinfo'])
    const writeCmds = new Set(['power', 'poweroff', 'poweron', 'powercycle', 'reset', 'off', 'on', 'cycle', 'delete', 'set', 'raw', 'flash', 'upgrade', 'bridge', 'send', 'inject'])
    const cmd = lower.find((t) => !t.startsWith('-'))
    const sub = lower.filter((t) => !t.startsWith('-'))[1]
    if (cmd === undefined) return null
    if (writeCmds.has(cmd)) return verdict('MODIFY', 'ipmitool.mutate.' + cmd, 'ipmitool ' + cmd + ' changes the BMC state')
    if (sub !== undefined && readSubs.has(sub)) return semanticRead('ipmitool.read.' + cmd + '.' + sub, 'ipmitool ' + cmd + ' ' + sub + ' only queries the BMC')
    return null
  }
  if (command === 'crm_mon') {
    // Pacemaker/Corosync monitor: query-only by construction.
    return semanticRead('pacemaker.crm_mon', 'crm_mon only reports cluster state')
  }
  if (command === 'crm') {
    const sub = lower.find((t) => !t.startsWith('-'))
    const sub2 = lower.filter((t) => !t.startsWith('-'))[1]
    if (sub === 'configure' && sub2 === 'show') return semanticRead('pacemaker.crm.configure-show', 'crm configure show only reads the configuration')
    if (sub !== undefined && ['status', 'node', 'resource', 'cluster', 'options', 'history', 'shadow', 'health', 'do', 'pending', 'stack', 'verify', 'simulate'].includes(sub)) {
      return semanticRead('pacemaker.crm.' + sub, 'crm ' + sub + ' only reports cluster state')
    }
    return null
  }
  if (command === 'systemd-tmpfiles') {
    // --version is a query; --clean DELETES files (must never be READ).
    if (lower.includes('--version') || lower.includes('-v')) return semanticRead('systemd.tmpfiles.version', 'systemd-tmpfiles --version only prints the version')
    if (lower.some((t) => t === '--clean' || t === '--create' || t === '--remove' || t === '--boot')) {
      return verdict('MODIFY', 'systemd.tmpfiles.mutate', 'systemd-tmpfiles --clean/--create/--remove writes or deletes files under /tmp and /var')
    }
    return null
  }
  if (command === 'ufw') {
    const sub = lower.find((t) => !t.startsWith('-'))
    if (sub === 'status' || sub === 'show' || sub === 'version' || sub === 'list') return semanticRead('ufw.' + sub, 'ufw ' + sub + ' only reports the firewall state')
    if (sub !== undefined && ['enable', 'disable', 'allow', 'deny', 'reset', 'reload', 'delete', 'insert', 'append'].includes(sub)) {
      return verdict('MODIFY', 'ufw.mutate.' + sub, 'ufw ' + sub + ' changes the firewall rules')
    }
    return null
  }
  if (command === 'auditctl') {
    if (lower.some((t) => t === '-l' || t === '--list' || t === '-s' || t === '--status' || t === '-st')) {
      return semanticRead('auditctl.read', 'auditctl list/status only reads the audit rules')
    }
    if (lower.some((t) => t === '-D' || t === '--delete-all' || t === '-d' || t === '--delete' || t === '-b' || t === '-R' || t === '-W')) {
      return verdict('MODIFY', 'auditctl.mutate', 'auditctl delete/rule changes the audit configuration')
    }
    return null
  }
  if (command === 'mdadm') {
    const verb = lower.find((t) => t.startsWith('--'))
    if (verb !== undefined && ['--detail', '--examine', '--scan', '--query', '--brief'].includes(verb)) {
      return semanticRead('mdadm.read' + verb, 'mdadm ' + verb + ' only reports array state')
    }
    if (verb !== undefined && ['--create', '--add', '--grow', '--stop', '--assemble', '--remove', '--update', '--zero-superblock', '--examine'].includes(verb)) {
      return verdict('MODIFY', 'mdadm.mutate' + verb, 'mdadm ' + verb + ' changes the RAID array')
    }
    return null
  }
  if (command === 'exportfs') {
    if (lower.includes('-v') || lower.includes('--verbose')) return semanticRead('nfs.exportfs.read', 'exportfs -v only lists the export table')
    return verdict('MODIFY', 'nfs.exportfs.mutate', 'exportfs without -v modifies the NFS export table')
  }
  if (command === 'php' || command === 'php-fpm') {
    // Only the display forms are read-only. `php -r`, `php script.php` and a
    // bare `php-fpm` EXECUTE code / start the service.
    const flags = lower.filter((t) => t.startsWith('-'))
    if (command === 'php') {
      if (flags.some((t) => ['-r', '-f', '-d'].includes(t))) return verdict('MODIFY', 'php.execute', 'php -r/-f executes arbitrary code')
      if (flags.some((t) => ['-v', '--version', '-m', '--modules', '-i', '--info', '-h', '--help'].includes(t)) && args.every((t) => t.startsWith('-'))) {
        return semanticRead('php.display', 'php display form only prints version/modules')
      }
      if (args.some((t) => !t.startsWith('-'))) return verdict('MODIFY', 'php.execute', 'php running a script executes arbitrary code')
      return null
    }
    if (flags.some((t) => ['-v', '--version', '-t', '-tt'].includes(t))) return semanticRead('php-fpm.display', 'php-fpm display/test form only reports the configuration')
    return verdict('MODIFY', 'php-fpm.start', 'php-fpm starts the FastCGI process pool')
  }
  if (command === 'mysqld') {
    if (lower.includes('--version') || lower.includes('-V')) return semanticRead('mysql.mysqld.version', 'mysqld --version only prints the version')
    return verdict('MODIFY', 'mysql.mysqld.start', 'mysqld starts the database server')
  }
  if (command === 'stty') {
    // `stty` with no argument prints the terminal settings (read-only).
    // `stty cols 300` SETS a terminal attribute: that is a session-level
    // change, so it stays MODIFY.
    if (args.length === 0) return semanticRead('term.stty.show', 'stty without arguments only prints the terminal settings')
    return verdict('MODIFY', 'term.stty.set', 'stty with arguments changes the terminal settings')
  }
  if (command === 'hdbuserstore') {
    // `hdbuserstore list` prints the user store — read-only.
    // `create` / `delete` / `alter` / `modify` change the user store.
    const verb = lower.find((t) => !t.startsWith('-'))
    if (verb === 'list') return semanticRead('sap.hdbuserstore.list', 'hdbuserstore list only reports the user store')
    if (verb !== undefined && ['create', 'delete', 'alter', 'modify', 'set', 'reset', 'disable', 'enable', 'import', 'export'].includes(verb)) {
      return verdict('MODIFY', 'sap.hdbuserstore.mutate.' + verb, 'hdbuserstore ' + verb + ' changes the HANA user store')
    }
    return null
  }
  if (command === 'hdbnsutil') {
    // HANA admin tool: only the read-only sub-commands are recognised.
    if (lower.includes('-sr_state') || lower.includes('--version') || lower.includes('-h')) {
      return semanticRead('sap.hdbnsutil.read', 'hdbnsutil ' + (lower.find((t) => t.startsWith('-')) ?? '') + ' only reports the instance state')
    }
    return null
  }
  if (command === 'saphostexec') {
    if (lower.includes('-status')) return semanticRead('sap.saphostexec.status', 'saphostexec -status only reports the instance status')
    if (lower.some((t) => t === '-start' || t === '-stop' || t === '-restart' || t === '-kill' || t === '-dummy')) {
      return verdict('MODIFY', 'sap.saphostexec.mutate', 'saphostexec start/stop changes the SAP instance')
    }
    return null
  }
  if (command === 'saposcol') {
    if (lower.includes('-s') || lower.includes('-h')) return semanticRead('sap.saposcol.read', 'saposcol -s only lists the collectors')
    return verdict('MODIFY', 'sap.saposcol.mutate', 'saposcol -r/-l rewrites the collector configuration files')
  }
  if (command === 'command') {
    // The `command` builtin: -v/-V only query the PATH.
    if (lower.includes('-v') || lower.includes('-V') || lower.includes('--version')) return semanticRead('shell.command.lookup', 'command -v only looks up the PATH')
    if (args.length === 0) return semanticRead('shell.command.list', 'bare command only lists the available builtins')
    return null
  }
  if (command === 'nohup') {
    // `nohup <cmd>` runs <cmd> in the background: the inner command decides.
    const inner = args.join(' ')
    if (inner.trim().length === 0) return null
    const innerRisk = classifyInnerFully(inner)
    if (innerRisk === 'READ') return semanticRead('nohup.inner.read', 'nohup runs a read-only inner command')
    if (innerRisk === 'MODIFY') return verdict('MODIFY', 'nohup.inner.modify', 'nohup runs an inner command that changes state')
    if (innerRisk === 'DANGEROUS') return verdict('DANGEROUS', 'nohup.inner.dangerous', 'nohup runs a host-destructive inner command')
    return null
  }
  if (command === 'shuf' || command === 'jstat' || command === 'jinfo' || command === 'javap' || command === 'jq' || command === 'ipcs' || command === 'getenforce' || command === 'sleep') {
    // Query-only tools (no write form at all).
    return semanticRead('tool.readonly.' + command, command + ' has no state-changing form')
  }
  return null
}

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
  // ---- V0.7.0 (C-1): shell control structure normalization ------------
  // `for x in a b`, `do <cmd>`, `then <cmd>`, `done`, `fi` are SHELL SYNTAX,
  // not commands. Without this step the loop header was treated as an
  // unknown command (UNKNOWN) and, worse, the destructive verb of
  // `if shutdown -h now; then ... fi` hid behind the keyword.
  const shell = stripShellStructure(segment)
  if (shell.kind === 'pure') {
    return classificationOf('READ', 'shell keyword only, runs no command', 'shell.keyword', segment)
  }
  if (shell.kind === 'list') {
    return classificationOf('READ', 'shell word list, runs no command', 'shell.wordlist', segment)
  }
  if (shell.kind === 'command') {
    const inner = classifySegment(shell.rest)
    return { ...inner, command: segment }
  }
  // A group opener (`(docker ps ...`) was peeled off by stripShellStructure.
  // The payload after it is the real command, so that is what gets
  // classified — the original text is kept for the audit trail.
  const body = shell.rest.trim().length > 0 ? shell.rest : segment

  const token = firstToken(body)
  if (token === 'sudo') {
    const rest = body.replace(/^sudo\b\s*/u, '')
    if (rest.trim().length === 0) return classificationOf('UNKNOWN', 'bare sudo', 'sudo.bare', segment)
    // The inner command goes through the FULL pipeline (danger scan
    // included): `sudo rm -rf /` must be DANGEROUS, not merely "some
    // segment".
    const inner = classifyInnerFully(rest)
    if (inner === 'READ') {
      return classificationOf('PRIVILEGED_READ', 'privileged read (sudo): the inner command is read-only', 'sudo.privileged-read', segment)
    }
    // sudo never downgrades: MODIFY/DANGEROUS/UNKNOWN stay as classified
    return classificationOf(inner, 'inner command of sudo is ' + inner.toLowerCase(), 'sudo.inner.' + inner.toLowerCase(), segment)
  }
  if (token === 'su') {
    // `su [-] [user] -c '<command>'` switches to another user and runs the
    // command there. The inner command decides whether it reads or writes,
    // but the result is a PRIVILEGED read: it runs as somebody else.
    const inner = extractSuCommand(body)
    if (inner === null) {
      // A bare `su` opens an interactive shell: it can do anything.
      return classificationOf('UNKNOWN', 'bare su opens an interactive shell as another user', 'su.interactive', segment, 'LOW')
    }
    // The inner command goes through the FULL pipeline (danger scan
    // included): `su - root -c "rm -rf /"` must be DANGEROUS.
    const innerRisk = classifyInnerFully(inner)
    if (innerRisk === 'READ') {
      return classificationOf('PRIVILEGED_READ', 'privileged read (su): the inner command is read-only', 'su.privileged-read', segment)
    }
    return classificationOf(innerRisk, 'inner command of su is ' + innerRisk.toLowerCase(), 'su.inner.' + innerRisk.toLowerCase(), segment)
  }
  if (isWrapperToken(token)) {
    const inner = stripWrapper(body, token!)
    if (inner.trim().length === 0) return classificationOf('READ', 'bare ' + token + ' only lists its environment', token + '.bare', segment)
    const innerClass = classifySegment(inner)
    return { ...innerClass, command: segment }
  }
  // Exec wrappers (kubectl exec / docker exec): the semantics are decided by
  // the INNER command, which goes through the SAME full pipeline. An inner
  // read stays READ, an inner write stays MODIFY, an unanalyzable inner stays
  // UNKNOWN (fail-closed).
  const execInner = extractExecInner(body)
  if (execInner !== null) {
    const innerRisk = classifyExecInner(execInner)
    const ruleId = 'exec.inner.' + innerRisk.toLowerCase()
    if (innerRisk === 'READ') return classificationOf('READ', 'exec inner command is read-only', ruleId, segment)
    if (innerRisk === 'PRIVILEGED_READ') return classificationOf('PRIVILEGED_READ', 'exec inner command is a privileged read', ruleId, segment)
    if (innerRisk === 'MODIFY') return classificationOf('MODIFY', 'exec inner command modifies state', ruleId, segment)
    if (innerRisk === 'DANGEROUS') return classificationOf('DANGEROUS', 'exec inner command is host-destructive', ruleId, segment)
    return classificationOf('UNKNOWN', 'exec inner command cannot be verified as read-only', ruleId, segment, 'LOW')
  }
  return classifyPlainSegment(body, segment)
}

/**
 * The executable of a segment (after skipping env assignments and the
 * env/timeout/nice/sudo wrappers). Returns null when there is no executable.
 *
 * V0.7.0 (C-1): shell control keywords are peeled off FIRST, so
 * `if shutdown -h now; then ... fi` reports `shutdown` as the command
 * position — otherwise the destructive verb hid behind the keyword and the
 * dangerous-command scan missed it.
 */
function segmentExecutable(segment: string): string | null {
  const shell = stripShellStructure(segment)
  if (shell.kind === 'pure' || shell.kind === 'list') return null
  const tokens = rawTokens(shell.kind === 'command' ? shell.rest : segment)
  if (tokens === null) return null
  let i = 0
  while (i < tokens.length) {
    const v = tokens[i]!.value
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(v)) { i++; continue }
    if (WRAPPER_TOKENS.has(v)) {
      i++
      const next = tokens[i]?.value
      if (next !== undefined && /^\d+(?:\.\d+)?$/.test(next)) i++
      continue
    }
    if (v === 'sudo') { i++; continue }
    break
  }
  const raw = tokens[i]?.value
  if (raw === undefined || raw.length === 0) return null
  return raw.split('/').pop()!.toLowerCase()
}

/**
 * Detect a destructive command anywhere in the given text.
 *
 * Three independent angles, all of them needed:
 *  1. compound destructive patterns (`rm -rf /`, `chmod -R 777 /`, ...) — these
 *     are matched on the RAW text, because the payload may be a quoted
 *     argument of a wrapper (`bash -c "rm -rf /"`);
 *  2. destructive VERBS (`shutdown`, `reboot`, `poweroff`, `halt`) — matched
 *     only in the COMMAND POSITION (`shutdown -h now`) or as the verb of a
 *     destructive host tool (`systemctl reboot`). A literal argument
 *     (`grep -i 'shutdown' /var/log/messages`) is NOT destructive;
 *  3. destructive executables (`dd`, `mkfs.*`, `wipefs`, ...) — matched only in
 *     the COMMAND POSITION of a segment.
 *
 * Wrappers (`sh -c`, `bash -c`), exec wrappers (`kubectl exec`, `docker exec`)
 * and command substitutions (`$(...)`, backticks) are recursed into: their
 * content is EXECUTED, so a destructive command hidden there stays dangerous.
 */
function detectDangerous(command: string, depth = 0): { ruleId: string; reason: string } | null {
  if (depth > 3) return null

  for (const pattern of DANGEROUS_COMMANDS) {
    if (pattern.test(command)) return { ruleId: 'dangerous.pattern', reason: DANGEROUS_REASON(pattern.source) }
  }

  for (const segment of splitSegments(command)) {
    const tokens = rawTokens(segment)
    if (tokens === null) continue
    const exe = segmentExecutable(segment)
    if (exe === null) continue
    if (DANGEROUS_COMMAND_WORDS.includes(exe)) {
      return { ruleId: 'dangerous.command', reason: 'destructive command in command position: ' + exe }
    }
    if (DANGEROUS_EXECUTABLES.has(exe) || DANGEROUS_EXECUTABLE_PREFIXES.some((p) => exe.startsWith(p))) {
      return { ruleId: 'dangerous.command', reason: 'destructive command in command position: ' + exe }
    }
    if (DANGEROUS_VERB_HOSTS.has(exe)) {
      for (const t of tokens.slice(1)) {
        const verb = t.value.toLowerCase()
        if (DANGEROUS_COMMAND_WORDS.includes(verb)) {
          return { ruleId: 'dangerous.command', reason: exe + ' ' + verb + ' changes host power state' }
        }
      }
    }
  }

  for (const segment of splitSegments(command)) {
    const shellInner = extractShellCInner(segment)
    if (shellInner !== null) {
      const inner = detectDangerous(stripOuterQuotes(shellInner), depth + 1)
      if (inner !== null) return inner
    }
    const execInner = extractExecInner(segment)
    if (execInner !== null) {
      const inner = detectDangerous(execInner, depth + 1)
      if (inner !== null) return inner
    }
  }

  for (const substitution of extractSubstitutions(command)) {
    const inner = detectDangerous(substitution, depth + 1)
    if (inner !== null) return inner
  }

  return null
}

/**
 * Risk severity order used when several findings are merged.
 *
 * READ < PRIVILEGED_READ < UNKNOWN < MODIFY < DANGEROUS.
 *
 * NOTE: this is the "what does the command DO" order, not the "how
 * restrictive is the gate" order. MODIFY and UNKNOWN are both gated in
 * READ_ONLY and both need approval in AUTO; they differ only in FULL_ACCESS,
 * where MODIFY is allowed and UNKNOWN still prompts. The order therefore
 * answers "is a mutation confirmed", not "which gate is stricter".
 */
const RISK_ORDER: Record<CommandRisk, number> = { READ: 0, PRIVILEGED_READ: 1, UNKNOWN: 2, MODIFY: 3, DANGEROUS: 4 }

/**
 * Bodies of the command substitutions that the shell ACTUALLY EXECUTES.
 *
 * `$(...)` and backticks run a command — their content is a command, not
 * data. Inside single quotes they are literal text and are ignored.
 * `$((...))` is arithmetic and runs nothing.
 *
 * Returns null when a substitution is not balanced (=> not analysable, the
 * caller must fail closed).
 */
function extractActiveSubstitutions(command: string): string[] | null {
  const out: string[] = []
  let quote: "'" | '"' | null = null
  let i = 0
  while (i < command.length) {
    const ch = command[i]!
    if (ch === '\\') {
      i += 2
      continue
    }
    if (quote === "'") {
      if (ch === "'") quote = null
      i++
      continue
    }
    if (ch === "'") {
      quote = "'"
      i++
      continue
    }
    if (ch === '"') {
      quote = quote === '"' ? null : '"'
      i++
      continue
    }
    if (ch === '`') {
      const end = command.indexOf('`', i + 1)
      if (end < 0) return null
      out.push(command.slice(i + 1, end))
      i = end + 1
      continue
    }
    if (ch === '$' && command[i + 1] === '(') {
      // `$((...))` is ARITHMETIC, not a command: it runs nothing.
      if (command[i + 2] === '(') {
        let depth = 0
        let j = i + 1
        while (j < command.length) {
          if (command[j] === '(') depth++
          else if (command[j] === ')') {
            depth--
            if (depth === 0) break
          }
          j++
        }
        if (j >= command.length) return null
        i = j + 1
        continue
      }
      let depth = 1
      let j = i + 2
      while (j < command.length && depth > 0) {
        if (command[j] === '(') depth++
        else if (command[j] === ')') depth--
        j++
      }
      if (depth !== 0) return null // unbalanced => not analysable
      out.push(command.slice(i + 2, j - 1))
      i = j
      continue
    }
    i++
  }
  return out
}

/**
 * The risk contributed by the command substitutions of `text`.
 *
 * Every substitution body goes through the SAME full pipeline, so an inner
 * write stays MODIFY and an inner unanalysable command stays UNKNOWN. The
 * OUTER command can never be more permissive than what it substitutes —
 * that is exactly why `x=$(some-unknown-cli)` must not be a plain READ.
 *
 * Returns null when the text has no active substitution.
 */
function substitutionFloor(text: string, depth: number): { risk: CommandRisk; reason: string } | null {
  const bodies = extractActiveSubstitutions(text)
  if (bodies === null) {
    return { risk: 'UNKNOWN', reason: 'command substitution is not balanced; read-only cannot be confirmed' }
  }
  if (bodies.length === 0) return null
  let worst: CommandRisk = 'READ'
  let reason = 'command substitutions are read-only'
  for (const body of bodies) {
    const risk = classifyInnerFully(body, depth + 1)
    if (RISK_ORDER[risk] > RISK_ORDER[worst]) {
      worst = risk
      reason = 'command substitution body is ' + risk.toLowerCase()
    }
  }
  return { risk: worst, reason }
}

function extractShellCInner(segment: string): string | null {
  const tokens = rawTokens(segment)
  if (tokens === null || tokens.length < 3) return null
  if (!['sh', 'bash', 'dash', 'ksh', 'zsh'].includes(tokens[0]!.value)) return null
  if (!/^-[a-z]*c$/.test(tokens[1]!.value)) return null
  return tokens[2]!.raw
}

/**
 * Bodies of command substitutions (`$(...)` and backticks). Their content is
 * EXECUTED, so a destructive verb inside them is a real destructive command.
 */
function extractSubstitutions(command: string): string[] {
  const out: string[] = []
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === '`') {
      const end = command.indexOf('`', i + 1)
      if (end < 0) break
      out.push(command.slice(i + 1, end))
      i = end
      continue
    }
    if (ch === '$' && command[i + 1] === '(') {
      let depth = 1
      let j = i + 2
      while (j < command.length && depth > 0) {
        if (command[j] === '(') depth++
        else if (command[j] === ')') depth--
        j++
      }
      out.push(command.slice(i + 2, Math.max(i + 2, j - 1)))
      i = j - 1
    }
  }
  return out
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

  // 1) whole-command dangerous detection (compound patterns + destructive
  //    words in command position + destructive executables, recursing into
  //    sh -c / exec wrappers / command substitutions)
  const danger = detectDangerous(trimmed)
  if (danger !== null) return classificationOf('DANGEROUS', danger.reason, danger.ruleId, trimmed)

  const masked = maskQuoted(trimmed)

  // 2) opaque shell syntax -> UNKNOWN (honest: cannot be verified as read-only,
  //    and NOT claimed to modify).
  //    Exec wrappers (kubectl exec / docker exec) are skipped here: their INNER
  //    command is classified separately by the full pipeline, so the `sh -c`
  //    inside them must not short-circuit the whole command to UNKNOWN.
  for (const segment of splitSegments(trimmed)) {
    if (extractExecInner(segment) !== null) continue
    if (OPAQUE_SYNTAX_PATTERN.test(maskQuoted(segment))) {
      return classificationOf('UNKNOWN', 'opaque shell syntax; read-only cannot be confirmed', 'syntax.opaque', trimmed, 'LOW')
    }
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

/**
 * Full classification of an inner command string (watch/strace specials).
 *
 * `depth` bounds the recursion through wrappers and command substitutions: a
 * pathological nesting must not blow the stack, and the depth limit makes the
 * deepest level fail closed (UNKNOWN) instead of guessing.
 */
function classifyInnerFully(text: string, depth = 0): CommandRisk {
  if (depth > 6) return 'UNKNOWN'
  const inner = text.replace(/^['"]([\s\S]*)['"]$/, '$1')
  const scanned = scanWholeCommand(inner)
  if (scanned !== null) return scanned.risk
  // The substitution floor applies HERE too: an inner command that runs
  // `x=$(unknown-cli)` must not be more permissive than the substitution.
  const floor = substitutionFloor(inner, depth)
  if (floor !== null && floor.risk !== 'READ') return floor.risk
  const segments = splitSegments(inner)
  if (segments.length === 0) return 'UNKNOWN'
  let worst: CommandRisk = 'READ'
  for (const segment of segments) {
    const c = classifySegment(segment)
    if (RISK_ORDER[c.risk] > RISK_ORDER[worst]) worst = c.risk
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

  // 3) command substitutions are EXECUTED, so their bodies decide a floor:
  // the outer command can never be more permissive than what it substitutes.
  // This is what turns `T=$(grep -c . /var/log/app.log)` from UNKNOWN into
  // READ while keeping `x=$(unknown-cli)` fail-closed.
  const floor = substitutionFloor(trimmed, 0)
  if (floor !== null && floor.risk !== 'READ') {
    return classificationOf(floor.risk, floor.reason, 'substitution.' + floor.risk.toLowerCase(), trimmed, 'LOW')
  }

  // 4) every segment must classify; take the worst result (never downgrade)
  const segments = splitSegments(trimmed)
  if (segments.length === 0) {
    return classificationOf('UNKNOWN', 'unparseable command', 'unknown.command', trimmed, 'LOW')
  }
  let worst: Classification | null = null
  for (const segment of segments) {
    const c = classifySegment(segment)
    if (worst === null || RISK_ORDER[c.risk] > RISK_ORDER[worst.risk]) worst = c
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
