/**
 * Host parser tests — every parser must be defensive, a format it does not
 * understand must yield an empty result and never a wrong number.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  parseHostname, parseOsRelease, parseUptime, parseLoadavg, parseMemory,
  parseDisks, parseIpAddr, parseDefaultRoute, parseListen, parseConnections,
  parseHosts, parsePs, parseServices, parseJps, parseDockerPs,
  parseNginxConfig, detectRoles, applyProbe, emptyInventory,
} from '../../lib/jumpserver/host-parse.js'

test('parseHostname: first trimmed word, no spaces', () => {
  assert.equal(parseHostname('oa-nginx\n'), 'oa-nginx')
  assert.equal(parseHostname('  oa-nginx  '), 'oa-nginx')
  assert.equal(parseHostname('oa nginx'), null)
})

test('parseOsRelease: every field is a separate key', () => {
  const r = parseOsRelease('NAME="Rocky Linux"\nVERSION="9.4 (Blue Onyx)"\nID=rocky\nVERSION_ID=9.4\n')
  assert.equal(r.id, 'rocky')
  assert.equal(r.name, 'Rocky Linux')
  assert.equal(r.version, '9.4 (Blue Onyx)')
})

test('parseUptime + parseLoadavg are independent', () => {
  const { uptime, load } = parseUptime(' 17:32:14 up 12 days,  3:45,  2 users,  load average: 0.31, 0.22, 0.18')
  assert.equal(uptime, '12 days')
  assert.deepEqual(load, [0.31, 0.22, 0.18])
  assert.deepEqual(parseLoadavg('0.31 0.22 0.18 1/234 5678'), [0.31, 0.22, 0.18])
})

test('parseMemory honours the Mem: line over headers', () => {
  const r = parseMemory('              total        used        free      shared  buff/cache   available\n' +
    'Mem:        16000        9000        1200         300        5800        6500\n')
  assert.equal(r.totalMb, 16000)
  assert.equal(r.usedMb, 9000)
  assert.equal(r.availableMb, 6500)
  assert.equal(r.usedPct, 56)
})

test('parseDisks ignores non-root lines and parses the rest', () => {
  const r = parseDisks('Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   30G   20G  60% /\n')
  assert.equal(r.length, 1)
  assert.equal(r[0].fs, '/dev/sda1')
  assert.equal(r[0].usePct, 60)
  assert.equal(r[0].mount, '/')
})

test('parseIpAddr returns one entry per interface, dropping loopback + link-local', () => {
  const r = parseIpAddr([
    '1: lo    inet 127.0.0.1/8 scope host lo',
    '2: eth0  inet 192.168.79.99/24 brd 192.168.79.255 scope global eth0',
    '3: eth0  inet6 fe80::1/64 scope link',
  ].join('\n'))
  assert.equal(r.length, 2)
  // lo has no usable (non-loopback) IPs - keep the row but empty.
  assert.equal(r[0].name, 'lo')
  assert.deepEqual(r[0].addrs, [])
  assert.equal(r[1].name, 'eth0')
  assert.deepEqual(r[1].addrs, ['192.168.79.99'])
})

test('parseDefaultRoute finds the "default" line', () => {
  assert.equal(parseDefaultRoute('default via 192.168.79.1 dev eth0\n192.168.79.0/24 dev eth0 src 192.168.79.99'), '192.168.79.1')
  assert.equal(parseDefaultRoute('192.168.79.0/24 dev eth0'), null)
})

test('parseListen: only ESTAB/LISTEN rows pass; entries are de-duplicated', () => {
  const sample = [
    'State      Recv-Q Send-Q Local Address:Port    Peer Address:Port',
    'LISTEN     0      128          0.0.0.0:80           0.0.0.0:*       users:(("nginx",pid=1234))',
    'LISTEN     0      128          0.0.0.0:80           0.0.0.0:*       users:(("nginx",pid=1234))',
    'LISTEN     0      128             [::]:443               [::]:*       users:(("nginx",pid=1234))',
  ].join('\n')
  const r = parseListen(sample)
  assert.equal(r.length, 2)
  assert.equal(r[0].port, 80)
  assert.equal(r[0].process, 'nginx')
  assert.equal(r[1].port, 443)
})

test('parseConnections: only ESTABLISHED rows pass', () => {
  const sample = [
    'State Recv-Q Send-Q Local Address:Port    Peer Address:Port',
    'ESTAB 0      0      192.168.79.99:443     192.168.79.101:54321',
    'TIME-WAIT 0  0    192.168.79.99:443     192.168.79.102:54322',
  ].join('\n')
  const r = parseConnections(sample)
  assert.equal(r.length, 1)
  assert.equal(r[0].remoteIp, '192.168.79.101')
})

test('parseHosts ignores loopback and comments', () => {
  const r = parseHosts('# header\n127.0.0.1   localhost\n192.168.79.101 oa-app-01\n')
  assert.deepEqual(r, [{ ip: '192.168.79.101', names: ['oa-app-01'] }])
})

test('parsePs is tolerant of missing columns', () => {
  const r = parsePs('  PID  PPID USER     %CPU %MEM     ELAPSED  CMD\n' +
    ' 1234     1 root      0.5  1.2  12-03:45:01  nginx: master\n' +
    ' 1235  1234 www-data  0.2  0.8  12-03:45:01  nginx: worker\n')
  assert.equal(r.length, 2)
  assert.equal(r[0].pid, 1234)
  assert.equal(r[0].user, 'root')
})

test('parseServices returns the unit names', () => {
  const r = parseServices('UNIT                                   LOAD   ACTIVE SUB     DESCRIPTION\n' +
    'sshd.service                            loaded active running OpenSSH server daemon\n' +
    'nginx.service                           loaded active running The nginx HTTP server\n')
  assert.deepEqual(r, ['sshd.service', 'nginx.service'])
})

test('parseJps extracts pid, main, args', () => {
  const r = parseJps('1234 Resin  -Dresin.home=/usr/weaver -Xmx4096m\n5678 Jps -lv\n')
  assert.equal(r[0].pid, 1234)
  assert.equal(r[0].main, 'Resin')
  assert.equal(r[0].args.startsWith('-Dresin.home'), true)
})

test('parseDockerPs reads CONTAINER ID / IMAGE / NAMES', () => {
  const r = parseDockerPs('CONTAINER ID   IMAGE          COMMAND                CREATED         STATUS         PORTS                  NAMES\n' +
    'a1b2c3d4e5f6   nginx:1.25     "/docker-entrypoint…"  12 minutes ago  Up 12 minutes  0.0.0.0:80->80/tcp   web\n')
  assert.equal(r[0].id, 'a1b2c3d4e5f6')
  assert.equal(r[0].name, 'web')
  assert.equal(r[0].image, 'nginx:1.25')
})

test('parseNginxConfig: upstreams + proxy_pass + server_name', () => {
  const cfg = [
    'nginx config',
    'upstream oa_backend {',
    '  server 192.168.79.101:8080;',
    '  server 192.168.79.102:8080;',
    '  server 192.168.79.103:8080;',
    '}',
    'server {',
    '  listen 80;',
    '  server_name oa.example.com;',
    '  location / { proxy_pass http://oa_backend; }',
    '}',
  ].join('\n')
  const r = parseNginxConfig(cfg)
  assert.equal(r.upstreams.length, 1)
  assert.equal(r.upstreams[0].name, 'oa_backend')
  assert.equal(r.upstreams[0].servers.length, 3)
  assert.deepEqual(r.proxies, ['http://oa_backend'])
  assert.deepEqual(r.serverNames, ['oa.example.com'])
})

test('detectRoles from process + listen evidence', () => {
  const inv = emptyInventory('1.2.3.4', [])
  inv.processes = [
    { pid: 1, ppid: 0, user: 'root', cpu: 0, mem: 0, etime: '1d', cmd: '/usr/sbin/nginx: master' },
    { pid: 2, ppid: 1, user: 'root', cpu: 0, mem: 0, etime: '1d', cmd: 'mysqld --datadir=/var/lib/mysql' },
  ]
  inv.listening = [
    { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd' },
    { proto: 'tcp', address: '0.0.0.0', port: 80, process: 'nginx' },
    { proto: 'tcp', address: '0.0.0.0', port: 3306, process: 'mysqld' },
  ]
  // reverse-proxy is only set when an actual nginx config was collected.
  assert.deepEqual(detectRoles(inv).sort(), ['mysql', 'nginx', 'ssh'])
})

test('applyProbe: unknown probe id is a no-op (the inspector must not crash on a new probe)', () => {
  const inv = emptyInventory('1.2.3.4', [])
  applyProbe(inv, 'no-such-id', 'irrelevant', 0)
  assert.equal(inv.target, '1.2.3.4')
})
