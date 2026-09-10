/**
 * Topology tests — every edge must carry a confidence and evidence. Topology
 * MUST NOT infer relationships from naming conventions or aliases.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { buildTopology, renderTopology } from '../../lib/jumpserver/topology.js'
import { emptyInventory } from '../../lib/jumpserver/host-parse.js'

function inventoryFor(target, hostname, ips, extras) {
  const inv = emptyInventory(target, [])
  inv.hostname = hostname
  inv.interfaces = ips.map((ip) => ({ name: 'eth0', addrs: [ip] }))
  return Object.assign(inv, extras)
}

test('nginx upstream -> evidence = upstream block + peer listens on port', () => {
  const proxy = inventoryFor('192.168.79.99', 'oa-nginx', ['192.168.79.99'], {
    nginx: { upstreams: [{ name: 'oa_backend', servers: [{ host: '192.168.79.101', port: 8080 }, { host: '192.168.79.102', port: 8080 }] }], proxies: [], serverNames: [] },
  })
  const app1 = inventoryFor('192.168.79.101', 'oa-app-01', ['192.168.79.101'], {
    listening: [{ proto: 'tcp', address: '0.0.0.0', port: 8080, process: 'resin' }],
    roles: ['resin'],
  })
  const app2 = inventoryFor('192.168.79.102', 'oa-app-02', ['192.168.79.102'], {
    listening: [{ proto: 'tcp', address: '0.0.0.0', port: 8080, process: 'resin' }],
    roles: ['resin'],
  })
  const topo = buildTopology([proxy, app1, app2])
  const upEdges = topo.edges.filter((e) => e.type === 'reverse_proxy')
  assert.equal(upEdges.length, 2)
  for (const edge of upEdges) {
    assert.equal(edge.confidence, 'HIGH')
    assert.ok(edge.evidence.some((e) => e.startsWith('nginx upstream')), 'edge ' + JSON.stringify(edge))
    assert.ok(edge.evidence.some((e) => e.includes('peer listens on 8080')), 'peer listening evidence missing')
  }
})

test('established socket is HIGH only when the peer really listens on the remote port', () => {
  const a = inventoryFor('192.168.79.99', 'oa-nginx', ['192.168.79.99'], {
    connections: [
      { remoteIp: '192.168.79.101', remotePort: 8080, state: 'ESTABLISHED', process: 'nginx' },
      { remoteIp: '192.168.79.102', remotePort: 9999, state: 'ESTABLISHED', process: 'nginx' },
    ],
  })
  const b = inventoryFor('192.168.79.101', 'oa-app-01', ['192.168.79.101'], {
    listening: [{ proto: 'tcp', address: '0.0.0.0', port: 8080, process: 'resin' }],
  })
  const c = inventoryFor('192.168.79.102', 'oa-app-02', ['192.168.79.102'], {
    listening: [{ proto: 'tcp', address: '0.0.0.0', port: 1234, process: 'misc' }],
  })
  const topo = buildTopology([a, b, c])
  const conn = topo.edges.filter((e) => e.type === 'tcp_client')
  assert.equal(conn.length, 2)
  const confirmed = conn.find((e) => e.to === '192.168.79.101')
  const guessed = conn.find((e) => e.to === '192.168.79.102')
  assert.equal(confirmed.confidence, 'HIGH')
  assert.equal(guessed.confidence, 'MEDIUM')
})

test('depth=2 links app nodes that share one upstream', () => {
  const proxy = inventoryFor('192.168.79.99', 'oa-nginx', ['192.168.79.99'], {
    nginx: { upstreams: [{ name: 'oa_backend', servers: [{ host: '192.168.79.101', port: 8080 }, { host: '192.168.79.102', port: 8080 }] }], proxies: [], serverNames: [] },
  })
  const app1 = inventoryFor('192.168.79.101', 'oa-app-01', ['192.168.79.101'], { listening: [{ proto: 'tcp', address: '0.0.0.0', port: 8080, process: 'resin' }] })
  const app2 = inventoryFor('192.168.79.102', 'oa-app-02', ['192.168.79.102'], { listening: [{ proto: 'tcp', address: '0.0.0.0', port: 8080, process: 'resin' }] })
  const topo = buildTopology([proxy, app1, app2], { depth: 2 })
  const siblings = topo.edges.filter((e) => e.type === 'same_upstream')
  assert.equal(siblings.length, 2, 'a <-> b should be both directions')
  assert.ok(siblings.every((e) => e.confidence === 'MEDIUM'))
})

test('unreachable nodes produce a warning and no edges', () => {
  const a = inventoryFor('192.168.79.99', 'oa-nginx', ['192.168.79.99'])
  a.reachable = false
  a.error = 'CONNECTION_LOST'
  const b = inventoryFor('192.168.79.101', 'oa-app-01', ['192.168.79.101'], {
    connections: [{ remoteIp: '192.168.79.99', remotePort: 443, state: 'ESTABLISHED', process: 'resin' }],
  })
  const topo = buildTopology([a, b])
  assert.equal(topo.edges.length, 0)
  assert.ok(topo.warnings.some((w) => w.includes('192.168.79.99')))
})

test('renderTopology is a stable, text-only projection', () => {
  const a = inventoryFor('192.168.79.99', 'oa-nginx', ['192.168.79.99'], { roles: ['nginx'] })
  const out = renderTopology(buildTopology([a]))
  assert.ok(out.includes('192.168.79.99'))
  assert.ok(out.includes('nginx'))
})
