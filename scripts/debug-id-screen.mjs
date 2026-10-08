#!/usr/bin/env node
/**
 * Debug: drive the bastion over SSH/PTY until the post-target `ID>`
 * account-selection screen appears, then dump BOTH the raw PTY tail and
 * the detector's verdict on it. Used to verify lib/jumpserver/detector.js
 * against the real KoKo output (fixtures in tests/jumpserver/detector-*.test.mjs
 * cover canonical forms, but the operator may see slightly different layouts).
 *
 * Usage:
 *   JUMPSERVER_PASSWORD=... \
 *   JUMPSERVER_TARGET=192.168.138.56 \
 *   /path/to/node scripts/debug-id-screen.mjs
 *
 * Output: one JSON object on stdout with `rawTail`, `cleanTail`,
 * `detection`, and `reason`. Exit 0 when an ID> screen was reached.
 */
import { Client } from 'ssh2'
import { looksLikeAccountSelection } from '../lib/jumpserver/detector.js'
import { cleanAnsi } from '../lib/jumpserver/output-buffer.js'

const host = process.env.JUMPSERVER_HOST ?? '192.168.74.130'
const port = Number(process.env.JUMPSERVER_PORT ?? 2222)
const username = process.env.JUMPSERVER_USERNAME ?? '114976'
const password = process.env.JUMPSERVER_PASSWORD
const target = process.env.JUMPSERVER_TARGET ?? '192.168.138.56'

if (password === undefined || password.length === 0) {
  console.error('JUMPSERVER_PASSWORD env var is required')
  process.exit(2)
}

const client = new Client()
let collected = ''
let stream = null
let menuReady = false
let reported = false

function report(reason) {
  if (reported) return
  reported = true
  const tail = collected.slice(-2048)
  const clean = cleanAnsi(tail)
  const detection = looksLikeAccountSelection(tail)
  process.stdout.write(JSON.stringify({
    reason,
    menuReady,
    bytes: collected.length,
    rawTail: tail,
    cleanTail: clean,
    detection,
  }, null, 2) + '\n')
  cleanup()
}

function cleanup() {
  try { stream?.close() } catch { /* already closed */ }
  try { client.end() } catch { /* already closed */ }
  setTimeout(() => process.exit(0), 200)
}

client.on('error', (err) => {
  console.error('ssh error: ' + err.message)
  process.exit(4)
})

client.on('ready', () => {
  client.shell({ term: 'xterm-256color', cols: 200, rows: 50 }, (err, s) => {
    if (err !== null && err !== undefined) {
      console.error('shell error: ' + err.message)
      process.exit(1)
    }
    stream = s
    s.on('data', (chunk) => {
      collected += chunk.toString()
      const clean = cleanAnsi(collected)
      if (!menuReady && /Opt[>#]\s/.test(clean)) {
        menuReady = true
        console.error('[debug] menu ready; typing target=' + target)
        setTimeout(() => { s.write(target + '\n') }, 100)
      }
    })
    s.on('close', () => {
      if (!menuReady) report('wire-closed-before-menu')
      else report('wire-closed-after-menu')
    })
    // Hard deadlines: 5s for menu, then 8s after the target was typed.
    setTimeout(() => {
      if (!menuReady) report('menu-never-appeared')
    }, 5000)
    setTimeout(() => {
      if (menuReady) report('deadline-reached')
    }, 13000)
  })
})

client.connect({ host, port, username, password, readyTimeout: 15000 })