#!/usr/bin/env node
/**
 * Pin a stable path for this checkout, so frozen install artifacts keep working.
 *
 * Why this exists: a dev-mode marketplace package bakes the checkout's absolute
 * path in at BUILD time (stdio servers cannot be expressed any other way), and
 * "re-bind from the marketplace" copies that path straight into the connector
 * registry. Move the folder and every artifact built before the move points at
 * nothing — the connector then shows as enabled with an EMPTY tool list.
 *
 * A directory junction at the path the artifacts already froze makes all of them
 * resolve again, without rebuilding or editing the registry by hand.
 *
 *   node scripts/link-stable-checkout.mjs            # create/repair the link
 *   node scripts/link-stable-checkout.mjs --status    # report only
 *   node scripts/link-stable-checkout.mjs --remove    # drop the link (never the checkout)
 *
 * The link lives at ~/WorkBuddy/jumpserver-mcp — the location the original
 * package was built against. Nothing is ever deleted: --remove only removes the
 * link itself, and refuses if the link target is not this checkout.
 */
import { existsSync, lstatSync, readlinkSync, realpathSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const LINK_PATH = join(homedir(), 'WorkBuddy', 'jumpserver-mcp')

const args = process.argv.slice(2)
const wantStatus = args.includes('--status')
const wantRemove = args.includes('--remove')

const same = (a, b) => {
  try {
    return resolve(realpathSync(a)).toLowerCase() === resolve(realpathSync(b)).toLowerCase()
  } catch {
    return false
  }
}

function describe() {
  if (!existsSync(LINK_PATH)) return { kind: 'absent' }
  const stat = lstatSync(LINK_PATH)
  if (!stat.isSymbolicLink()) return { kind: 'real-directory' }
  let target = null
  try {
    target = readlinkSync(LINK_PATH)
  } catch {
    target = null
  }
  return { kind: 'link', target, pointsHere: same(LINK_PATH, ROOT) }
}

console.log('checkout : ' + ROOT)
console.log('link     : ' + LINK_PATH)

const state = describe()
console.log('state    : ' + state.kind + (state.kind === 'link' ? ' -> ' + String(state.target) : ''))

if (wantStatus) {
  if (state.kind === 'link' && state.pointsHere) {
    console.log('\nOK — frozen artifacts pointing at the link path resolve to this checkout.')
    process.exit(0)
  }
  console.log('\nNOT PINNED — run without --status to create the link.')
  process.exit(1)
}

if (wantRemove) {
  if (state.kind !== 'link') {
    console.log('\nNothing to remove: the path is not a link. Refusing to touch it.')
    process.exit(1)
  }
  if (!state.pointsHere) {
    console.log('\nRefusing: the link does not point at this checkout.')
    process.exit(1)
  }
  if (spawnSync('cmd', ['/c', 'rmdir', LINK_PATH], { stdio: 'inherit' }).status !== 0) {
    console.log('\nCould not remove the link.')
    process.exit(1)
  }
  console.log('\nLink removed. The checkout itself was not touched.')
  process.exit(0)
}

if (state.kind === 'real-directory') {
  console.log('')
  console.log('Refusing: a REAL directory already exists at the link path, and replacing it')
  console.log('would hide whatever is in it. Move it aside yourself, then run this again.')
  process.exit(1)
}

if (state.kind === 'link' && state.pointsHere) {
  console.log('\nAlready pinned — nothing to do.')
  process.exit(0)
}

if (state.kind === 'link' && !state.pointsHere) {
  console.log('\nReplacing a link that points somewhere else…')
  spawnSync('cmd', ['/c', 'rmdir', LINK_PATH], { stdio: 'inherit' })
}

mkdirSync(dirname(LINK_PATH), { recursive: true })
const made = spawnSync('cmd', ['/c', 'mklink', '/J', LINK_PATH, ROOT], { stdio: 'inherit' })
if (made.status !== 0 || !existsSync(join(LINK_PATH, 'package.json'))) {
  console.log('')
  console.log('Could not create the junction.')
  console.log('Fallback: run this in an elevated shell —')
  console.log('  cmd /c mklink /J "' + LINK_PATH + '" "' + ROOT + '"')
  process.exit(1)
}

console.log('')
console.log('Pinned. Frozen install artifacts pointing at the link path now resolve here.')
console.log('Drop it any time with: node scripts/link-stable-checkout.mjs --remove')
