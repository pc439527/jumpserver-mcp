#!/usr/bin/env node
/**
 * Discover every tests `**` `.test.mjs` and hand them to node:test.
 * Used by `npm test` so the same command works on every platform
 * (the built-in `node --test path` requires a file, not a directory).
 */
import { spawn } from 'node:child_process'
import { readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const testsRoot = join(root, 'tests')

function walk(dir, out) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) walk(full, out)
    else if (name.endsWith('.test.mjs')) out.push(relative(root, full))
  }
  return out
}

const files = walk(testsRoot, []).sort()
if (files.length === 0) {
  console.error('no tests found under ' + testsRoot)
  process.exit(1)
}

const child = spawn(process.execPath, ['--test', ...files], {
  stdio: 'inherit',
  cwd: root,
})
child.on('exit', (code, signal) => {
  if (signal !== null) process.kill(process.pid, signal)
  process.exit(code ?? 1)
})
