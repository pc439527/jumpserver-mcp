#!/usr/bin/env node
/**
 * pack-connector.mjs — 生成「发布连接器」页面上传用的 zip。
 *
 * 注意区分两个 zip，传错会被直接打回：
 *
 *   .workbuddy/artifacts/jumpserver-connector-v<ver>.zip   ← 本脚本，上传用
 *       扁平结构，只有这一个连接器：
 *         connector-meta.json / mcp.json / token-schema.json
 *         icon.svg / skills/jumpserver/SKILL.md
 *
 *   .workbuddy/artifacts/connectors-config.zip              ← 本地市场用，不要上传
 *       整个市场快照（185 个连接器 + .codebuddy-connector/connectors.json），
 *       是给本机 WorkBuddy 当市场源用的。
 *
 * 先跑 validate:connector（含脱敏扫描），没问题再打包。
 *
 * Run: npm run pack:connector
 */

import { readFileSync, existsSync, readdirSync, statSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import AdmZip from 'adm-zip'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const srcDir = join(root, 'connector')
const outDir = join(root, '.workbuddy', 'artifacts')

const REQUIRED = ['connector-meta.json', 'mcp.json']
const ICONS = ['icon.svg', 'icon.png', 'icon.jpg']

function fail(msg) {
  console.error(`✗ ${msg}`)
  process.exit(1)
}

if (!existsSync(srcDir)) fail(`未找到 ${srcDir}`)

for (const f of REQUIRED) {
  if (!existsSync(join(srcDir, f))) fail(`缺少必需文件 connector/${f}`)
}
if (!ICONS.some((f) => existsSync(join(srcDir, f)))) {
  fail(`缺少图标：connector/${ICONS[0]}（或 .png / .jpg）`)
}

const meta = JSON.parse(readFileSync(join(srcDir, 'connector-meta.json'), 'utf8'))
const version = meta.version
if (typeof version !== 'string' || version.length === 0) fail('connector-meta.json 缺少 version，无法命名产物')
if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(meta.source ?? '')) fail(`source "${meta.source}" 不是 kebab-case`)

/** 递归列出包内文件，用正斜杠（zip 规范要求） */
function listFiles(dir, base = dir, acc = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) listFiles(full, base, acc)
    else acc.push(relative(base, full).split('\\').join('/'))
  }
  return acc
}

const files = listFiles(srcDir).sort()
if (files.length === 0) fail('connector/ 是空的')

const pkgName = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).name
const target = (JSON.parse(readFileSync(join(srcDir, 'mcp.json'), 'utf8')).mcpServers ?? {})[meta.source] ?? {}
const args = Array.isArray(target.args) ? target.args : []
if (!args.includes(pkgName)) {
  console.error(`! mcp.json 的 args 里没有 "${pkgName}"（${JSON.stringify(args)}）—— 安装后会拉不到包，确认是否故意`)
}

const zip = new AdmZip()
for (const rel of files) zip.addLocalFile(join(srcDir, rel), dirname(rel) === '.' ? '' : dirname(rel))

mkdirSync(outDir, { recursive: true })
const outPath = join(outDir, `jumpserver-connector-v${version}.zip`)
if (existsSync(outPath)) rmSync(outPath)
zip.writeZip(outPath)

const buf = readFileSync(outPath)
const sha = createHash('sha256').update(buf).digest('hex')
const LIMIT = 20 * 1024 * 1024

console.log(`\n连接器提交包（上传到「发布连接器」页面）`)
console.log(`  source    ${meta.source}`)
console.log(`  version   ${version}`)
console.log(`  文件      ${files.length} 个`)
for (const f of files) console.log(`            ${f}  (${statSync(join(srcDir, f)).size} B)`)
console.log(`  产物      ${relative(root, outPath)}`)
console.log(`  大小      ${buf.length} B / 上限 ${LIMIT} B — ${buf.length <= LIMIT ? 'OK' : '超限'}`)
console.log(`  sha256    ${sha}`)

// 目录型产物便于人工核对
const stagingDir = join(outDir, 'connector-package')
rmSync(stagingDir, { recursive: true, force: true })
mkdirSync(stagingDir, { recursive: true })
for (const rel of files) {
  const dest = join(stagingDir, rel)
  mkdirSync(dirname(dest), { recursive: true })
  writeFileSync(dest, readFileSync(join(srcDir, rel)))
}
console.log(`  解包预览  ${relative(root, stagingDir)}/\n`)

if (buf.length > LIMIT) process.exit(1)
