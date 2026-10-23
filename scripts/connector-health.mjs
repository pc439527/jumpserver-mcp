#!/usr/bin/env node
/**
 * connector-health.mjs — WorkBuddy 升级后 jumpserver 连接器体检 / 一键修复
 *
 * 背景（2026-10-15 事故）：
 *   WorkBuddy v0.9.2 起，连接器目录默认切到 Market API（在线），本地
 *   connectors-marketplace 目录不再被读取 ⇒ 手装的本地连接器在升级后
 *   会被 reconcile `removed + revokeCredentials`。总开关是用户环境变量
 *   WORKBUDDY_CONNECTOR_MARKET_API=0（'0'=回落本地目录扫描）。
 *
 * 用法：
 *   node scripts/connector-health.mjs          # 体检（只读）
 *   node scripts/connector-health.mjs --fix    # 体检 + 自动修复可修复项
 *
 * 退出码：0 = 全绿；1 = 有红项（--fix 后仍未全绿）。
 */
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'

const REPO = 'D:/desktop/IT信息部/WorkBuddy/jumpserver-mcp'
const WB = 'C:/Users/114976/.workbuddy'
const ACCOUNT = '3f83a5bd-8129-40d2-a355-58dcb153efee'
const JUNCTION = 'C:/Users/114976/WorkBuddy/jumpserver-mcp/lib/server.js'
const NODE = 'C:/Users/114976/.workbuddy/binaries/node/versions/22.22.2-6/node.exe'

const results = []
function check(name, ok, detail, fix) {
  results.push({ name, ok, detail, fix })
  console.log(`${ok ? '[ OK ]' : '[ FAIL]'} ${name}${detail ? ' — ' + detail : ''}`)
}

function readJson(p) {
  try { return JSON.parse(readFileSync(p, 'utf8')) } catch { return null }
}

// 1. 环境变量开关（HKCU 用户级）
function envFix() {
  try { execSync('setx WORKBUDDY_CONNECTOR_MARKET_API 0', { stdio: 'ignore' }); return true }
  catch { return false }
}
let envVal = null
try {
  envVal = execSync(
    'powershell -NoProfile -Command "(Get-ItemProperty HKCU:\\Environment).WORKBUDDY_CONNECTOR_MARKET_API"',
    { encoding: 'utf8' },
  ).trim()
  if (!envVal) envVal = null
} catch {}
check('环境变量 WORKBUDDY_CONNECTOR_MARKET_API=0', envVal === '0',
  envVal === '0' ? '已设置（本地目录模式）' : `当前值=${envVal ?? '未设置'}（默认在线 Market API，本地包不可见）`, envFix)

// 2. 目录联接 + lib 产物
let junctionOk = false
try { junctionOk = statSync(JUNCTION).size > 0 } catch {}
check('目录联接 → lib/server.js', junctionOk, JUNCTION,
  () => { try { execSync(`cmd /c mklink /J "C:\\Users\\114976\\WorkBuddy\\jumpserver-mcp" "D:\\desktop\\IT信息部\\WorkBuddy\\jumpserver-mcp"`, { stdio: 'ignore' }); return true } catch { return false } })

// 3. 注册表条目（connectors/default/mcp.json）
const regPath = join(WB, 'connectors/default/mcp.json')
const reg = readJson(regPath)
const regEntry = reg?.mcpServers?.['connector:jumpserver']
const regOk = !!regEntry && regEntry.disabled === false
check('注册表 connector:jumpserver 条目（enabled）', regOk,
  regOk ? '存在且 enabled' : regEntry ? '存在但 disabled' : '缺失',
  () => {
    try {
      const j = readJson(regPath); if (!j?.mcpServers) return false
      j.mcpServers['connector:jumpserver'] = {
        type: 'stdio', command: NODE,
        args: ['C:/Users/114976/WorkBuddy/jumpserver-mcp/lib/server.js'],
        runtime: { type: 'node', version: '>=18' }, disabled: false,
      }
      writeFileSync(regPath + '.bak', readFileSync(regPath))
      writeFileSync(regPath, JSON.stringify(j, null, 1))
      return true
    } catch { return false }
  })

// 4. 凭据状态（账号目录 connector-states.v3.json）
const st = readJson(join(WB, 'connectors', ACCOUNT, 'connector-states.v3.json'))
const stOk = st?.enabled?.includes('jumpserver') && !st?.userDisabled?.jumpserver
check('凭据状态 jumpserver enabled', !!stOk,
  stOk ? 'enabled 且未被用户禁用' : '异常（enabled 列表缺失或被禁用）——需在 UI 连接器页重新启用', null)

// 5. 本地市场索引含 jumpserver
const idx = readJson(join(WB, 'connectors-marketplace/.codebuddy-connector/connectors.json'))
const idxOk = !!idx?.connectors?.some(c => c.id === 'jumpserver')
check('本地市场索引含 jumpserver', idxOk,
  idxOk ? `${idx.connectors.length} 项，含 jumpserver` : '缺失——需要跑 npm run market:build',
  () => { try { execSync('npm run market:build', { cwd: REPO, env: { ...process.env, CODEBUDDY_SAFE_DELETE_ENABLED: '0' }, stdio: 'ignore', timeout: 15 * 60_000 }); return true } catch { return false } })

// 6. 自定义 mcp.json 不应有 jumpserver（防双份）
const custom = readJson(join(WB, 'mcp.json'))
const dup = !!custom?.mcpServers?.jumpserver
check('无重复的自定义 MCP jumpserver', !dup, dup ? '存在——会与 connector:jumpserver 双份工具冲突' : '干净',
  () => { try { writeFileSync(join(WB, 'mcp.json'), JSON.stringify({ mcpServers: {} }, null, 2)); return true } catch { return false } })

// ---- 汇总
const fails = results.filter(r => !r.ok)
console.log('\n==== 汇总 ====')
if (fails.length === 0) { console.log('全部通过。'); process.exit(0) }
if (process.argv.includes('--fix')) {
  let remaining = 0
  for (const f of fails) {
    if (typeof f.fix !== 'function') { console.log(`[需手动] ${f.name}`); remaining++; continue }
    const ok = f.fix() === true
    console.log(`[${ok ? '已修复' : '修复失败'}] ${f.name}`)
    if (!ok) remaining++
  }
  console.log(remaining ? `\n仍有 ${remaining} 项未自动修复，按上面提示手动处理，然后重启 WorkBuddy。` : '\n已全部修复。重启 WorkBuddy 生效。')
  process.exit(remaining ? 1 : 0)
}
console.log('跑 `node scripts/connector-health.mjs --fix` 尝试自动修复；标[需手动]的按提示处理。修复后重启 WorkBuddy。')
process.exit(1)
