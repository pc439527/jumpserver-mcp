#!/usr/bin/env node
/**
 * local-connector-market.mjs — 本地连接器市场（开发验证专用）
 *
 * 让 WorkBuddy 从本机加载一个自定义的 connector marketplace，用来在不提交审核、
 * 不上架的前提下，验证连接器的完整链路：
 *
 *   token-schema.json 表单渲染 → ${VAR} 注入 env → stdio MCP 启动 → skills 安装
 *
 * 原理（来自 WorkBuddy 客户端实现）：
 *   客户端会读 `{configDir}/connectors/connector-marketplace.json`，用其中的
 *   `connectorMarketplaceUrl` / `connectorMarketplaceInternalUrl` 覆盖远端市场
 *   zip 地址，然后把 zip 解压替换整个 `connectors-marketplace/` 目录。
 *
 *   zip 内必须包含：
 *     .codebuddy-connector/connectors.json   ← 索引（缺了会直接抛错）
 *     connectors/<id>/mcp.json
 *     connectors/<id>/token-schema.json      ← auth_mode=token 时读取
 *     connectors/<id>/skills/**              ← 安装到 ~/.workbuddy/connectors/skills/connector-<id>/
 *     icons/<id>.svg
 *
 *   注意：`replaceMarketplaceDir` 是 `rmSync(baseDir)` + `rename`，
 *   所以不能往 `connectors-marketplace/` 里硬塞文件——每次同步都会被清掉。
 *   本脚本的做法是以现有缓存为基线、追加我们的连接器，再整包替换。
 *
 * 用法：
 *   node scripts/local-connector-market.mjs build            # 生成 zip（dev：跑本地 lib/server.js）
 *   node scripts/local-connector-market.mjs build --release  # 生成 zip（release：npx jumpserver-mcp）
 *   node scripts/local-connector-market.mjs serve [--port N]  # 起本地 HTTP 市场服务（默认 8899）
 *   node scripts/local-connector-market.mjs enable [--port N] # 写入覆盖配置 + 清除指纹，触发重同步
 *   node scripts/local-connector-market.mjs disable           # 撤销覆盖，恢复官方市场
 *   node scripts/local-connector-market.mjs status            # 查看当前状态
 */
import {
  existsSync,
  mkdirSync,
  rmSync,
  cpSync,
  readFileSync,
  writeFileSync,
  statSync,
  readdirSync,
} from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import AdmZip from 'adm-zip'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')

/** WorkBuddy 配置根目录 */
const CONFIG_DIR = join(homedir(), '.workbuddy')
/** 市场本地缓存目录（客户端每次同步会整体替换） */
const CACHE_DIR = join(CONFIG_DIR, 'connectors-marketplace')
/** 市场指纹（etag / sha256），删掉即强制重新同步 */
const MARKET_META = join(CONFIG_DIR, '.connectors-marketplace.meta.json')
/** 本地覆盖配置文件 —— 官方支持的入口 */
const OVERRIDE_FILE = join(CONFIG_DIR, 'connectors', 'connector-marketplace.json')
/** 基线索引：用它保证不丢掉已有的 184 个连接器 */
const BASELINE_MANIFEST = join(CACHE_DIR, '.codebuddy-connector', 'connectors.json')

const ARTIFACT_DIR = join(ROOT, '.workbuddy', 'artifacts')
const OUT_DIR = join(ARTIFACT_DIR, 'local-market')
/** 与客户端 MANIFEST_REL_PATH / CONNECTORS_DIR 对齐 */
const OUT_MANIFEST = join(OUT_DIR, '.codebuddy-connector', 'connectors.json')
const ZIP_PATH = join(ARTIFACT_DIR, 'connectors-config.zip')

const SRC_DIR = join(ROOT, 'connector')
const ID = 'jumpserver'
const DEFAULT_PORT = 8899
const CACHE_SUBDIRS = ['.codebuddy-connector', 'connectors', 'icons']

// ---------------------------------------------------------------- helpers

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function parseArgs(argv) {
  const args = { _: [] }
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]
    if (a === '--port') {
      args.port = Number(argv[++i])
    } else if (a.startsWith('--port=')) {
      args.port = Number(a.slice(7))
    } else if (a === '--release') {
      args.release = true
    } else {
      args._.push(a)
    }
  }
  return args
}

function fail(msg) {
  console.error(`\x1b[31m✗ ${msg}\x1b[0m`)
  process.exit(1)
}

function ok(msg) {
  console.log(`\x1b[32m✓\x1b[0m ${msg}`)
}

function info(msg) {
  console.log(`  ${msg}`)
}

// ---------------------------------------------------------------- build

/**
 * connector-meta.json → 市场索引条目。
 *
 * 刻意不写 `visible_in`：客户端 isConnectorVisible() 对空数组返回 true，
 * 写错规则（如 iOA / plan:xxx）反而会让连接器在列表里消失。
 */
function buildManifestEntry() {
  const meta = readJson(join(SRC_DIR, 'connector-meta.json'))
  return {
    id: ID,
    name: meta.name_en || meta.name,
    name_zh: meta.name_zh || meta.name,
    name_en: meta.name_en || meta.name,
    description: meta.description_en || meta.description,
    description_zh: meta.description_zh || meta.description,
    description_en: meta.description_en || meta.description,
    source: ID,
    type: 'mcp',
    auth_mode: 'token',
    version: meta.version,
    minWorkbuddyVersion: meta.minWorkbuddyVersion,
    examples_zh: meta.examples_zh ?? [],
    examples_en: meta.examples_en ?? [],
  }
}

/**
 * 组装 mcp.json。
 *
 * dev 模式跑本地 `lib/server.js`：npm 上的 jumpserver-mcp 尚未发布，
 * 用 `npx -y jumpserver-mcp` 会在启动阶段直接失败，且报错与配置无关。
 */
function buildMcpConfig({ release }) {
  const env = {
    JUMPSERVER_HOST: '${JUMPSERVER_HOST}',
    JUMPSERVER_PORT: '${JUMPSERVER_PORT}',
    JUMPSERVER_USERNAME: '${JUMPSERVER_USERNAME}',
    JUMPSERVER_PASSWORD: '${JUMPSERVER_PASSWORD}',
  }
  // 不要给 server 条目加 `description`：官方市场 153 个条目里出现 0 次，它不是
  // 平台字段。连接器卡片的描述来自索引条目（buildManifestEntry），不是这里。
  if (release) {
    return {
      mcpServers: {
        [ID]: {
          type: 'stdio',
          command: 'npx',
          args: ['-y', 'jumpserver-mcp'],
          runtime: { type: 'node', version: '20' },
          env,
        },
      },
    }
  }
  const serverJs = join(ROOT, 'lib', 'server.js')
  if (!existsSync(serverJs)) fail(`未找到 ${serverJs}，请先运行 npm run build`)
  return {
    mcpServers: {
      [ID]: { type: 'stdio', command: process.execPath, args: [serverJs], env },
    },
  }
}

function cmdBuild(args) {
  const release = Boolean(args.release)

  if (!existsSync(BASELINE_MANIFEST)) {
    fail(`未找到市场基线 ${BASELINE_MANIFEST}\n  请先启动一次 WorkBuddy 以便它下载官方连接器市场。`)
  }
  const tokenSchema = readJson(join(SRC_DIR, 'token-schema.json'))
  const skillMd = join(SRC_DIR, 'skills', 'jumpserver', 'SKILL.md')
  const iconSvg = join(SRC_DIR, 'icon.svg')
  for (const f of [skillMd, iconSvg]) {
    if (!existsSync(f)) fail(`缺少源文件：${f}`)
  }

  console.log(`\n构建本地连接器市场（${release ? 'release' : 'dev'} 模式）`)

  // 1. 以现有缓存为基线复制，保证原有连接器一个不少
  rmSync(OUT_DIR, { recursive: true, force: true })
  mkdirSync(OUT_DIR, { recursive: true })
  let copied = 0
  for (const sub of CACHE_SUBDIRS) {
    const src = join(CACHE_DIR, sub)
    if (!existsSync(src)) {
      info(`跳过不存在的基线子目录：${sub}`)
      continue
    }
    cpSync(src, join(OUT_DIR, sub), { recursive: true })
    copied += 1
  }
  ok(`复制基线 ${copied}/${CACHE_SUBDIRS.length} 个子目录`)

  // 2. 注入连接器包
  const pkgDir = join(OUT_DIR, 'connectors', ID)
  mkdirSync(join(pkgDir, 'skills'), { recursive: true })
  writeJson(join(pkgDir, 'mcp.json'), buildMcpConfig({ release }))
  writeJson(join(pkgDir, 'token-schema.json'), tokenSchema)
  // skills 拍平成单层：安装后会变成 connector-jumpserver/SKILL.md
  cpSync(skillMd, join(pkgDir, 'skills', 'SKILL.md'))
  mkdirSync(join(OUT_DIR, 'icons'), { recursive: true })
  cpSync(iconSvg, join(OUT_DIR, 'icons', `${ID}.svg`))
  ok(`注入 connector: ${ID}（${tokenSchema.fields.length} 个表单字段）`)

  // 3. 更新索引
  const manifest = readJson(OUT_MANIFEST)
  if (!Array.isArray(manifest.connectors)) fail('基线索引缺少 connectors 数组')
  const before = manifest.connectors.length
  manifest.connectors = manifest.connectors.filter((c) => c.id !== ID && c.source !== ID)
  manifest.connectors.push(buildManifestEntry())
  writeJson(OUT_MANIFEST, manifest)
  ok(`索引条目 ${before} → ${manifest.connectors.length}（追加 ${ID}）`)

  // 4. 打包
  const zip = new AdmZip()
  zip.addLocalFolder(OUT_DIR)
  zip.writeZip(ZIP_PATH)

  // 5. 自检：缺 .codebuddy-connector/connectors.json 客户端会直接抛错
  const verify = new AdmZip(ZIP_PATH)
  const names = verify.getEntries().map((e) => e.entryName.replace(/\\/g, '/'))
  const required = [
    '.codebuddy-connector/connectors.json',
    `connectors/${ID}/mcp.json`,
    `connectors/${ID}/token-schema.json`,
    `connectors/${ID}/skills/SKILL.md`,
    `icons/${ID}.svg`,
  ]
  const missing = required.filter((r) => !names.includes(r))
  const buf = readFileSync(ZIP_PATH)
  console.log('')
  if (missing.length > 0) fail(`zip 缺少必需条目：\n  ${missing.join('\n  ')}`)
  ok(`zip 校验通过：${names.length} 个条目`)
  ok(`产物：${ZIP_PATH}`)
  info(`大小：${(buf.length / 1024 / 1024).toFixed(1)} MB`)
  info(`sha256：${sha256(buf)}`)

  // 6. 占位符一致性（提交审核最容易被卡的一项：拼错只在用户机器上静默注入空值）
  const mcpEnv = buildMcpConfig({ release }).mcpServers[ID].env
  const keys = tokenSchema.fields.map((f) => f.key)
  const placeholders = Object.values(mcpEnv).map((v) => String(v).replace(/^\$\{|\}$/g, ''))
  const mismatched = placeholders.filter((p) => !keys.includes(p))
  if (mismatched.length > 0) fail(`mcp.json 占位符与 token-schema 字段不一致：${mismatched.join(', ')}`)
  ok(`占位符一致性：${placeholders.length} 个 ${'${VAR}'} 全部匹配`)

  console.log('\n下一步：npm run market:serve，然后 npm run market:enable\n')
}

// ---------------------------------------------------------------- serve

function cmdServe(args) {
  const port = args.port ?? DEFAULT_PORT
  if (!existsSync(ZIP_PATH)) fail(`未找到 ${ZIP_PATH}，请先运行 build`)

  // V0.5.1: 按 mtime+size 惰性重载。旧实现只在启动时 readFileSync 一次并把
  // buffer 缓存到进程生命周期结束 —— 结果是重新 build 之后客户端仍然拿到旧包，
  // 而且不会报任何错，极易误判成"改了没生效"。
  let cached = null
  function current() {
    const st = statSync(ZIP_PATH)
    const key = `${st.mtimeMs}:${st.size}`
    if (cached === null || cached.key !== key) {
      const buf = readFileSync(ZIP_PATH)
      cached = { key, buf, etag: `"${sha256(buf).slice(0, 32)}"` }
      console.log(`[${new Date().toISOString()}] 载入 zip ${(buf.length / 1024 / 1024).toFixed(1)} MB etag=${cached.etag}`)
    }
    return cached
  }

  const server = createServer((req, res) => {
    const path = (req.url ?? '').split('?')[0]
    if (path === '/connectors-config.zip' || path === '/connectors-config-internal.zip' || path === '/') {
      const { buf, etag } = current()
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { ETag: etag })
        res.end()
        console.log(`[${new Date().toISOString()}] 304 ${path}（内容未变）`)
        return
      }
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Length': buf.length,
        ETag: etag,
      })
      res.end(buf)
      console.log(`[${new Date().toISOString()}] 200 ${path} → ${(buf.length / 1024 / 1024).toFixed(1)} MB`)
      return
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' })
    res.end('not found\n')
  })

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      fail(`端口 ${port} 已被占用。换一个端口：--port 8899，同时 enable 时保持一致`)
    }
    fail(String(err.message))
  })

  server.listen(port, '127.0.0.1', () => {
    const { etag } = current()
    console.log(`\n本地连接器市场已启动`)
    ok(`http://127.0.0.1:${port}/connectors-config.zip`)
    info(`ETag：${etag}`)
    info('保持本进程运行；WorkBuddy 每 10 分钟检查一次更新')
    info('重新 build 后无需重启本服务：下一次请求会按 mtime 自动载入新包')
    console.log('\n按 Ctrl+C 停止\n')
  })
}

// ---------------------------------------------------------------- enable / disable

function cmdEnable(args) {
  const port = args.port ?? DEFAULT_PORT
  if (!existsSync(ZIP_PATH)) fail(`未找到 ${ZIP_PATH}，请先运行 build`)
  const url = `http://127.0.0.1:${port}/connectors-config.zip`
  writeJson(OVERRIDE_FILE, {
    connectorMarketplaceUrl: url,
    connectorMarketplaceInternalUrl: url,
  })
  ok(`写入覆盖配置：${OVERRIDE_FILE}`)
  info(`connectorMarketplaceUrl = ${url}`)

  if (existsSync(MARKET_META)) {
    rmSync(MARKET_META, { force: true })
    ok(`已清除市场指纹，触发重新同步：${MARKET_META}`)
  } else {
    info('市场指纹本就不存在，客户端下次启动会重新下载')
  }

  console.log('\n现在重启 WorkBuddy（或在连接器中心手动刷新），即可在连接器列表看到 JumpServer。')
  console.log('验证完成后执行 npm run market:disable 恢复官方市场。\n')
}

function cmdDisable() {
  let removed = 0
  for (const f of [OVERRIDE_FILE, MARKET_META]) {
    if (existsSync(f)) {
      rmSync(f, { force: true })
      ok(`已删除 ${f}`)
      removed += 1
    }
  }
  if (removed === 0) info('没有需要清理的覆盖配置')
  console.log('\n重启 WorkBuddy 后会重新从官方地址拉取连接器市场。\n')
}

// ---------------------------------------------------------------- status

function cmdStatus() {
  console.log('\n本地连接器市场状态\n')
  const rows = [
    ['官方市场基线', BASELINE_MANIFEST, '客户端下载的 184 个连接器索引'],
    ['构建产物 zip', ZIP_PATH, '供本地服务分发'],
    ['本地服务目录', OUT_DIR, 'zip 解压后的内容'],
    ['覆盖配置', OVERRIDE_FILE, '指向本机市场地址'],
    ['市场指纹', MARKET_META, '存在则说明上次是官方同步'],
  ]
  for (const [label, path, note] of rows) {
    const exists = existsSync(path)
    console.log(`${exists ? '\x1b[32m[存在]\x1b[0m' : '\x1b[90m[缺失]\x1b[0m'} ${label}`)
    info(`${path}`)
    info(`\x1b[90m${note}\x1b[0m`)
  }

  if (existsSync(OVERRIDE_FILE)) {
    console.log('\n当前覆盖配置：')
    console.log(readFileSync(OVERRIDE_FILE, 'utf8'))
  }
  if (existsSync(ZIP_PATH)) {
    const s = statSync(ZIP_PATH)
    console.log(`\nzip 大小：${(s.size / 1024 / 1024).toFixed(1)} MB`)
    console.log(`zip 修改时间：${s.mtime.toISOString()}`)
  }
  if (existsSync(join(OUT_DIR, 'connectors'))) {
    const n = readdirSync(join(OUT_DIR, 'connectors')).length
    console.log(`构建目录内连接器数量：${n}`)
  }
  console.log('')
}

// ---------------------------------------------------------------- main

const args = parseArgs(process.argv.slice(2))
const cmd = args._[0]

switch (cmd) {
  case 'build':
    cmdBuild(args)
    break
  case 'serve':
    cmdServe(args)
    break
  case 'enable':
    cmdEnable(args)
    break
  case 'disable':
    cmdDisable()
    break
  case 'status':
    cmdStatus()
    break
  default:
    console.log(`
用法：node scripts/local-connector-market.mjs <命令> [选项]

  build [--release]    构建本地市场 zip（默认 dev 模式，跑本机 lib/server.js）
  serve [--port N]     起本地 HTTP 市场服务（默认 ${DEFAULT_PORT}）
  enable [--port N]    写入覆盖配置并清除指纹，触发 WorkBuddy 重同步
  disable              撤销覆盖，恢复官方连接器市场
  status               查看当前状态
`)
    process.exit(cmd ? 1 : 0)
}
