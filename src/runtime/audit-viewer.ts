/**
 * Embedded ops console (MCP V0.3.0) — one local page served from inside the
 * MCP process. Tabs:
 *   实时终端  live per-conversation PTY mirror (redacted stream from TerminalObserver)
 *   审计日志  JSONL audit table + filter + JSONL/CSV export
 *   统计      risk / target / operation / daily aggregates
 *   会话      active sessions + disconnect buttons
 *
 * V0.3.1 behavior:
 *   - one console per conversation: when the configured port is taken (another
 *     conversation's MCP process holds it), fall back to an ephemeral port so
 *     every conversation gets its OWN live console with its OWN data.
 *   - NO external browser launch, ever. An MCP server has no way to raise UI in
 *     the host app; only the host (WorkBuddy) can open its preview panel, and
 *     that happens through the model handover, see consoleHintForModel().
 *   - every instance heartbeats a discovery file under data/consoles/<pid>.json
 *     so any external process can enumerate the live consoles and their ports.
 *   - the page detects a dead server (conversation ended => process gone) and
 *     shows an "expired" overlay, attempting to close itself.
 */
import http from 'node:http'
import { mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { SessionRegistry } from '../jumpserver/session-registry.js'
import type { TerminalEvent } from '../jumpserver/terminal-observer.js'

export interface AuditViewerOptions {
  enabled: boolean
  port: number
  autoOpen: boolean
  /** EADDRINUSE => take an ephemeral port instead of sharing another process's console (default true). */
  portFallback: boolean
}

/** Terminal events sent to the page per poll (tail; older events are dropped). */
const TERMINAL_TAIL_EVENTS = 400
/** Max lines kept per session in the page (client side). */
const TERMINAL_MAX_LINES = 2000
/** Consecutive failed polls before the page declares the server dead. */
const DEAD_AFTER_FAILURES = 6

let viewerUrl: string | null = null
/** Discovery-file dir + our own file, written on every heartbeat. */
let consoleDir: string | null = null
let consoleFile: string | null = null
/** Whether this process hands its console URL to the model (config: auditViewer.autoOpen). */
let hintEnabled = true

/** Parse the JSONL audit sink; a missing or partially written file yields what is readable. */
export function readAuditEntries(file: string): Record<string, unknown>[] {
  try {
    const text = readFileSync(file, 'utf8')
    return text
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => {
        try {
          return JSON.parse(line) as Record<string, unknown>
        } catch {
          return null
        }
      })
      .filter(Boolean) as Record<string, unknown>[]
  } catch {
    return []
  }
}

function page(): string {
  return `<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>JumpServer MCP 控制台</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#141414;color:#ddd;font:13px/1.6 "JetBrains Mono","Cascadia Code",Consolas,monospace}
header{position:sticky;top:0;background:#1b1b1b;border-bottom:1px solid #2a2a2a;padding:8px 12px;display:flex;gap:10px;align-items:center;z-index:5;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}
header::-webkit-scrollbar{display:none}
.dot{width:8px;height:8px;border-radius:50%;background:#1d9e75;animation:pulse 2s infinite;flex:none}
@keyframes pulse{50%{opacity:.4}}
header h1{font-size:14px;margin:0;font-weight:500;color:#fff;white-space:nowrap;flex:none}
nav{display:flex;gap:4px;flex:none}
nav button{background:transparent;border:1px solid transparent;color:#999;padding:4px 10px;border-radius:6px;font:inherit;cursor:pointer;white-space:nowrap}
nav button:hover{color:#ddd}
nav button.on{background:#2a2a2a;color:#fff;border-color:#3a3a3a}
#stat{color:#777;font-size:12px;margin-left:auto;white-space:nowrap;flex:none;padding-left:10px}
main{padding:12px 16px}
section{display:none}section.on{display:block}
input[type=text]{background:#222;border:1px solid #333;color:#ddd;padding:4px 10px;border-radius:6px;outline:none}
button.act{background:#24313c;border:1px solid #35505f;color:#9fd3ee;padding:4px 12px;border-radius:6px;font:inherit;cursor:pointer;white-space:nowrap}
button.act:hover{background:#2c3f4d}
button.warn{background:#3a2424;border-color:#5f3535;color:#ee9f9f}
.tw{overflow-x:auto}
table{border-collapse:collapse;min-width:640px;width:100%}
th{position:sticky;top:0;background:#1b1b1b;text-align:left;padding:8px 12px;color:#888;font-weight:400;font-size:12px;border-bottom:1px solid #2a2a2a}
td{padding:6px 12px;border-bottom:1px solid #222;vertical-align:top}
tr:hover td{background:#1d1d1d}
.time{color:#888;white-space:nowrap}
.op{color:#7fb3e8;white-space:nowrap}
.tgt{color:#c9a86a;white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis}
.risk{white-space:nowrap}
.risk-READ{color:#7fc98f}.risk-PRIVILEGED_READ{color:#c9c37f}.risk-UNKNOWN{color:#bbb}.risk-MODIFY{color:#e8a86a}.risk-DANGEROUS{color:#e87f7f}
.cmd{color:#a8d8a8;word-break:break-all}
#empty{padding:40px;text-align:center;color:#666}
.termbox{background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;padding:10px;height:calc(100vh - 170px);overflow-y:auto;white-space:pre-wrap;word-break:break-all;font-size:12.5px;line-height:1.45}
.t-out{color:#cfe3cf}.t-in{color:#e8d47f}.t-sys{color:#6fa8c9}.t-err{color:#e87f7f}
.sessbar{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.sesschip{background:#222;border:1px solid #333;border-radius:6px;padding:2px 10px;cursor:pointer;color:#999;white-space:nowrap}
.sesschip.on{border-color:#3f6d8a;color:#9fd3ee}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.card{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:8px;padding:10px 16px;min-width:110px}
.card .n{font-size:22px;color:#fff}
.card .l{color:#888;font-size:12px}
.grp{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:8px;padding:12px 16px;margin-bottom:12px;overflow-x:auto}
.grp h3{margin:0 0 8px;font-size:13px;color:#ccc;font-weight:500;white-space:nowrap}
.bar{display:flex;align-items:center;gap:10px;margin:3px 0;min-width:420px}
.bar .lab{width:200px;color:#aaa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:right;flex:none}
.bar .track{flex:1;background:#222;border-radius:4px;height:14px;overflow:hidden}
.bar .fill{height:100%;background:#3f6d8a;display:block}
.bar .cnt{width:60px;color:#888;flex:none}
#dead{position:fixed;inset:0;background:rgba(10,10,10,.92);z-index:50;display:none;align-items:center;justify-content:center;flex-direction:column;gap:14px}
#dead .t{font-size:16px;color:#e8a86a}
#dead .d{color:#999;font-size:13px;max-width:420px;text-align:center}
@media (max-width:720px){
  header h1{display:none}
  #stat{display:none}
  nav button{padding:3px 7px;font-size:12px}
  main{padding:8px}
}
</style></head><body>
<header>
  <div class="dot"></div><h1>JumpServer MCP 控制台</h1>
  <nav>
    <button data-tab="terminal">实时终端</button>
    <button data-tab="audit">审计日志</button>
    <button data-tab="stats">统计</button>
    <button data-tab="sessions">会话</button>
  </nav>
  <span id="stat">loading…</span>
</header>
<main>

<section id="tab-terminal">
  <div class="sessbar" id="sesschips"></div>
  <div class="termbox" id="term"></div>
</section>

<section id="tab-audit">
  <div class="sessbar">
    <input type="text" id="filter" placeholder="过滤：命令 / 资产 / 操作类型 / 风险" style="width:280px">
    <button class="act" id="exp-jsonl">导出 JSONL</button>
    <button class="act" id="exp-csv">导出 CSV</button>
  </div>
  <div class="tw"><table><thead><tr><th style="width:165px">时间</th><th style="width:125px">操作</th><th style="width:185px">目标</th><th style="width:140px">风险 / 结果</th><th>命令</th></tr></thead>
  <tbody id="rows"></tbody></table></div>
  <div id="empty">暂无审计记录</div>
</section>

<section id="tab-stats">
  <div class="cards" id="cards"></div>
  <div class="grp"><h3>按目标资产（Top 10）</h3><div id="by-target"></div></div>
  <div class="grp"><h3>按风险等级</h3><div id="by-risk"></div></div>
  <div class="grp"><h3>按操作类型</h3><div id="by-op"></div></div>
  <div class="grp"><h3>近 14 天</h3><div id="by-day"></div></div>
</section>

<section id="tab-sessions">
  <div class="sessbar">
    <button class="act warn" id="close-all">断开全部会话</button>
    <span style="color:#777;font-size:12px">断开会释放 SSH/PTY；AI 侧下次调用工具会自动重连。</span>
  </div>
  <div class="tw"><table><thead><tr><th style="width:200px">会话</th><th style="width:150px">状态</th><th style="width:190px">当前资产</th><th style="width:120px">权限模式</th><th style="width:170px">最近使用</th><th></th></tr></thead>
  <tbody id="srows"></tbody></table></div>
</section>

</main>
<div id="dead"><div class="t">工作台已失效</div><div class="d">对应的对话已结束，服务进程已退出。本页不会再更新，可以关闭。</div><button class="act" id="dead-close">关闭本页</button></div>
<script>
var tab = (location.hash || '#audit').slice(1);
var auditAll = [], lastCount = -1;
var trackedSeq = {}, currentSess = null, sessStatus = {}, termLines = 0;
var failCount = 0, deadShown = false;
function $(id){return document.getElementById(id);}
function esc(s){return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function stripAnsi(s){return String(s == null ? '' : s).replace(/\\x1b\\[[0-9;?]*[A-Za-z]/g,'').replace(/[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f]/g,'');}
function shortId(id){return id.length > 22 ? id.slice(0,8) + '…' + id.slice(-10) : id;}
function labelId(id){return id === 'anonymous' ? '当前对话' : shortId(id);}
function fmtTime(ts){return String(ts == null ? '' : ts).replace('T',' ').slice(0,19);}
function showDead(){
  if (deadShown) return; deadShown = true;
  $('dead').style.display = 'flex';
}
$('dead-close').addEventListener('click', function(){ window.close(); });
/* fetch wrapper: any success resets the dead-counter; N misses => expired overlay */
function F(u,o){
  return fetch(u,o).then(function(r){failCount=0;return r;}).catch(function(e){failCount++;if(failCount>=${DEAD_AFTER_FAILURES})showDead();throw e;});
}

/* ---- tabs ---- */
function showTab(name){
  tab = name; location.hash = name;
  var secs = document.querySelectorAll('section');
  for (var i=0;i<secs.length;i++) secs[i].className = (secs[i].id === 'tab-'+name) ? 'on' : '';
  var btns = document.querySelectorAll('nav button');
  for (var j=0;j<btns.length;j++) btns[j].className = (btns[j].getAttribute('data-tab')===name)?'on':'';
  if (name==='audit') pollAudit();
  if (name==='stats') pollStats();
  if (name==='sessions') pollSessions();
}
var navBtns = document.querySelectorAll('nav button');
for (var b=0;b<navBtns.length;b++){
  (function(btn){btn.addEventListener('click',function(){showTab(btn.getAttribute('data-tab'));});})(navBtns[b]);
}
showTab(['terminal','audit','stats','sessions'].indexOf(tab)>=0?tab:'audit');

/* ---- terminal ---- */
function renderChips(list){
  var el = $('sesschips');
  if (!list.length){ el.innerHTML = '<span style="color:#666">当前没有活动会话 —— 在对话里用 jumpserver 工具连接后，这里会出现实时终端。</span>'; return; }
  var exists = false;
  for (var i=0;i<list.length;i++) if (list[i].id===currentSess) exists = true;
  if (!exists) currentSess = list[0].id;
  el.innerHTML = list.map(function(s){
    var st = s.status || {};
    var label = labelId(s.id) + ' · ' + (st.state||'?') + (st.target? ' · '+st.target : '');
    return '<span class="sesschip'+(s.id===currentSess?' on':'')+'" data-id="'+esc(s.id)+'" title="'+esc(s.id)+'">'+esc(label)+'</span>';
  }).join('');
  var chips = el.querySelectorAll('.sesschip');
  for (var j=0;j<chips.length;j++){
    (function(ch){ch.addEventListener('click',function(){currentSess=ch.getAttribute('data-id');$('term').innerHTML='';termLines=0;renderChips(list);});})(chips[j]);
  }
}
function appendTerm(sess, events){
  if (sess !== currentSess) return;
  var box = $('term');
  var stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  for (var i=0;i<events.length;i++){
    var e = events[i]; var cls='t-out', txt='';
    if (e.type==='output'){cls='t-out';txt=stripAnsi(e.data);}
    else if (e.type==='input'){cls='t-in';txt='▸ '+stripAnsi(e.data);}
    else if (e.type==='state'){cls='t-sys';txt='── '+(e.prev||'?')+' → '+e.state;}
    else if (e.type==='target'){cls='t-sys';txt='── 进入 '+e.target+(e.hostname?(' ('+e.hostname+')'):'');}
    else if (e.type==='error'){cls='t-err';txt='!! '+e.message;}
    var div=document.createElement('div');div.className=cls;div.appendChild(document.createTextNode(txt));
    box.appendChild(div);termLines++;
  }
  while (termLines > ${TERMINAL_MAX_LINES} && box.firstChild){box.removeChild(box.firstChild);termLines--;}
  if (stick) box.scrollTop = box.scrollHeight;
}
function pollTerminal(){
  if (tab!=='terminal'){setTimeout(pollTerminal,1000);return;}
  var min = Infinity;
  for (var k in trackedSeq) if (trackedSeq[k]<min) min=trackedSeq[k];
  F('/api/terminal?since='+(min===Infinity?0:min)).then(function(r){return r.json();}).then(function(j){
    var list=j.sessions||[];
    renderChips(list);
    for (var i=0;i<list.length;i++){
      var s=list[i];
      sessStatus[s.id]=s.status;
      var mine=(s.events||[]).filter(function(e){return e.seq>(trackedSeq[s.id]||0);});
      appendTerm(s.id,mine);
      trackedSeq[s.id]=s.lastSeq||trackedSeq[s.id]||0;
    }
    var st=sessStatus[currentSess];
    $('stat').textContent = st ? ('state='+st.state+' target='+(st.target||'none')+' mode='+st.permissionMode) : (list.length+' 会话');
  }).catch(function(){});
  setTimeout(pollTerminal,1000);
}
pollTerminal();

/* ---- audit ---- */
function renderAudit(){
  var q=$('filter').value.toLowerCase();
  var list=q?auditAll.filter(function(e){return JSON.stringify(e).toLowerCase().indexOf(q)>=0;}):auditAll;
  var rows=list.slice().reverse().map(function(e){
    var tgt=e.target||e.hostname||'-';
    var cmd=e.redactedCommand||e.command||'-';
    var risk=esc(e.risk||'?');
    return '<tr><td class="time">'+esc(fmtTime(e.timestamp))+'</td>'
      +'<td class="op">'+esc(e.operation)+'</td>'
      +'<td class="tgt" title="'+esc(tgt)+'">'+esc(tgt)+'</td>'
      +'<td class="risk risk-'+risk+'">'+risk+' / '+esc(e.result||'?')+'</td>'
      +'<td class="cmd">'+esc(cmd)+'</td></tr>';
  }).join('');
  $('rows').innerHTML=rows;
  $('empty').style.display=list.length?'none':'block';
  $('stat').textContent='审计 '+auditAll.length+' 条'+(q?' / 匹配 '+list.length:'');
  lastCount=auditAll.length;
}
function pollAudit(){
  if (tab!=='audit') return;
  F('/api/entries').then(function(r){return r.json();}).then(function(j){
    if (j.length!==auditAll.length){auditAll=j;renderAudit();}else{auditAll=j;}
  }).catch(function(){});
}
setInterval(pollAudit,1000);
$('filter').addEventListener('input',renderAudit);
function download(name,mime,text){
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([text],{type:mime}));
  a.download=name;a.click();URL.revokeObjectURL(a.href);
}
$('exp-jsonl').addEventListener('click',function(){
  download('jumpserver-audit.jsonl','application/json',auditAll.map(function(e){return JSON.stringify(e);}).join('\\n'));
});
$('exp-csv').addEventListener('click',function(){
  var cols=['timestamp','operation','actor','target','hostname','risk','result','exitCode','durationMs','redactedCommand'];
  var q=function(v){v=v==null?'':String(v);return /[",\\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  var lines=[cols.join(',')];
  auditAll.forEach(function(e){lines.push(cols.map(function(c){return q(e[c]);}).join(','));});
  download('jumpserver-audit.csv','text/csv','\\ufeff'+lines.join('\\n'));
});

/* ---- stats ---- */
function bars(el,rows){
  if (!rows.length){el.innerHTML='<span style="color:#666">暂无数据</span>';return;}
  var max=rows[0][1]||1;
  el.innerHTML=rows.map(function(r){
    return '<div class="bar"><span class="lab" title="'+esc(r[0])+'">'+esc(r[0])+'</span>'
      +'<span class="track"><span class="fill" style="width:'+Math.round(r[1]/max*100)+'%"></span></span>'
      +'<span class="cnt">'+r[1]+'</span></div>';
  }).join('');
}
function topN(map,n){
  var arr=[];for (var k in map) arr.push([k,map[k]]);
  arr.sort(function(a,b){return b[1]-a[1];});
  return arr.slice(0,n||10);
}
function pollStats(){
  if (tab!=='stats') return;
  F('/api/stats').then(function(r){return r.json();}).then(function(s){
    var fail=s.failed||0;
    $('cards').innerHTML=
      '<div class="card"><div class="n">'+s.total+'</div><div class="l">审计总数</div></div>'
      +'<div class="card"><div class="n" style="color:'+(fail?'#e8a86a':'#7fc98f')+'">'+fail+'</div><div class="l">失败 / 受阻</div></div>'
      +'<div class="card"><div class="n">'+s.targets+'</div><div class="l">涉及资产</div></div>'
      +'<div class="card"><div class="n">'+s.days+'</div><div class="l">活跃天数</div></div>';
    bars($('by-target'),topN(s.byTarget,10));
    bars($('by-risk'),topN(s.byRisk,10));
    bars($('by-op'),topN(s.byOperation,10));
    bars($('by-day'),s.byDay.slice(-14));
  }).catch(function(){});
}
setInterval(pollStats,3000);

/* ---- sessions ---- */
function pollSessions(){
  if (tab!=='sessions') return;
  F('/api/sessions').then(function(r){return r.json();}).then(function(list){
    $('srows').innerHTML = list.length ? list.map(function(s){
      var st=s.status||{};
      return '<tr><td title="'+esc(s.id)+'">'+esc(labelId(s.id))+'</td>'
        +'<td>'+esc(st.state||'?')+'</td>'
        +'<td class="tgt">'+esc(st.target||'-')+(st.hostname?' ('+esc(st.hostname)+')':'')+'</td>'
        +'<td>'+esc(st.permissionMode||'-')+'</td>'
        +'<td class="time">'+new Date(s.lastUsedAt).toLocaleString()+'</td>'
        +'<td><button class="act warn" data-id="'+esc(s.id)+'">断开</button></td></tr>';
    }).join('') : '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px">无活动会话</td></tr>';
    var btns=$('srows').querySelectorAll('button');
    for (var i=0;i<btns.length;i++){
      (function(btn){btn.addEventListener('click',function(){
        if (!confirm('断开该会话？')) return;
        F('/api/sessions/close',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sessionId:btn.getAttribute('data-id')})})
          .then(function(){pollSessions();}).catch(function(){});
      });})(btns[i]);
    }
  }).catch(function(){});
}
setInterval(pollSessions,2000);
$('close-all').addEventListener('click',function(){
  if (!confirm('断开全部 JumpServer 会话？')) return;
  F('/api/sessions/close',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"all":true}'})
    .then(function(){pollSessions();}).catch(function(){});
});
</script></body></html>`
}

function sendJson(res: import('node:http').ServerResponse, data: unknown): void {
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(data))
}

function readBody(req: import('node:http').IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let text = ''
    req.on('data', (chunk: Buffer) => {
      text += chunk.toString('utf8')
      if (text.length > 65536) req.destroy()
    })
    req.on('end', () => {
      try {
        resolve(JSON.parse(text) as Record<string, unknown>)
      } catch {
        resolve({})
      }
    })
    req.on('error', () => resolve({}))
  })
}

function lastSeqOf(events: TerminalEvent[]): number {
  return events.length > 0 ? (events[events.length - 1]?.seq ?? 0) : 0
}

/**
 * There is NO browser launch here on purpose. A MCP server runs as a detached
 * child process: any shell-open it performs lands in the OS default browser
 * (Chrome/Edge), not in the WorkBuddy preview panel. The only available path is
 * a handover to the model — see consoleHintForModel() — which then opens the
 * URL through the host's own preview surface.
 */

/**
 * Instruction block handed to the model on the first tool response of this
 * process. `present_files` with a localhost URL opens the WorkBuddy built-in
 * preview panel — that is the ONLY way to surface this console in-app.
 */
export function consoleHintForModel(): string | null {
  const url = auditViewerUrl()
  if (url === null || hintEnabled !== true) return null
  return (
    '[jumpserver-console] 本对话的 JumpServer 工作台: ' + url + '\n' +
    '请立即调用 present_files 打开这个 URL（会显示在 WorkBuddy 内置预览面板里，实时终端/审计/统计/会话四个页签）。\n' +
    '禁止改用系统浏览器打开（不要 rundll32 / start / explorer / 外部浏览器），每个对话端口独立，关掉对话即失效。'
  )
}

/**
 * Start the embedded console. Returns the intended URL, or null when disabled.
 * `registry` powers the live-terminal / session tabs; pass null for an
 * audit-only mirror. When the configured port is taken and portFallback is
 * on, an ephemeral port is used so every conversation keeps its own console.
 */
export function startAuditViewer(
  auditPath: string,
  opts: AuditViewerOptions,
  registry: SessionRegistry | null,
): string | null {
  if (opts.enabled !== true) return null
  hintEnabled = opts.autoOpen
  consoleDir = join(dirname(auditPath), 'consoles')
  const server = http.createServer((req, res) => {
    void (async () => {
      const target = req.url ?? '/'
      const href = target.split('?')[0] ?? '/'
      const query = new URLSearchParams(target.split('?')[1] ?? '')
      if (href === '/api/entries') {
        sendJson(res, readAuditEntries(auditPath))
        return
      }
      if (href === '/api/stats') {
        const entries = readAuditEntries(auditPath)
        const byRisk: Record<string, number> = {}
        const byOperation: Record<string, number> = {}
        const byTarget: Record<string, number> = {}
        const byDayMap: Record<string, number> = {}
        let failed = 0
        for (const e of entries) {
          const risk = String(e['risk'] ?? '?')
          const op = String(e['operation'] ?? '?')
          const targetName = String(e['target'] ?? e['hostname'] ?? '(未进入资产)')
          const day = String(e['timestamp'] ?? '').slice(0, 10)
          byRisk[risk] = (byRisk[risk] ?? 0) + 1
          byOperation[op] = (byOperation[op] ?? 0) + 1
          byTarget[targetName] = (byTarget[targetName] ?? 0) + 1
          if (day.length > 0) byDayMap[day] = (byDayMap[day] ?? 0) + 1
          const approvalPending = e['approvalRequired'] === true && String(e['approvalResult']) === 'pending'
          if (String(e['result'] ?? '') !== 'COMPLETED' || approvalPending) failed += 1
        }
        const byDay = Object.keys(byDayMap).sort().map((d) => [d.slice(5), byDayMap[d] ?? 0] as [string, number])
        sendJson(res, {
          total: entries.length,
          failed,
          targets: Object.keys(byTarget).length,
          days: byDay.length,
          byRisk,
          byOperation,
          byTarget,
          byDay,
        })
        return
      }
      if (href === '/api/sessions') {
        if (registry === null) {
          sendJson(res, [])
          return
        }
        const list: unknown[] = []
        for (const [id, bundle] of registry.snapshot()) {
          list.push({ id, status: bundle.manager.status(), lastUsedAt: bundle.lastUsedAt, lastSeq: lastSeqOf(bundle.observer.snapshot()) })
        }
        sendJson(res, list)
        return
      }
      if (href === '/api/sessions/close' && req.method === 'POST') {
        if (registry === null) {
          sendJson(res, { closed: 0 })
          return
        }
        const body = await readBody(req)
        let closed = 0
        const ids: string[] = body['all'] === true
          ? [...registry.snapshot().keys()]
          : [String(body['sessionId'] ?? '')]
        await Promise.all(ids.map(async (id) => {
          const bundle = registry.get(id)
          if (bundle === undefined) return
          try {
            await bundle.manager.close()
            closed += 1
          } catch {
            /* close failures must not 500 the console */
          }
        }))
        sendJson(res, { closed })
        return
      }
      if (href === '/api/terminal') {
        if (registry === null) {
          sendJson(res, { sessions: [] })
          return
        }
        const since = Math.max(0, Math.floor(Number(query.get('since') ?? '0')) || 0)
        const sessions: unknown[] = []
        for (const [id, bundle] of registry.snapshot()) {
          let events = bundle.observer.snapshotSince(since)
          if (events.length > TERMINAL_TAIL_EVENTS) events = events.slice(-TERMINAL_TAIL_EVENTS)
          sessions.push({ id, status: bundle.manager.status(), lastSeq: lastSeqOf(bundle.observer.snapshot()), events })
        }
        sendJson(res, { sessions })
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(page())
    })().catch(() => {
      try {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end('console error')
      } catch {
        /* response already gone */
      }
    })
  })
  server.on('error', (error) => {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'EADDRINUSE' && opts.portFallback !== false) {
      // Another conversation holds the configured port — take an ephemeral one
      // so THIS conversation keeps its own live console.
      try {
        server.listen(0, '127.0.0.1')
      } catch {
        console.error('[jumpserver-mcp] ops console: fallback listen failed')
      }
      return
    }
    console.error('[jumpserver-mcp] ops console: ' + (error instanceof Error ? error.message : String(error)))
  })
  server.on('listening', () => {
    const address = server.address()
    const port = typeof address === 'object' && address !== null ? address.port : opts.port
    viewerUrl = 'http://127.0.0.1:' + String(port) + '/'
    if (port !== opts.port) {
      console.error('[jumpserver-mcp] ops console: port ' + String(opts.port) + ' busy, using ' + viewerUrl)
    } else {
      console.error('[jumpserver-mcp] ops console: ' + viewerUrl)
    }
    startHeartbeat(port)
  })
  try {
    server.listen(opts.port, '127.0.0.1')
  } catch (error) {
    console.error('[jumpserver-mcp] ops console: ' + (error instanceof Error ? error.message : String(error)))
  }
  server.unref?.()
  return 'http://127.0.0.1:' + String(opts.port) + '/'
}

/**
 * Heartbeat a per-process discovery file:
 *   data/consoles/<pid>.json = { pid, port, url, startedAt, heartbeatAt }
 * Stale files (heartbeat older than 20s => the conversation/process is gone)
 * are pruned, so external tools can enumerate live consoles by listing the dir.
 */
function startHeartbeat(port: number): void {
  if (consoleDir === null || viewerUrl === null) return
  const startedAt = new Date().toISOString()
  const pid = process.pid
  try {
    mkdirSync(consoleDir, { recursive: true })
    consoleFile = join(consoleDir, String(pid) + '.json')
  } catch {
    return
  }
  const write = (): void => {
    if (consoleFile === null) return
    try {
      writeFileSync(consoleFile, JSON.stringify({
        pid,
        port,
        url: viewerUrl,
        startedAt,
        heartbeatAt: new Date().toISOString(),
      }) + '\n', 'utf8')
    } catch {
      /* discovery file is best-effort */
    }
  }
  write()
  const timer = setInterval(() => {
    write()
    pruneStale()
  }, 5_000)
  timer.unref?.()
  process.once('exit', () => {
    try {
      if (consoleFile !== null) unlinkSync(consoleFile)
    } catch {
      /* already gone */
    }
  })
}

function pruneStale(): void {
  if (consoleDir === null) return
  try {
    const names = readdirSync(consoleDir)
    const now = Date.now()
    for (const name of names) {
      if (!name.endsWith('.json')) continue
      const file = join(consoleDir, name)
      try {
        const raw = JSON.parse(readFileSync(file, 'utf8')) as { heartbeatAt?: string }
        const age = now - Date.parse(raw.heartbeatAt ?? '')
        if (!Number.isFinite(age) || age > 20_000) unlinkSync(file)
      } catch {
        try {
          unlinkSync(file)
        } catch {
          /* concurrent delete */
        }
      }
    }
  } catch {
    /* console dir may not exist yet */
  }
}

/** Audit hook kept for API compatibility: console opening is model-driven now. */
export function notifyAuditRecord(): void {
  /* no-op: see consoleHintForModel() */
}

/** Current console URL (null until the listener is bound / when disabled). */
export function auditViewerUrl(): string | null {
  return viewerUrl
}
