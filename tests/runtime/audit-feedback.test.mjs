import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AuditFeedbackStore, auditFeedbackId } from '../../lib/runtime/audit-feedback.js'
import { startAuditViewer, stopAuditViewer } from '../../lib/runtime/audit-viewer.js'

test('人工反馈独立持久化、撤销、损坏文件拒写', () => {
  const dir=mkdtempSync(join(tmpdir(),'audit-feedback-'))
  const file=join(dir,'feedback.jsonl'), id=auditFeedbackId({ command:'secret' })
  const store=new AuditFeedbackStore(file)
  assert.deepEqual(store.list(),[])
  store.set(id,true)
  assert.equal(new AuditFeedbackStore(file).list()[0].falsePositive,true)
  store.set(id,false)
  assert.equal(store.list()[0].falsePositive,false)
  assert.equal(readFileSync(file,'utf8').includes('secret'),false)
  assert.throws(()=>store.set('../audit.jsonl',true))
  writeFileSync(file,'invalid')
  assert.throws(()=>store.set(id,true))
  assert.equal(readFileSync(file,'utf8'),'invalid')
})

test('真实HTTP反馈鉴权、标记撤销、脱敏与页面脚本', async () => {
  const port=await new Promise(resolve=>{const s=http.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p))})})
  const dir=mkdtempSync(join(tmpdir(),'audit-feedback-http-'))
  const audit=join(dir,'audit.jsonl'), file=join(dir,'audit-feedback.jsonl')
  const original=JSON.stringify({timestamp:'2026-10-23T00:00:00Z',command:'password=top-secret<script>',confirm:true,result:'DENIED'})+'\n'
  writeFileSync(audit,original)
  startAuditViewer(audit,{enabled:true,port,autoOpen:false,portFallback:true,stableUrl:true},null)
  const base='http://127.0.0.1:'+port
  try {
    const html=await (await fetch(base)).text()
    for (const [,script] of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) new Function(script)
    assert.match(html,/人工标记为误判/)
    const token=html.match(/\|\| "([0-9a-f]{16,})";/)[1]
    const endpoint=base+'/api/audit/feedback'
    const headers={'content-type':'application/json','x-console-token':token}
    const entries=await (await fetch(base+'/api/entries?token='+token)).json()
    const id=entries[0].feedbackRecordId
    const post=(data,extra={})=>fetch(endpoint,{method:'POST',headers:{...headers,...extra},body:JSON.stringify(data)})
    assert.equal((await (await fetch(endpoint+'?token='+token)).json()).falsePositiveCount,0)
    assert.equal((await fetch(endpoint,{method:'POST',body:'{}'})).status,403)
    assert.equal((await post({recordId:id,falsePositive:true},{origin:'https://evil.example'})).status,403)
    assert.equal(existsSync(file),false)
    assert.equal((await post({recordId:'../audit.jsonl',falsePositive:true})).status,400)
    assert.equal((await post({recordId:'a'.repeat(64),falsePositive:true})).status,404)
    assert.equal((await post({recordId:id,falsePositive:true,note:'secret'})).status,400)
    const marked=await (await post({recordId:id,falsePositive:true})).json()
    assert.equal(marked.falsePositiveCount,1)
    assert.equal(marked.policyChanged,false)
    assert.equal(new AuditFeedbackStore(file).list()[0].actor,'HUMAN')
    assert.equal(readFileSync(file,'utf8').includes('secret'),false)
    const revoked=await (await post({recordId:id,falsePositive:false})).json()
    assert.equal(revoked.falsePositiveCount,0)
    assert.equal(readFileSync(audit,'utf8'),original)
  } finally { stopAuditViewer() }
})
