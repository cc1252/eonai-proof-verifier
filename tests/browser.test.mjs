import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {verifyResponse} from '../verifier.js';
import {POLICY} from '../policy.js';
const encoder=new TextEncoder();
const body='event: message_start\ndata: {"type":"message_start","message":{"model":"claude-opus-5-5"}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n';
const request=encoder.encode('{}'),keys=generateKeyPairSync('ed25519');
const hash=b=>createHash('sha256').update(b).digest('hex');
function fixture(attestation='AA=='){
 const t={v:2,alg:'ed25519',public_key:keys.publicKey.export({format:'der',type:'spki'}).toString('base64'),nonce:'bm9uY2U=',upstream_host:POLICY.host,upstream_path:'/v1/messages',http_method:'POST',http_status:200,resp_content_type:'text/event-stream',request_body_sha256:hash(request),response_body_sha256:hash(body),attestation};
 const statement=['tee-exchange-v2','nonce='+t.nonce,'upstream-host='+t.upstream_host,'upstream-path='+t.upstream_path,'http-method=POST','http-status=200','resp-content-type='+t.resp_content_type,'request-body-sha256='+t.request_body_sha256,'response-body-sha256='+t.response_body_sha256].join('\n')+'\n';
 t.signature=sign(null,Buffer.from(statement),keys.privateKey).toString('base64');
 return encoder.encode(body+'event: tee.proof\ndata: '+JSON.stringify(t)+'\n\n');
}
test('missing proof fails',async()=>assert.rejects(verifyResponse(encoder.encode(body),POLICY),/缺少/));
test('valid synthetic signature cannot masquerade as Nitro hardware',async()=>{
 const result=await verifyResponse(fixture(),POLICY);assert.equal(result.ok,false);assert.equal(result.mode,'response-only');
 assert.equal(result.checks.find(c=>c.name==='Ed25519 声明签名有效').ok,true);
 assert.equal(result.checks.find(c=>c.name==='真实硬件证明与 AWS 根证书链').ok,false);
});
test('body tampering fails',async()=>{const capture=encoder.encode(new TextDecoder().decode(fixture()).replace('message_start','message_stArt'));const result=await verifyResponse(capture,POLICY);assert.equal(result.checks.find(c=>c.name==='响应正文未被篡改').ok,false);});
test('full mode binds exact original request bytes',async()=>{const result=await verifyResponse(fixture(),POLICY,encoder.encode('{ }'));assert.equal(result.mode,'full');assert.equal(result.checks.at(-1).ok,false);});
test('mock attestation objects are rejected',async()=>assert.rejects(verifyResponse(fixture({pcr0:POLICY.pcr0}),POLICY),/字段格式/));
test('truncated and oversized CBOR never passes hardware checks',async()=>{
 for(const raw of [Buffer.from([0x9f,0xff]),Buffer.from([0x9f,0x9f]),Buffer.alloc(262145,0x9f)]){const result=await verifyResponse(fixture(raw.toString('base64')),POLICY);assert.equal(result.ok,false);}
});
test('offline artifact contains no remote scripts or imports',()=>{const html=readFileSync(new URL('../verify-offline.html',import.meta.url),'utf8');assert.ok(!/<script[^>]+src=/i.test(html));assert.ok(!/^import /m.test(html));assert.ok(!/fetch\(/.test(html));});
