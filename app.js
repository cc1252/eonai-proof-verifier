import {verifyResponse} from './verifier.js';
import {POLICY} from './policy.js';
const $=id=>document.getElementById(id);
$('pcr').textContent=POLICY.pcr0;
const select=$('expected-model');
for(const [model,entry] of Object.entries(POLICY.models||{[POLICY.model]:POLICY})) {
 const option=document.createElement('option');option.value=model;option.textContent=model;select.append(option);
}
select.value='claude-opus-5-5';
let generation=0;
function invalidate(){generation++;$('result').hidden=true;$('progress').textContent='';$('progress').className='';$('verify').disabled=false;}
select.addEventListener('change',invalidate);
$('response').addEventListener('change',()=>{invalidate();$('paste').value='';$('filename').textContent=$('response').files[0]?.name||'尚未选择文件';});
$('paste').addEventListener('input',()=>{invalidate();$('response').value='';$('filename').textContent='使用粘贴的响应';});
$('request').addEventListener('change',invalidate);
$('clear').addEventListener('click',()=>{invalidate();$('response').value='';$('request').value='';$('paste').value='';$('filename').textContent='尚未选择文件';});
$('verify').addEventListener('click',async()=>{
 const current=++generation;$('verify').disabled=true;$('result').hidden=true;$('progress').className='';$('progress').textContent='正在本机核对证书与签名…';
 try{
  const file=$('response').files[0],req=$('request').files[0];
  if(file&&file.size>8*1024*1024)throw new Error('响应文件超过 8 MiB');
  if(req&&req.size>1024*1024)throw new Error('请求文件超过 1 MiB');
  const response=file?new Uint8Array(await file.arrayBuffer()):new TextEncoder().encode($('paste').value);
  if(!response.length)throw new Error('请先选择文件或粘贴完整响应');
  const selected=POLICY.models?.[select.value]||POLICY;
  const result=await verifyResponse(response,{...selected,pcr0:POLICY.pcr0,model:select.value},req?new Uint8Array(await req.arrayBuffer()):undefined);
  if(current!==generation)return;
  $('verdict').textContent=result.ok?'验证通过':'验证未通过';
  $('scope').textContent=result.ok?(result.mode==='full'?'来源、响应及原始请求字节均通过核验。':'官方来源和响应正文核验通过；未验证供应商收到的请求与原始请求完全一致。'):'至少一项检查失败，请勿把这条响应当作已验证结果。';
  $('host').textContent=result.ok?result.host:'未确认';$('model').textContent=result.ok?result.model:'未确认';$('mode').textContent=result.mode==='full'?'来源、响应与请求':'来源与响应';
  $('checks').replaceChildren(...result.checks.map(check=>{const li=document.createElement('li');li.className=check.ok?'pass':'fail';li.textContent=(check.ok?'✓ ':'✕ ')+check.name;return li;}));
  $('result').className='result '+(result.ok?'passed':'failed');$('result').hidden=false;$('progress').textContent='本机验证完成';
 }catch(error){if(current===generation){$('progress').textContent=error.message;$('progress').className='fail';}}
 finally{if(current===generation)$('verify').disabled=false;}
});
