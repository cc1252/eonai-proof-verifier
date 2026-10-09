// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from proof-of-observation bf21141f0a76090061d1a0a6709688618ff753c8.
// Browser parser hardening and EonAI policy are modifications; see NOTICE.
// ───────── 与 verifier/signing.ts + verify-attestation-cose.mjs 对齐的规范化（务必逐字节一致）─────────
const te = new TextEncoder();
// v2 字段分解声明的域名(docs/tee-signing-v2-design.md);布局须与 verifier/signing.ts buildV2Statement 逐字节一致。
const SIGNING_DOMAIN_V2 = 'tee-exchange-v2';
const WOKEY_SSE_TRANSPORT_KEEPALIVE_V1 = te.encode(': wokey-transport-keepalive-v1\n\n');
const b64ToBytes = (b)=>{const s=atob(b);const u=new Uint8Array(s.length);for(let i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return u;};
const bytesToB64 = (u)=>{let s='';for(const b of u)s+=String.fromCharCode(b);return btoa(s);};
const bytesToHex = (u)=>Array.from(u).map(b=>b.toString(16).padStart(2,'0')).join('');
const concat = (a)=>{const n=a.reduce((x,y)=>x+y.length,0);const o=new Uint8Array(n);let p=0;for(const x of a){o.set(x,p);p+=x.length;}return o;};
const sha256 = async(b)=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
const td = new TextDecoder();
const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));
const short = (s)=> s && s.length>16 ? s.slice(0,10)+'…'+s.slice(-6) : s;
const textToB64 = (s)=>bytesToB64(te.encode(s));

function isProofWire(o){
  return !!o && typeof o==='object' && o.public_key && o.nonce && o.signature && o.attestation
    && o.upstream_host!==undefined && o.request_body_sha256!==undefined && o.response_body_sha256!==undefined;
}
function startsWithBytes(bytes,prefix,offset=0){
  if(offset<0||offset+prefix.length>bytes.length)return false;
  for(let i=0;i<prefix.length;i++)if(bytes[offset+i]!==prefix[i])return false;
  return true;
}
function findLastBytes(bytes,needle){
  if(!needle.length||needle.length>bytes.length)return -1;
  for(let i=bytes.length-needle.length;i>=0;i--)if(startsWithBytes(bytes,needle,i))return i;
  return -1;
}
function trimSseDataPrefix(line,prefix){
  let p=prefix.length;
  while(p<line.length&&(line[p]===32||line[p]===9))p++;
  return line.subarray(p);
}
function isAsciiWhitespaceByte(b){
  return b===9||b===10||b===13||b===32;
}
function parseProofEventBytes(bytes){
  const markerLf=te.encode('event: tee.proof\n');
  const markerCrLf=te.encode('event: tee.proof\r\n');
  const idx=Math.max(findLastBytes(bytes,markerLf),findLastBytes(bytes,markerCrLf));
  if(idx<0)return null;
  const before=bytes.subarray(0,idx);
  const eventBlock=bytes.subarray(idx);
  const dataPrefix=te.encode('data:');
  const dataLines=[];
  let eventEnd=-1;
  for(let p=0;p<=eventBlock.length;){
    const nl=eventBlock.indexOf(10,p);
    const end=nl>=0?nl:eventBlock.length;
    let line=eventBlock.subarray(p,end);
    if(line.length&&line[line.length-1]===13)line=line.subarray(0,line.length-1);
    if(startsWithBytes(line,dataPrefix))dataLines.push(td.decode(trimSseDataPrefix(line,dataPrefix)));
    else if(line.length===0&&dataLines.length){eventEnd=nl>=0?nl+1:eventBlock.length;break;}
    if(nl<0)break;
    p=nl+1;
  }
  if(!dataLines.length)return null;
  // 容忍最后一个事件缺少结尾空行/换行:流末尾本身即终止该事件(SSE 规范),按 curl 落盘/终端复制常丢尾换行的现实放宽。
  // 仅当未找到终止空行时把事件视作延伸到流末尾;若中途已找到空行后又出现非空白内容,仍按下方校验拒绝(tee.proof 必须是末事件)。
  if(eventEnd<0)eventEnd=eventBlock.length;
  for(let i=eventEnd;i<eventBlock.length;i++)if(!isAsciiWhitespaceByte(eventBlock[i]))return null;
  const proof=JSON.parse(dataLines.join('\n'));
  if(!isProofWire(proof))throw new Error(typeof L==='function'?L('tee.proof data 字段不是有效证明材料','tee.proof data field is not valid proof material'):'tee.proof data 字段不是有效证明材料');
  // The capture starts at byte zero. Exact relay transport keepalives are
  // normalized later only at SSE record boundaries and only when the signed
  // response hash proves the complete removal.
  return {bodyBytes:before,proof};
}
function parseProofEventText(text){
  return parseProofEventBytes(te.encode(text));
}
function parseLooseProofData(text){
  const s=text.trim();
  if(!s)return null;
  const dataMatch=s.match(/^data:\s*(\{[\s\S]*\})\s*$/m);
  const candidate=dataMatch?dataMatch[1]:s;
  try{
    const o=JSON.parse(candidate);
    return isProofWire(o)?o:null;
  }catch{return null;}
}
function findBytes(bytes,needle,offset=0){
  if(!needle.length||needle.length>bytes.length)return -1;
  for(let i=Math.max(0,offset);i<=bytes.length-needle.length;i++)if(startsWithBytes(bytes,needle,i))return i;
  return -1;
}
function consumeLineEnding(bytes,offset){
  if(bytes[offset]===13&&bytes[offset+1]===10)return offset+2;
  if(bytes[offset]===10)return offset+1;
  return -1;
}
function firstMultipartBoundary(bytes){
  const dash=te.encode('--');
  let start=startsWithBytes(bytes,dash,0)?0:-1;
  if(start<0){
    for(let i=0;i<bytes.length;i++){
      if(bytes[i]===10&&startsWithBytes(bytes,dash,i+1)){start=i+1;break;}
    }
  }
  if(start<0)return null;
  const nl=bytes.indexOf(10,start);
  if(nl<0)return null;
  let line=bytes.subarray(start,nl);
  if(line.length&&line[line.length-1]===13)line=line.subarray(0,line.length-1);
  const text=td.decode(line);
  if(!text.startsWith('--')||text.endsWith('--'))return null;
  return {boundary:text.slice(2),offset:start};
}
function stripBoundarySeparatorLineEnding(bytes){
  if(bytes.length>=2&&bytes[bytes.length-2]===13&&bytes[bytes.length-1]===10)return bytes.subarray(0,bytes.length-2);
  if(bytes.length>=1&&bytes[bytes.length-1]===10)return bytes.subarray(0,bytes.length-1);
  return bytes;
}
function isProofPartHeaders(headers){
  return /content-disposition:\s*[^;\r\n]*(?:;\s*)?name="?proof"?/i.test(headers)
    || /content-type:\s*application\/[^;\r\n]*proof[^;\r\n]*/i.test(headers);
}
function readMultipartBoundary(bytes,boundaryBytes,offset){
  if(!startsWithBytes(bytes,boundaryBytes,offset))return null;
  let p=offset+boundaryBytes.length;
  const closing=bytes[p]===45&&bytes[p+1]===45;
  if(closing)p+=2;
  if(closing&&p===bytes.length)return {closing,nextOffset:p};
  const nextOffset=consumeLineEnding(bytes,p);
  if(nextOffset<0)return null;
  return {closing,nextOffset};
}
function multipartHeaderEnd(bytes,offset){
  const crlf=findBytes(bytes,te.encode('\r\n\r\n'),offset);
  const lf=findBytes(bytes,te.encode('\n\n'),offset);
  if(crlf>=0&&(lf<0||crlf<lf))return {headerEnd:crlf,bodyStart:crlf+4};
  if(lf>=0)return {headerEnd:lf,bodyStart:lf+2};
  return null;
}
function multipartContentLength(headers){
  const lines=headers.split(/\r?\n/);
  for(const line of lines){
    const m=line.match(/^content-length:\s*(\d+)\s*$/i);
    if(!m)continue;
    const n=Number.parseInt(m[1],10);
    return Number.isFinite(n)&&n>=0?n:null;
  }
  return null;
}
function readMultipartPart(bytes,boundaryBytes,offset){
  const headerEnd=multipartHeaderEnd(bytes,offset);
  if(!headerEnd)return null;
  const headers=td.decode(bytes.subarray(offset,headerEnd.headerEnd));
  const length=multipartContentLength(headers);
  const bodyStart=headerEnd.bodyStart;
  let bodyEnd=-1, nextBoundaryOffset=-1;
  if(length!==null){
    const expectedEnd=bodyStart+length;
    if(expectedEnd<=bytes.length){
      const expectedNext=consumeLineEnding(bytes,expectedEnd);
      if(expectedNext>=0&&startsWithBytes(bytes,boundaryBytes,expectedNext)){ bodyEnd=expectedEnd; nextBoundaryOffset=expectedNext; }
    }
  }
  if(bodyEnd<0){
    const boundaryText=td.decode(boundaryBytes);
    const crlfBoundary=findBytes(bytes,te.encode('\r\n'+boundaryText),bodyStart);
    const lfBoundary=findBytes(bytes,te.encode('\n'+boundaryText),bodyStart);
    let marker=-1, markerLen=0;
    if(crlfBoundary>=0&&(lfBoundary<0||crlfBoundary<=lfBoundary)){ marker=crlfBoundary; markerLen=2; }
    else if(lfBoundary>=0){ marker=lfBoundary; markerLen=1; }
    if(marker<0)return null;
    bodyEnd=marker;
    nextBoundaryOffset=marker+markerLen;
  }
  return {headers,body:bytes.subarray(bodyStart,bodyEnd),nextBoundaryOffset};
}
function parseProofMultipartBytes(bytes){
  const first=firstMultipartBoundary(bytes);
  if(!first)return null;
  const capture=bytes.subarray(first.offset);
  const boundaryBytes=te.encode('--'+first.boundary);
  const firstBoundary=readMultipartBoundary(capture,boundaryBytes,0);
  if(!firstBoundary||firstBoundary.closing)return null;
  const responsePart=readMultipartPart(capture,boundaryBytes,firstBoundary.nextOffset);
  if(!responsePart)return null;
  const proofBoundary=readMultipartBoundary(capture,boundaryBytes,responsePart.nextBoundaryOffset);
  if(!proofBoundary||proofBoundary.closing){
    if(first.offset<=0||!isProofPartHeaders(responsePart.headers))return null;
    let proof=null, unavailable=null;
    try{
      const parsed=JSON.parse(td.decode(responsePart.body));
      if(isProofWire(parsed))proof=parsed;
      else if(parsed&&parsed.type==='tee.proof_unavailable')unavailable=parsed;
    }catch{}
    return {bodyBytes:stripBoundarySeparatorLineEnding(bytes.subarray(0,first.offset)),proof,unavailable,tail:true};
  }
  const proofPart=readMultipartPart(capture,boundaryBytes,proofBoundary.nextOffset);
  if(!proofPart)return null;
  const closingBoundary=readMultipartBoundary(capture,boundaryBytes,proofPart.nextBoundaryOffset);
  if(!closingBoundary||!closingBoundary.closing)return null;
  let proof=null, unavailable=null;
  try{
    const parsed=JSON.parse(td.decode(proofPart.body));
    if(isProofWire(parsed))proof=parsed;
    else if(parsed&&parsed.type==='tee.proof_unavailable')unavailable=parsed;
  }catch{}
  return {bodyBytes:responsePart.body,proof,unavailable,tail:false};
}
function validSha256Hex(s){
  return typeof s==='string' && /^[a-f0-9]{64}$/i.test(s);
}
function consumeLeadingBlankLine(bytes,offset){
  let p=offset;
  while(bytes[p]===32||bytes[p]===9)p++;
  if(bytes[p]===13&&bytes[p+1]===10)return p+2;
  if(bytes[p]===10)return p+1;
  return -1;
}
async function normalizePastedBodyBytes(bodyBytes,proof,allowLeadingBlankTrim){
  if(!allowLeadingBlankTrim || !proof || !validSha256Hex(proof.response_body_sha256)){
    return {bodyBytes,ignoredLeadingBytes:0};
  }
  const expected=String(proof.response_body_sha256).toLowerCase();
  if(bytesToHex(await sha256(bodyBytes))===expected)return {bodyBytes,ignoredLeadingBytes:0};
  let offset=0;
  for(;;){
    const next=consumeLeadingBlankLine(bodyBytes,offset);
    if(next<=offset)return {bodyBytes,ignoredLeadingBytes:0};
    offset=next;
    const candidate=bodyBytes.subarray(offset);
    if(bytesToHex(await sha256(candidate))===expected){
      return {bodyBytes:candidate,ignoredLeadingBytes:offset};
    }
  }
}
async function normalizeSseTransportKeepalives(bodyBytes,proof){
  if(!proof || !validSha256Hex(proof.response_body_sha256)){
    return {bodyBytes,ignoredTransportKeepaliveBytes:0,ignoredTransportKeepaliveCount:0};
  }
  const expected=String(proof.response_body_sha256).toLowerCase();
  if(bytesToHex(await sha256(bodyBytes))===expected){
    return {bodyBytes,ignoredTransportKeepaliveBytes:0,ignoredTransportKeepaliveCount:0};
  }
  const kept=[];
  let searchOffset=0,copyOffset=0,count=0;
  for(;;){
    const index=findBytes(bodyBytes,WOKEY_SSE_TRANSPORT_KEEPALIVE_V1,searchOffset);
    if(index<0)break;
    const atRecordBoundary=index===0
      ||(index>=2&&bodyBytes[index-2]===10&&bodyBytes[index-1]===10)
      ||(index>=4&&bodyBytes[index-4]===13&&bodyBytes[index-3]===10&&bodyBytes[index-2]===13&&bodyBytes[index-1]===10);
    if(!atRecordBoundary){searchOffset=index+1;continue;}
    kept.push(bodyBytes.subarray(copyOffset,index));
    copyOffset=index+WOKEY_SSE_TRANSPORT_KEEPALIVE_V1.length;
    searchOffset=copyOffset;
    count++;
  }
  if(count){
    kept.push(bodyBytes.subarray(copyOffset));
    const candidate=concat(kept);
    if(bytesToHex(await sha256(candidate))===expected){
      return {bodyBytes:candidate,ignoredTransportKeepaliveBytes:count*WOKEY_SSE_TRANSPORT_KEEPALIVE_V1.length,ignoredTransportKeepaliveCount:count};
    }
  }
  return {bodyBytes,ignoredTransportKeepaliveBytes:0,ignoredTransportKeepaliveCount:0};
}
// 存成文件再上传的抓包常被 Windows 工具把 LF 改成 CRLF(PowerShell 的 > 重定向、记事本另存等)。
// 上游 SSE 只用 LF,换行只出现在记录分隔处(JSON 里的换行是转义的),还原成 LF 不改动任何事件内容;
// 仍以签名哈希为闸:还原后对上签名覆盖的 hash 才采用,否则原样返回、照常判失败。
async function normalizeSseLineEndings(bodyBytes,proof){
  const none={bodyBytes,restoredLfLineEndings:0,ignoredTransportKeepaliveBytes:0,ignoredTransportKeepaliveCount:0};
  if(!proof || !validSha256Hex(proof.response_body_sha256))return none;
  const expected=String(proof.response_body_sha256).toLowerCase();
  if(bytesToHex(await sha256(bodyBytes))===expected)return none;
  const parts=[],lf=te.encode('\n'),crlf=te.encode('\r\n');
  let copyOffset=0,count=0;
  for(;;){
    const index=findBytes(bodyBytes,crlf,copyOffset);
    if(index<0)break;
    parts.push(bodyBytes.subarray(copyOffset,index),lf);
    copyOffset=index+2;
    count++;
  }
  if(!count)return none;
  parts.push(bodyBytes.subarray(copyOffset));
  const normalized=await normalizeSseTransportKeepalives(concat(parts),proof);
  if(bytesToHex(await sha256(normalized.bodyBytes))!==expected)return none;
  return {...normalized,restoredLfLineEndings:count};
}
// 文件编码被保存工具改过:Windows PowerShell 5.1 的 > 重定向写 UTF-16LE(带 BOM),记事本等可能在开头加 UTF-8 BOM。
// 上游 SSE / multipart 是不带 BOM 的 UTF-8,原样字节不可能是这两种形态,所以先转回 UTF-8 再解析
// 不会让本应通过的响应失败;转回后是否就是签名覆盖的字节,仍由 response hash 判定。
function looksLikeBomlessUtf16(bytes,zeroAt){
  if(bytes.length<8||bytes.length%2!==0)return false;
  const end=Math.min(bytes.length,64);
  for(let i=0;i<end;i+=2)if(bytes[i+zeroAt]!==0||bytes[i+1-zeroAt]===0)return false;
  return true;
}
function decodeSavedCapture(bytes){
  if(bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf)return {bytes:bytes.subarray(3),encoding:'utf-8-bom'};
  let encoding=null,start=0;
  if(bytes[0]===0xff&&bytes[1]===0xfe){encoding='utf-16le';start=2;}
  else if(bytes[0]===0xfe&&bytes[1]===0xff){encoding='utf-16be';start=2;}
  else if(looksLikeBomlessUtf16(bytes,1))encoding='utf-16le';
  else if(looksLikeBomlessUtf16(bytes,0))encoding='utf-16be';
  if(!encoding)return {bytes,encoding:null};
  const units=new Uint8Array(bytes.subarray(start,bytes.length-((bytes.length-start)%2)));
  if(encoding==='utf-16be')for(let i=0;i<units.length;i+=2){const b=units[i];units[i]=units[i+1];units[i+1]=b;}
  return {bytes:te.encode(new TextDecoder('utf-16le').decode(units)),encoding};
}

// v2 字段分解声明:与 verifier/signing.ts buildV2Statement 逐字节一致(golden 向量锁)。
function pathNoQuery(p){const s=p||'';const q=s.indexOf('?');return q>=0?s.slice(0,q):s;}
function buildV2Statement(t){
  const lines=[
    SIGNING_DOMAIN_V2,
    'nonce='+t.nonce,
    'upstream-host='+String(t.upstream_host||'').toLowerCase(),
    'upstream-path='+pathNoQuery(t.upstream_path),
    'http-method='+String(t.http_method||'').toUpperCase(),
    'http-status='+String(t.http_status),
    'resp-content-type='+String(t.resp_content_type||''),
    'request-body-sha256='+t.request_body_sha256,
    'response-body-sha256='+t.response_body_sha256,
  ];
  return te.encode(lines.map(l=>l+'\n').join(''));
}
function attestationSigningBytes(a){return te.encode(JSON.stringify({module_id:a.module_id,pcr0:a.pcr0,public_key:a.public_key,timestamp:a.timestamp}));}
async function importSpkiPem(pem){const der=b64ToBytes(pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,''));return crypto.subtle.importKey('spki',der,{name:'Ed25519'},false,['verify']);}
async function importSpkiB64(b){return crypto.subtle.importKey('spki',b64ToBytes(b),{name:'Ed25519'},false,['verify']);}
const edVerify = (k,sig,msg)=>crypto.subtle.verify({name:'Ed25519'},k,b64ToBytes(sig),msg);

// ───────── 真 Nitro attestation（COSE_Sign1 / ECDSA P-384 / X.509）浏览器验证器 ─────────
// 与 verifier/verify-attestation-cose.mjs 逐字对齐，但用 WebCrypto（P-384）+ 手写 ASN.1。
// AWS Nitro 根（G1）SHA-256 指纹，硬编码 pin（官方公布值）：
const AWS_NITRO_ROOT_FP='64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B';
const MAX_CBOR_DEPTH = 32;
const MAX_CBOR_CONTAINER_ITEMS = 1024;
const MAX_CBOR_STRING_BYTES = 262144;
const CBOR_BREAK = Symbol('cbor.break');

function cborError(message) {
  throw new Error(`invalid CBOR: ${message}`);
}

function requireAvailable(b, p, n) {
  if (!Number.isSafeInteger(p) || !Number.isSafeInteger(n) || p < 0 || n < 0 || p + n > b.length) {
    cborError('truncated item');
  }
}

function readAdditional(b, p, ai) {
  if (ai < 24) return [ai, p];
  if (ai === 24) { requireAvailable(b, p, 1); return [b[p], p + 1]; }
  if (ai === 25) { requireAvailable(b, p, 2); return [new DataView(b.buffer,b.byteOffset,b.byteLength).getUint16(p), p + 2]; }
  if (ai === 26) { requireAvailable(b, p, 4); return [new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(p), p + 4]; }
  if (ai === 27) {
    requireAvailable(b, p, 8);
    const v = new DataView(b.buffer,b.byteOffset,b.byteLength).getBigUint64(p);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) cborError('integer too large');
    return [Number(v), p + 8];
  }
  if (ai === 31) cborError('unexpected indefinite-length marker');
  cborError('invalid additional information');
}

function boundedSlice(b, p, len, kind) {
  if (len > MAX_CBOR_STRING_BYTES) cborError(`${kind} too large`);
  requireAvailable(b, p, len);
  return b.subarray(p, p + len);
}

function decodeIndefiniteCbor(b, p, mt, depth) {
  switch (mt) {
    case 2: {
      const chunks = [];
      let total = 0;
      for (;;) {
        let chunk;[chunk, p] = dec(b, p, depth + 1, true);
        if (chunk === CBOR_BREAK) return [concat(chunks), p];
        if (!(chunk instanceof Uint8Array)) cborError('non-bytes chunk in indefinite byte string');
        total += chunk.length;
        if (chunks.length >= MAX_CBOR_CONTAINER_ITEMS || total > MAX_CBOR_STRING_BYTES) cborError('byte string too large');
        chunks.push(chunk);
      }
    }
    case 3: {
      const chunks = [];
      let total = 0;
      for (;;) {
        let chunk;[chunk, p] = dec(b, p, depth + 1, true);
        if (chunk === CBOR_BREAK) return [chunks.join(''), p];
        if (typeof chunk !== 'string') cborError('non-text chunk in indefinite text string');
        total += te.encode(chunk).length;
        if (chunks.length >= MAX_CBOR_CONTAINER_ITEMS || total > MAX_CBOR_STRING_BYTES) cborError('text string too large');
        chunks.push(chunk);
      }
    }
    case 4: {
      const a = [];
      for (;;) {
        let v;[v, p] = dec(b, p, depth + 1, true);
        if (v === CBOR_BREAK) return [a, p];
        if (a.length >= MAX_CBOR_CONTAINER_ITEMS) cborError('array too large');
        a.push(v);
      }
    }
    case 5: {
      const m = Object.create(null);
      let count = 0;
      for (;;) {
        let k, v;[k, p] = dec(b, p, depth + 1, true);
        if (k === CBOR_BREAK) return [m, p];
        [v, p] = dec(b, p, depth + 1);
        if (count >= MAX_CBOR_CONTAINER_ITEMS) cborError('map too large');
        if(typeof k!=='string'&&typeof k!=='number')cborError('map key type'); if(Object.hasOwn(m,k))cborError('duplicate map key'); m[k] = v;
        count++;
      }
    }
    default:
      cborError('invalid indefinite-length item');
  }
}

// 最小有界 CBOR 解码器:仅覆盖 attestation 文档用到的类型。
function dec(b, p, depth = 0, allowBreak = false) {
  if (depth > MAX_CBOR_DEPTH) cborError('nesting too deep');
  requireAvailable(b, p, 1);
  if (b[p] === 0xff) {
    if (allowBreak) return [CBOR_BREAK, p + 1];
    cborError('unexpected break');
  }
  const ib = b[p], mt = ib >> 5, ai = ib & 0x1f; p++;
  if (ai === 31) return decodeIndefiniteCbor(b, p, mt, depth);
  let len;[len, p] = readAdditional(b, p, ai);
  switch (mt) {
    case 0: return [len, p];
    case 1: return [-1 - len, p];
    case 2: return [boundedSlice(b, p, len, 'byte string'), p + len];
    case 3: return [td.decode(boundedSlice(b, p, len, 'text string')), p + len];
    case 4: {
      if (len > MAX_CBOR_CONTAINER_ITEMS) cborError('array too large');
      const a = [];
      for (let i = 0; i < len; i++) { let v;[v, p] = dec(b, p, depth + 1); a.push(v); }
      return [a, p];
    }
    case 5: {
      if (len > MAX_CBOR_CONTAINER_ITEMS) cborError('map too large');
      const m = Object.create(null);
      for (let i = 0; i < len; i++) { let k, v;[k, p] = dec(b, p, depth + 1);[v, p] = dec(b, p, depth + 1); if(typeof k!=='string'&&typeof k!=='number')cborError('map key type'); if(Object.hasOwn(m,k))cborError('duplicate map key'); m[k] = v; }
      return [m, p];
    }
    case 6: if(len!==18)cborError('unsupported tag'); return dec(b, p, depth + 1);
    case 7: { if (ai === 20) return [false, p]; if (ai === 21) return [true, p]; return [null, p]; }
    default: cborError('unknown major type');
  }
}

function cborDec(b,p){if(!(b instanceof Uint8Array)||b.length>262144)throw new Error("CBOR bounds");return dec(b,p);}
function cborBstr(b){
  if(b.length<24)return concat([Uint8Array.of(0x40|b.length),b]);
  if(b.length<256)return concat([Uint8Array.of(0x58,b.length),b]);
  if(b.length<65536){const h=new Uint8Array(3);h[0]=0x59;new DataView(h.buffer).setUint16(1,b.length);return concat([h,b]);}
  const h=new Uint8Array(5);h[0]=0x5a;new DataView(h.buffer).setUint32(1,b.length);return concat([h,b]);
}
const cborText=(s)=>{const b=te.encode(s);return concat([Uint8Array.of(0x60|b.length),b]);};
function der(b,p){if(p<0||p+2>b.length)throw new Error('DER bounds');let tag=b[p],i=p+1,len=b[i];i++;if(len&0x80){const n=len&0x7f;if(n===0||n>4||i+n>b.length)throw new Error('DER length');len=0;for(let k=0;k<n;k++){len=(len*256)+b[i];i++;}}if(i+len>b.length)throw new Error('DER value bounds');return{tag,start:p,cstart:i,cend:i+len,end:i+len};}
function derChildren(b,t){const o=[];let p=t.cstart;while(p<t.cend){const c=der(b,p);o.push(c);p=c.end;}return o;}
function ecdsaDerToRaw(d,size){const seq=der(d,0);const[r,s]=derChildren(d,seq);
  const norm=(t)=>{let v=d.subarray(t.cstart,t.cend);while(v.length>size&&v[0]===0)v=v.subarray(1);const o=new Uint8Array(size);o.set(v,size-v.length);return o;};
  return concat([norm(r),norm(s)]);}
function derTime(b,t){const s=new TextDecoder().decode(b.subarray(t.cstart,t.cend));
  let i=0,y; if((t.tag&0xff)===0x17){y=+s.slice(0,2);y+=y<50?2000:1900;i=2;}else{y=+s.slice(0,4);i=4;}
  return Date.UTC(y,(+s.slice(i,i+2))-1,+s.slice(i+2,i+4),+s.slice(i+4,i+6),+s.slice(i+6,i+8),+s.slice(i+8,i+10));}
function parseCert(c){const top=der(c,0);const[tbs,,sigVal]=derChildren(c,top);
  const tbsBytes=c.subarray(tbs.start,tbs.end);const tch=derChildren(c,tbs);
  const vpres=((tch[0].tag&0xff)===0xa0);const spkiT=tch[vpres?6:5];
  const[nbT,naT]=derChildren(c,tch[vpres?4:3]);
  return{tbsBytes,spki:c.subarray(spkiT.start,spkiT.end),sigRaw:ecdsaDerToRaw(c.subarray(sigVal.cstart+1,sigVal.cend),48),
    notBefore:derTime(c,nbT),notAfter:derTime(c,naT)};}
const ecVerify=async(spki,sigRaw,msg)=>{const k=await crypto.subtle.importKey('spki',spki,{name:'ECDSA',namedCurve:'P-384'},false,['verify']);return crypto.subtle.verify({name:'ECDSA',hash:'SHA-384'},k,sigRaw,msg);};
async function sha256hexColon(b){const h=new Uint8Array(await crypto.subtle.digest('SHA-256',b));return Array.from(h).map(x=>x.toString(16).padStart(2,'0').toUpperCase()).join(':');}
export async function verifyCoseAttestation(docB64){
  if(typeof docB64!=='string'||docB64.length>350000)throw new Error('Attestation format');
  const buf=b64ToBytes(docB64);
  const[cose,coseEnd]=cborDec(buf,0);if(coseEnd!==buf.length||!Array.isArray(cose)||cose.length!==4)throw new Error('COSE envelope');
  const[protectedRaw,,payloadRaw,sig]=cose;
  if(!(protectedRaw instanceof Uint8Array)||!(payloadRaw instanceof Uint8Array)||!(sig instanceof Uint8Array)||sig.length!==96)throw new Error('COSE field types');
  const[protectedHeader,headerEnd]=cborDec(protectedRaw,0);if(headerEnd!==protectedRaw.length||protectedHeader[1]!==-35)throw new Error('COSE algorithm');
  const[doc,docEnd]=cborDec(payloadRaw,0);if(docEnd!==payloadRaw.length)throw new Error('COSE payload');
  if(!Array.isArray(doc.cabundle)||doc.cabundle.length<1||doc.cabundle.length>8||!(doc.certificate instanceof Uint8Array)||!(doc.pcrs?.[0] instanceof Uint8Array)||doc.pcrs[0].length!==48)throw new Error('Attestation fields');
  const leaf=parseCert(doc.certificate);
  const sigStruct=concat([Uint8Array.of(0x84),cborText('Signature1'),cborBstr(protectedRaw),cborBstr(new Uint8Array(0)),cborBstr(payloadRaw)]);
  const sigOk=await ecVerify(leaf.spki,sig,sigStruct);
  const certs=[...doc.cabundle.map(parseCert),leaf];
  let chainOk=true;
  for(let i=1;i<certs.length;i++)chainOk=chainOk&&await ecVerify(certs[i-1].spki,certs[i].sigRaw,certs[i].tbsBytes);
  const root=certs[0];
  const rootSelf=await ecVerify(root.spki,root.sigRaw,root.tbsBytes);
  const fp=await sha256hexColon(doc.cabundle[0]);
  const now=Date.now();
  const timeValid=certs.every(c=>now>=c.notBefore&&now<=c.notAfter);
  return{sigOk,chainOk,rootSelf,rootPinned:fp===AWS_NITRO_ROOT_FP,timeValid,
    leafNotAfter:new Date(leaf.notAfter).toISOString(),
    pcr0:bytesToHex(doc.pcrs[0]),publicKey:doc.public_key?bytesToB64(doc.public_key):null,
    nonce:doc.nonce?bytesToB64(doc.nonce):null,
    moduleId:doc.module_id,rootFp:fp,
    chainLen:certs.length,fields:Object.keys(doc),     // 弹窗用:链长 + 解出的字段表(让用户对照自己解的)
    timestamp:typeof doc.timestamp==='number'?doc.timestamp:null,
    digest:typeof doc.digest==='string'?doc.digest:null,
    userData:doc.user_data?bytesToB64(doc.user_data):null};
}

export async function verifyResponse(rawBytes, policy, requestBytes) {
  if(!(rawBytes instanceof Uint8Array)||rawBytes.length>8*1024*1024)throw new Error('响应文件超过 8 MiB 或格式错误');
  if(!/^[a-f0-9]{96}$/.test(policy.pcr0))throw new Error('可信 PCR0 格式错误');
  const decoded=decodeSavedCapture(rawBytes), parsed=parseProofEventBytes(decoded.bytes);
  if(!parsed)throw new Error('缺少完整 tee.proof；请保存完整原始响应');
  const t=parsed.proof;
  for(const field of ['public_key','nonce','upstream_host','upstream_path','http_method','resp_content_type','request_body_sha256','response_body_sha256','signature','attestation']) {
    if(typeof t[field]!=='string'||/[\r\n]/.test(t[field]))throw new Error('证明字段格式错误');
  }
  if(t.v!==2||t.alg!=='ed25519'||!validSha256Hex(t.request_body_sha256)||!validSha256Hex(t.response_body_sha256))throw new Error('不支持的证明版本或摘要');
  let normalized=await normalizeSseTransportKeepalives(parsed.bodyBytes,t);
  if(bytesToHex(await sha256(normalized.bodyBytes))!==t.response_body_sha256) {
    const restored=await normalizeSseLineEndings(parsed.bodyBytes,t);
    if(bytesToHex(await sha256(restored.bodyBytes))===t.response_body_sha256)normalized=restored;
  }
  const body=normalized.bodyBytes, checks=[];
  const check=async(name,fn)=>{let ok=false;try{ok=Boolean(await fn());}catch{}checks.push({name,ok});};
  let att;try{att=await verifyCoseAttestation(t.attestation);}catch{}
  await check('真实硬件证明与 AWS 根证书链',()=>att&&att.sigOk&&att.chainOk&&att.rootSelf&&att.rootPinned);
  await check('证书在当前有效期内',()=>att?.timeValid);
  await check('PCR0 与可信公开参考值一致',()=>att?.pcr0===policy.pcr0);
  await check('签名公钥由硬件证明绑定',()=>att?.publicKey===t.public_key);
  await check('证明与签名的 nonce 一致',()=>att?.nonce===t.nonce);
  await check('官方来源与原生接口一致',()=>t.upstream_host===policy.host&&t.upstream_path==='/v1/messages'&&t.http_method==='POST'&&t.http_status===200&&t.resp_content_type.startsWith('text/event-stream'));
  await check('Ed25519 声明签名有效',async()=>edVerify(await importSpkiB64(t.public_key),t.signature,buildV2Statement(t)));
  await check('响应正文未被篡改',async()=>bytesToHex(await sha256(body))===t.response_body_sha256);
  const events=td.decode(body).split(/\r?\n\r?\n/).map(record=>{
    const data=record.split(/\r?\n/).filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
    try{return JSON.parse(data);}catch{return null;}
  });
  const model=events.find(event=>event?.type==='message_start')?.message?.model;
  await check('签名覆盖的模型与预期一致',()=>model===policy.model);
  await check('响应包含完整结束事件',()=>events.some(event=>event?.type==='message_stop'));
  const mode=requestBytes===undefined?'response-only':'full';
  if(requestBytes!==undefined) {
    if(!(requestBytes instanceof Uint8Array)||requestBytes.length>1024*1024)throw new Error('请求文件超过 1 MiB 或格式错误');
    await check('原始请求字节与证明完全一致',async()=>bytesToHex(await sha256(requestBytes))===t.request_body_sha256);
  }
  return {ok:checks.every(c=>c.ok),checks,mode,host:t.upstream_host,model,
    normalizedKeepalives:normalized.ignoredTransportKeepaliveCount||0,
    restoredLineEndings:normalized.restoredLfLineEndings||0,savedEncoding:decoded.encoding};
}
