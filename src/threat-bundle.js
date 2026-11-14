import {canonicalDomain} from './domains.js';
export const MAX_FEED_BYTES=96*1024*1024, MAX_ENTRIES=1000000, FRESH_MS=72*3600000;
const utf8=new TextEncoder();
export const hex=bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');
export async function digest(bytes){return hex(await crypto.subtle.digest('SHA-256',bytes));}
export function signedManifestBytes(manifest) {
  const {signature,...payload}=manifest;
  return utf8.encode(JSON.stringify(Object.fromEntries(Object.keys(payload).sort().map(k=>[k,payload[k]]))));
}
export function threatBucket(host){let h=2166136261;for(const c of host)h=Math.imul(h^c.charCodeAt(0),16777619);return (h>>>0)%256;}
export function threatPartitions(payload){const groups=Array.from({length:256},()=>[]);for(const row of payload.entries)groups[threatBucket(row.host)].push(row);return groups.map(rows=>utf8.encode(JSON.stringify(rows)));}
function validTime(s){return typeof s==='string' && Number.isFinite(Date.parse(s));}
export async function verifyThreatManifest(manifest,keys,{previousVersion=0,now=Date.now(),allowSame=false}={}) {
  if(!manifest || manifest.schemaVersion!==1 || !Number.isSafeInteger(manifest.version) || manifest.version<1 ||
    manifest.version<previousVersion || (!allowSame && manifest.version===previousVersion) ||
    !validTime(manifest.generatedAt) || !validTime(manifest.sourcePublishedAt) || Date.parse(manifest.generatedAt)>now+300000 ||
    Date.parse(manifest.sourcePublishedAt)>Date.parse(manifest.generatedAt) ||
    !/^[a-f0-9]{64}$/.test(manifest.sha256) || !Number.isSafeInteger(manifest.bytes) || manifest.bytes<1 || manifest.bytes>MAX_FEED_BYTES || !Number.isSafeInteger(manifest.entries) || manifest.entries<1 || manifest.entries>MAX_ENTRIES || !Array.isArray(manifest.shardHashes) || manifest.shardHashes.length!==256 || manifest.shardHashes.some(h=>!(/^[a-f0-9]{64}$/).test(h)) ||
    !/^[a-f0-9]{40}$/.test(manifest.sourceRevision) || manifest.source!=='https://github.com/Phishing-Database/Phishing.Database' ||
    manifest.artifact!==`threats-${manifest.version}.json` || typeof manifest.signature!=='string') throw Error('위협 자료 메타데이터가 올바르지 않습니다.');
  const key=keys[manifest.keyId];
  if(!key)throw Error('등록되지 않은 위협 자료 서명 키입니다.');
  let signature;
  try {signature=Uint8Array.from(atob(manifest.signature),c=>c.charCodeAt(0));}catch{throw Error('잘못된 서명입니다.');}
  const publicKey=await crypto.subtle.importKey('jwk',key,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  if(signature.length!==64 || !await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,signature,signedManifestBytes(manifest)))throw Error('위협 자료의 서명이 일치하지 않습니다.');
}
export async function verifyThreatBundle(manifest,bytes,keys,options={}) {
  await verifyThreatManifest(manifest,keys,options);
  if(bytes.byteLength!==manifest.bytes)throw Error('위협 자료 크기가 일치하지 않습니다.');
  if(await digest(bytes)!==manifest.sha256)throw Error('위협 자료 체크섬이 일치하지 않습니다.');
  const payload=JSON.parse(new TextDecoder().decode(bytes));
  if(payload.schemaVersion!==1 || !Array.isArray(payload.entries) || payload.entries.length>MAX_ENTRIES || payload.entries.length!==manifest.entries || !Array.isArray(payload.withdrawals))throw Error('위협 목록 형식이 올바르지 않습니다.');
  const seen=new Set();
  for(const row of payload.entries) {
    if(!row || !['domain','url-host'].includes(row.scope) || canonicalDomain(row.host)!==row.host || !row.host.includes('.') ||
      !validTime(row.observedAt) || Date.parse(row.observedAt)>Date.parse(manifest.generatedAt) || seen.has(row.host))throw Error('위협 호스트 항목이 올바르지 않습니다.');
    seen.add(row.host);
  }
  const withdrawn=new Set();
  for(const row of payload.withdrawals) {
    if(canonicalDomain(row.host)!==row.host || !validTime(row.withdrawnAt) || seen.has(row.host) || withdrawn.has(row.host))throw Error('철회 기록이 올바르지 않습니다.');
    withdrawn.add(row.host);
  }
  const partitions=threatPartitions(payload);
  const hashes=await Promise.all(partitions.map(digest));
  if(hashes.some((h,i)=>h!==manifest.shardHashes[i]))throw Error('위협 자료 분할 체크섬이 일치하지 않습니다.');
  return {manifest,payload,partitions};
}
export function validateFeedChange(previous,next) {
  if(!next.entries.length)throw Error('빈 위협 목록은 배포하지 않습니다.');
  if(!previous)return;
  const old=new Map(previous.entries.map(r=>[r.host,r.scope])), current=new Map(next.entries.map(r=>[r.host,r.scope]));
  let changed=0;
  for(const [h,scope] of old)if(!current.has(h) || current.get(h)!==scope)changed++;
  for(const h of current.keys())if(!old.has(h))changed++;
  if(changed/Math.max(old.size,1)>.25)throw Error('위협 목록의 변화가 25%를 넘었습니다. 검토가 필요합니다.');
}
