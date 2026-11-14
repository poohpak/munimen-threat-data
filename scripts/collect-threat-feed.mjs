import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {canonicalDomain,registeredDomain} from '../src/domains.js';
import {validateFeedChange,MAX_FEED_BYTES,FRESH_MS,digest} from '../src/threat-bundle.js';
import {THREAT_SOURCES} from '../src/threat-sources.js';
import {downloadThreatFile} from './lib/threat-download.mjs';
const directory=process.argv.find(a=>a.startsWith('--output='))?.slice(9)||'.context/threat-feed';
const previousPath=process.argv.find(a=>a.startsWith('--previous='))?.slice(11);
const requested=process.argv.find(a=>a.startsWith('--source='))?.slice(9);
const providers=requested?THREAT_SOURCES.filter(p=>p.id===requested):THREAT_SOURCES;
if(!providers.length)throw Error('Unknown threat source');
const get=async url=>{const bytes=await downloadThreatFile(url,MAX_FEED_BYTES);if(!bytes)throw Error('Source HTTP 404');return bytes;};
const json=async url=>JSON.parse(new TextDecoder().decode(await get(url)));
const previous=previousPath?JSON.parse(await readFile(previousPath)):null;
await mkdir(directory,{recursive:true});
const attempts=[];let selected;
for(const provider of providers){
 try{
  const [commit]=await json(`https://api.github.com/repos/${provider.repository}/commits?per_page=1`);
  const revision=commit?.sha;if(!/^[a-f0-9]{40}$/.test(revision))throw Error('Invalid upstream revision');
  const dataRevisions=await Promise.all(provider.files.map(async file=>{
   const [record]=await json(`https://api.github.com/repos/${provider.repository}/commits?sha=${revision}&path=${encodeURIComponent(file.path)}&per_page=1`);
   if(!record || !/^[a-f0-9]{40}$/.test(record.sha) || !Number.isFinite(Date.parse(record.commit.committer.date)))throw Error('Missing data-file publication history');
   return {file:file.path,revision:record.sha,publishedAt:record.commit.committer.date,scope:file.scope};
  }));
  const publishedAt=new Date(Math.min(...dataRevisions.map(r=>Date.parse(r.publishedAt)))).toISOString();
  const receipt={source:provider.url,provider:provider.name,license:provider.license,sourceRevision:revision,sourcePublishedAt:publishedAt,collectedAt:new Date().toISOString(),dataRevisions};
  if(Date.now()-Date.parse(publishedAt)>FRESH_MS)throw Object.assign(Error('Upstream data files are older than 72 hours'),{receipt});
  const base=`https://raw.githubusercontent.com/${provider.repository}/${revision}/`;
  const licenseBytes=await get(base+'LICENSE'),license=new TextDecoder().decode(licenseBytes);
  if(!license.includes('MIT License'))throw Error('Upstream license changed; review required');
  const entries=new Map();
  for(const file of dataRevisions){
   const bytes=await get(base+file.file);file.sha256=await digest(bytes);file.bytes=bytes.length;
   let valid=0,nonempty=0;
   for(const raw of new TextDecoder().decode(bytes).split(/\r?\n/)){
    const line=raw.trim();if(!line||line.startsWith('#'))continue;nonempty++;
    let host;
    if(file.scope==='domain')host=canonicalDomain(line);
    else try{const u=new URL(line);if(['http:','https:'].includes(u.protocol))host=canonicalDomain(u.hostname);}catch{}
    if(host&&!isIP(host)&&registeredDomain(host)){valid++;if(!entries.has(host)||file.scope==='domain')entries.set(host,{host,scope:file.scope,observedAt:file.publishedAt});}
   }
   if(!nonempty || valid/nonempty<.99)throw Error('Unexpected upstream data format or excessive invalid records');
   file.records=nonempty;file.valid=valid;
  }
  const withdrawals=(previous?.withdrawals||[]).filter(r=>!entries.has(r.host)),already=new Set(withdrawals.map(r=>r.host));
  for(const row of previous?.entries||[])if(!entries.has(row.host)&&!already.has(row.host))withdrawals.push({host:row.host,withdrawnAt:new Date().toISOString()});
  const payload={schemaVersion:1,entries:[...entries.values()].sort((a,b)=>a.host.localeCompare(b.host)),withdrawals};
  // Provider fallback does not waive the same change limit or source lineage.
  validateFeedChange(previous,payload);
  selected={receipt:{...receipt,attempts,domainReports:payload.entries.filter(r=>r.scope==='domain').length,urlHostReports:payload.entries.filter(r=>r.scope==='url-host').length},payload,license};break;
 }catch(error){attempts.push({source:provider.url,error:error.message,...(error.receipt?{receipt:error.receipt}:{})});}
}
if(!selected){await writeFile(`${directory}/source.json`,JSON.stringify({...attempts.at(-1)?.receipt,attempts,collectedAt:new Date().toISOString()},null,2));throw Error('No eligible fresh threat source; publication withheld');}
await writeFile(`${directory}/payload.json`,JSON.stringify(selected.payload));
await writeFile(`${directory}/source.json`,JSON.stringify(selected.receipt,null,2));
await writeFile(`${directory}/LICENSE.txt`,selected.license);
console.log({directory,source:selected.receipt.source,publishedAt:selected.receipt.sourcePublishedAt,entries:selected.payload.entries.length,withdrawals:selected.payload.withdrawals.length});
