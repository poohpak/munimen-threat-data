import{mkdir,readFile,writeFile}from'node:fs/promises';
import{isIP}from'node:net';
import{canonicalDomain,registeredDomain}from'../src/domains.js';
import{validateFeedChange,MAX_FEED_BYTES,FRESH_MS}from'../src/threat-bundle.js';
const directory=process.argv.find(a=>a.startsWith('--output='))?.slice(9)||'.context/threat-feed';
const previousPath=process.argv.find(a=>a.startsWith('--previous='))?.slice(11);
async function get(url){const r=await fetch(url,{headers:{'User-Agent':'Munimen-threat-feed/1.0'},signal:AbortSignal.timeout(60000)});if(!r.ok)throw Error(`Source HTTP ${r.status}`);const body=await r.text();if(body.length>MAX_FEED_BYTES)throw Error('Source too large');return body;}
const commits=JSON.parse(await get('https://api.github.com/repos/Phishing-Database/Phishing.Database/commits?per_page=1'));
const commit=commits[0],revision=commit.sha;
if(!/^[a-f0-9]{40}$/.test(revision))throw Error('Invalid upstream revision');
const base=`https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/${revision}/`;
// README/license-only commits must not make old ACTIVE files appear fresh.
const dataFiles=['phishing-domains-ACTIVE.txt','phishing-links-ACTIVE.txt'];
const dataRevisions=await Promise.all(dataFiles.map(async file=>{
 const history=JSON.parse(await get(`https://api.github.com/repos/Phishing-Database/Phishing.Database/commits?sha=${revision}&path=${encodeURIComponent(file)}&per_page=1`));
 const row=history[0];
 if(!row || !/^[a-f0-9]{40}$/.test(row.sha) || !Number.isFinite(Date.parse(row.commit.committer.date)))throw Error('Missing data-file publication history');
 return {file,revision:row.sha,publishedAt:row.commit.committer.date};
}));
const publishedAt=new Date(Math.min(...dataRevisions.map(r=>Date.parse(r.publishedAt)))).toISOString();
await mkdir(directory,{recursive:true});
const receipt={source:'https://github.com/Phishing-Database/Phishing.Database',sourceRevision:revision,sourcePublishedAt:publishedAt,collectedAt:new Date().toISOString(),dataRevisions};
await writeFile(`${directory}/source.json`,JSON.stringify(receipt,null,2));
if(Date.now()-Date.parse(publishedAt)>FRESH_MS)throw Error('Upstream data files are older than 72 hours; publication withheld');
const [domains,urls,license]=await Promise.all(['phishing-domains-ACTIVE.txt','phishing-links-ACTIVE.txt','LICENSE'].map(f=>get(base+f)));
if(!license.includes('MIT License'))throw Error('Upstream license changed; review required');
const now=new Date().toISOString(),entries=new Map();
for(const line of domains.split(/\r?\n/)){const host=canonicalDomain(line.trim());if(host && !isIP(host) && registeredDomain(host))entries.set(host,{host,scope:'domain',observedAt:dataRevisions[0].publishedAt});}
for(const line of urls.split(/\r?\n/)){try{const u=new URL(line.trim());if(!['http:','https:'].includes(u.protocol))continue;const host=canonicalDomain(u.hostname);if(host&&!isIP(host)&&registeredDomain(host)&&!entries.has(host))entries.set(host,{host,scope:'url-host',observedAt:dataRevisions[1].publishedAt});}catch{}}
const previous=previousPath?JSON.parse(await readFile(previousPath)):null;
const withdrawals=(previous?.withdrawals||[]).filter(r=>!entries.has(r.host));const already=new Set(withdrawals.map(r=>r.host));
for(const row of previous?.entries||[])if(!entries.has(row.host)&&!already.has(row.host))withdrawals.push({host:row.host,withdrawnAt:now});
const payload={schemaVersion:1,entries:[...entries.values()].sort((a,b)=>a.host.localeCompare(b.host)),withdrawals};validateFeedChange(previous,payload);
await mkdir(directory,{recursive:true});await writeFile(`${directory}/payload.json`,JSON.stringify(payload));
await writeFile(`${directory}/source.json`,JSON.stringify({...receipt,domainReports:payload.entries.filter(r=>r.scope==='domain').length,urlHostReports:payload.entries.filter(r=>r.scope==='url-host').length},null,2));
await writeFile(`${directory}/LICENSE.txt`,license);console.log({directory,entries:entries.size,sourcePublishedAt:publishedAt,withdrawals:withdrawals.length});
