import{readFile,copyFile}from'node:fs/promises';import{execFileSync}from'node:child_process';
import{THREAT_CONFIG}from'../src/threat-config.js';
import{verifyThreatBundle,FRESH_MS}from'../src/threat-bundle.js';
const m=JSON.parse(await readFile('.context/threat-feed/manifest.json')),args={stdio:'inherit'};
const target=/^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/threat-feed\/manifest\.json$/.exec(THREAT_CONFIG.manifestURL)?.[1];
if(!target)throw Error('The feed publisher requires a configured GitHub Releases endpoint');
const repository=JSON.parse(execFileSync('gh',['repo','view',target,'--json','visibility'],{encoding:'utf8'}));
if(repository.visibility!=='PUBLIC')throw Error('Threat feed must be publicly downloadable without shipping credentials');
const bytes=await readFile(`.context/threat-feed/${m.artifact}`);
await verifyThreatBundle(m,bytes,THREAT_CONFIG.keys);
if(Date.now()-Date.parse(m.sourcePublishedAt)>FRESH_MS)throw Error('Refusing to publish stale source');
const repo=['--repo',target];
// This script is only executed in the protected publishing job.
try{execFileSync('gh',['release','view','threat-feed',...repo],{stdio:'ignore'});}catch{execFileSync('gh',['release','create','threat-feed',...repo,'--title','Munimen signed threat feed','--notes','Signed host reputation data. No visitor URLs are collected.'],args);}
// Preserve each signed manifest, collection receipt and license alongside the
// immutable payload; replacing the pointer must not erase provenance history.
const auditFiles=[];
for(const [input,output] of [['manifest.json',`manifest-${m.version}.json`],['source.json',`source-${m.version}.json`],['LICENSE.txt',`LICENSE-${m.version}.txt`]]){
 const destination=`.context/threat-feed/${output}`;
 await copyFile(`.context/threat-feed/${input}`,destination);auditFiles.push(destination);
}
execFileSync('gh',['release','upload','threat-feed',...repo,`.context/threat-feed/${m.artifact}`,...auditFiles],args);
execFileSync('gh',['release','upload','threat-feed',...repo,'.context/threat-feed/manifest.json','--clobber'],args);
