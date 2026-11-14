import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyThreatBundle,threatPartitions,signedManifestBytes,digest,validateFeedChange,FRESH_MS} from '../src/threat-bundle.js';
import {THREAT_CONFIG} from '../src/threat-config.js';
import {downloadThreatFile} from '../scripts/lib/threat-download.mjs';
import {readFile,mkdtemp,mkdir,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execute=promisify(execFile);
test('public endpoint uses only the data repository and a public verification key',()=>{
 assert.equal(THREAT_CONFIG.manifestURL,'https://github.com/poohpak/munimen-threat-data/releases/download/threat-feed/manifest.json');
 assert.equal(THREAT_CONFIG.manifestURL,THREAT_CONFIG.artifactBase+'manifest.json');
 for(const key of Object.values(THREAT_CONFIG.keys))assert.equal(key.d,undefined);
});
test('signature tampering, payload tampering and rollback fail verification',async()=>{
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const now=Date.now(),time=new Date(now).toISOString(),payload={schemaVersion:1,entries:[{host:'bad.example',scope:'domain',observedAt:time}],withdrawals:[]};
 const bytes=new TextEncoder().encode(JSON.stringify(payload));
 const manifest={schemaVersion:1,version:now,keyId:'test',generatedAt:time,sourcePublishedAt:time,source:'https://github.com/Phishing-Database/Phishing.Database',sourceRevision:'a'.repeat(40),artifact:`threats-${now}.json`,bytes:bytes.length,entries:1,sha256:await digest(bytes),shardHashes:await Promise.all(threatPartitions(payload).map(digest))};
 manifest.signature=Buffer.from(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,signedManifestBytes(manifest))).toString('base64');
 const keys={test:await crypto.subtle.exportKey('jwk',pair.publicKey)};
 assert.equal((await verifyThreatBundle(manifest,bytes,keys)).payload.entries.length,1);
 await assert.rejects(verifyThreatBundle({...manifest,sourceRevision:'b'.repeat(40)},bytes,keys));
 const broken=bytes.slice();broken[20]^=1;await assert.rejects(verifyThreatBundle(manifest,broken,keys));
 await assert.rejects(verifyThreatBundle(manifest,bytes,keys,{previousVersion:now+1}));
 assert.throws(()=>validateFeedChange(payload,{entries:[{host:'different.example',scope:'domain'}]}));
 assert.throws(()=>validateFeedChange(payload,{entries:[{host:'bad.example',scope:'url-host'}]}));
});
test('bounded downloads handle missing assets and reject oversized data',async()=>{
 assert.equal(await downloadThreatFile('https://fixture.test/missing',1,{fetcher:async()=>new Response('',{status:404})}),null);
 await assert.rejects(downloadThreatFile('https://fixture.test/large',2,{fetcher:async()=>new Response('123')}),/byte limit/);
});
test('old source is refused before the signing key is imported or a manifest is written',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'munimen-public-sign-'));
 try{
  const dir=path.join(root,'source');await mkdir(dir);
  const publicKey=Object.values(THREAT_CONFIG.keys)[0];
  await writeFile(path.join(dir,'source.json'),JSON.stringify({sourcePublishedAt:new Date(Date.now()-FRESH_MS-60000).toISOString()}));
  await writeFile(path.join(dir,'payload.json'),JSON.stringify({entries:[]}));
  await assert.rejects(execute(process.execPath,['scripts/sign-threat-feed.mjs',`--directory=${dir}`],{env:{...process.env,THREAT_SIGNING_KEY:JSON.stringify(publicKey)}}),/older than 72 hours/);
  await assert.rejects(readFile(path.join(dir,'manifest.json')));
 }finally{await rm(root,{recursive:true,force:true});}
});
