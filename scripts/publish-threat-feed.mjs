import {readFile,writeFile} from 'node:fs/promises';
import {gzipSync} from 'node:zlib';
import {execFileSync} from 'node:child_process';
import {THREAT_CONFIG} from '../src/threat-config.js';
import {verifyThreatBundle,verifyThreatManifest,FRESH_MS} from '../src/threat-bundle.js';
import {publishThreatSnapshot} from './lib/threat-publisher.mjs';
const directory='.context/threat-feed',transportOnly=process.argv.includes('--previous-transport');
const manifest=JSON.parse(await readFile(`${directory}/${transportOnly?'previous-manifest.json':'manifest.json'}`));
if(transportOnly&&!manifest){console.log('No previous signed snapshot to compress.');process.exit(0);}
const target=/^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/threat-feed\/manifest\.json$/.exec(THREAT_CONFIG.manifestURL)?.[1];
if(!target)throw Error('Expected a GitHub Releases endpoint');
const repository=JSON.parse(execFileSync('gh',['repo','view',target,'--json','visibility'],{encoding:'utf8'}));
if(repository.visibility!=='PUBLIC')throw Error('Threat feed must be public without shipping credentials');
const previous=await readFile(`${directory}/previous-manifest.json`,'utf8').then(JSON.parse,()=>null);
await verifyThreatManifest(manifest,THREAT_CONFIG.keys,{allowSame:transportOnly,previousVersion:transportOnly?0:previous?.version||0});
const bytes=await readFile(`${directory}/${transportOnly?'previous.json':manifest.artifact}`);
await verifyThreatBundle(manifest,bytes,THREAT_CONFIG.keys,{allowSame:transportOnly,previousVersion:transportOnly?0:previous?.version||0});
// No new signature or timestamp: the client verifies the decompressed bytes
// against the original manifest. Old clients continue downloading plain JSON.
const compressed=`${directory}/${manifest.artifact}.gz`;
await writeFile(compressed,gzipSync(bytes,{level:9}));
if(transportOnly){
 execFileSync('gh',['release','upload','threat-feed','--repo',target,compressed,'--clobber'],{stdio:'inherit'});
 console.log({version:manifest.version,compressedBytes:(await readFile(compressed)).length,originalBytes:bytes.length});process.exit(0);
}
if(Date.now()-Date.parse(manifest.sourcePublishedAt)>FRESH_MS)throw Error('Refusing to publish stale source');
console.log(await publishThreatSnapshot({target,manifest,previousVersion:previous?.version||0,directory}));
