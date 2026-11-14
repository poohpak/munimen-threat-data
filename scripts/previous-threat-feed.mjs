import {mkdir,writeFile} from 'node:fs/promises';
import {THREAT_CONFIG} from '../src/threat-config.js';
import {verifyThreatManifest,verifyThreatBundle,MAX_FEED_BYTES} from '../src/threat-bundle.js';
import {downloadThreatFile} from './lib/threat-download.mjs';
await mkdir('.context/threat-feed',{recursive:true});
const bytes=await downloadThreatFile(THREAT_CONFIG.manifestURL,65536);
if(!bytes){
 await writeFile('.context/threat-feed/previous.json','null');
 await writeFile('.context/threat-feed/previous-manifest.json','null');
 console.log('First publication; no prior signed feed.');
}else{
 const manifest=JSON.parse(new TextDecoder().decode(bytes));
 await verifyThreatManifest(manifest,THREAT_CONFIG.keys,{allowSame:true});
 const payload=await downloadThreatFile(THREAT_CONFIG.artifactBase+manifest.artifact,MAX_FEED_BYTES);
 if(!payload)throw Error('Previous signed payload is unavailable');
 const verified=await verifyThreatBundle(manifest,payload,THREAT_CONFIG.keys,{allowSame:true});
 await writeFile('.context/threat-feed/previous.json',JSON.stringify(verified.payload));
 await writeFile('.context/threat-feed/previous-manifest.json',JSON.stringify(manifest));
}
