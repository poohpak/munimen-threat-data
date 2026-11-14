import {execFileSync} from 'node:child_process';
import {THREAT_CONFIG} from '../src/threat-config.js';
const target=/^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/threat-feed\/manifest\.json$/.exec(THREAT_CONFIG.manifestURL)?.[1];
if(!target)throw Error('Expected a GitHub Releases endpoint');
const repository=JSON.parse(execFileSync('gh',['repo','view',target,'--json','visibility'],{encoding:'utf8'}));
if(repository.visibility!=='PUBLIC')throw Error('Status endpoint must be public');
try{execFileSync('gh',['release','view','threat-feed','--repo',target],{stdio:'ignore'});}
catch{execFileSync('gh',['release','create','threat-feed','--repo',target,'--title','Munimen signed threat data','--notes-file','RELEASE_NOTES.md'],{stdio:'inherit'});}
execFileSync('gh',['release','upload','threat-feed','--repo',target,'.context/threat-feed/status.json','public-keys.json','--clobber'],{stdio:'inherit'});
