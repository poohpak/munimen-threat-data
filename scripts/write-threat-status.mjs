import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {THREAT_CONFIG} from '../src/threat-config.js';
import {FRESH_MS} from '../src/threat-bundle.js';
const dir='.context/threat-feed',read=async file=>readFile(`${dir}/${file}`,'utf8').then(JSON.parse,()=>null);
await mkdir(dir,{recursive:true});
const source=await read('source.json'),previous=await read('previous-manifest.json'),published=process.env.FEED_PUBLICATION_OUTCOME==='success'?await read('manifest.json'):null;
const active=published||previous,checkedAt=new Date().toISOString(),sourcePublishedAt=source?.sourcePublishedAt||null;
const sourceIsStale=sourcePublishedAt&&Date.now()-Date.parse(sourcePublishedAt)>FRESH_MS;
const status={schemaVersion:1,checkedAt,source:source?.source||'https://github.com/Phishing-Database/Phishing.Database',sourceRevision:source?.sourceRevision||null,sourcePublishedAt,dataRevisions:source?.dataRevisions||[],
 state:published?'published':sourceIsStale?'withheld-stale-source':'withheld',
 reason:published?'Signed data passed publication checks.':sourceIsStale?'Upstream data files exceed the 72-hour limit. No replacement feed was published.':'Publication did not complete. Consult the public workflow log.',
 activeVersion:active?.version||null,activeSourcePublishedAt:active?.sourcePublishedAt||null,
 manifestURL:THREAT_CONFIG.manifestURL,workflowURL:process.env.GITHUB_SERVER_URL&&process.env.GITHUB_REPOSITORY&&process.env.GITHUB_RUN_ID?`${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`:null,
 securityNotice:'Informational status only. The extension accepts only a signed manifest and verified data, never this status file.'};
await writeFile(`${dir}/status.json`,JSON.stringify(status,null,2));console.log(status);
