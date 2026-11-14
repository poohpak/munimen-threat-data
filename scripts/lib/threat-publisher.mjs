import {copyFile as copy} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
// The CLI verifies the signed payload before calling this transport layer.
export async function publishThreatSnapshot({target,manifest,previousVersion=0,directory='.context/threat-feed',gh=(args)=>execFileSync('gh',args,{encoding:'utf8'}),copyFile=copy}){
 const repo=['--repo',target],version=manifest.version,day=manifest.generatedAt.slice(0,10);
 if(!/^\d{4}-\d{2}-\d{2}$/.test(day))throw Error('Invalid archive day');
 const archive=`threat-archive-${day}`;
 const ensure=(tag,notes)=>{try{gh(['release','view',tag,...repo]);}catch{gh(['release','create',tag,...repo,'--title',tag,'--notes',notes,'--latest=false']);}};
 ensure(archive,'Immutable signed threat data, original source receipts and upstream licenses.');
 const audit=[];
 for(const[input,output]of [['manifest.json',`manifest-${version}.json`],['source.json',`source-${version}.json`],['LICENSE.txt',`LICENSE-${version}.txt`]]){
  const destination=`${directory}/${output}`;await copyFile(`${directory}/${input}`,destination);audit.push(destination);
 }
 // An archive failure cannot publish an unauditable stable pointer.
 gh(['release','upload',archive,...repo,`${directory}/${manifest.artifact}`,...audit]);
 ensure('threat-feed','Signed host reputation data. See status.json for operational status.');
 gh(['release','upload','threat-feed',...repo,`${directory}/${manifest.artifact}`]);
 gh(['release','upload','threat-feed',...repo,`${directory}/manifest.json`,'--clobber']);
 // Keep a bounded stable endpoint. The archive retains the full history.
 // Cleanup failure is maintenance debt, never a failed activation report.
 try{
  const assets=JSON.parse(gh(['release','view','threat-feed',...repo,'--json','assets'])).assets;
  const keep=new Set([String(version),String(previousVersion)]);
  for(const asset of assets){
   const match=/^threats-(\d+)\.json$/.exec(asset.name);
   if(match&&!keep.has(match[1]))gh(['release','delete-asset','threat-feed',asset.name,...repo,'--yes']);
  }
  return {version,archive,maintenancePending:false};
 }catch{return {version,archive,maintenancePending:true};}
}
