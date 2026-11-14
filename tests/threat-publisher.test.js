import test from 'node:test';import assert from 'node:assert/strict';
import {publishThreatSnapshot} from '../scripts/lib/threat-publisher.mjs';
const manifest={version:3,generatedAt:'2026-11-15T00:00:00Z',artifact:'threats-3.json'},target='test/data';
function fixture(fail){const calls=[];return{calls,gh:args=>{calls.push(args);if(fail?.(args))throw Error('transport');if(args.includes('--json'))return JSON.stringify({assets:[{name:'threats-1.json'},{name:'threats-2.json'},{name:'threats-3.json'},{name:'status.json'},{name:'manifest.json'}]});return '';},copyFile:async()=>{}};}
test('archive and payload precede pointer publication; cleanup retains current and previous payloads',async()=>{
 const f=fixture();const result=await publishThreatSnapshot({...f,target,manifest,previousVersion:2});
 const uploads=f.calls.filter(a=>a[1]==='upload');
 assert.equal(uploads[0][2],'threat-archive-2026-11-15');assert(uploads[0].includes('.context/threat-feed/source-3.json'));
 assert.equal(uploads[1][2],'threat-feed');assert(uploads[1].includes('.context/threat-feed/threats-3.json'));
 assert(uploads[2].includes('.context/threat-feed/manifest.json'));
 const removals=f.calls.filter(a=>a[1]==='delete-asset');assert.equal(removals.length,1);assert.equal(removals[0][3],'threats-1.json');assert.equal(result.maintenancePending,false);
});
test('archive failure never switches the stable manifest',async()=>{
 const f=fixture(a=>a[1]==='upload'&&a[2].startsWith('threat-archive'));
 await assert.rejects(publishThreatSnapshot({...f,target,manifest}));
 assert(!f.calls.some(a=>a[1]==='upload'&&a[2]==='threat-feed'));
});
test('cleanup failure reports maintenance debt after a successful pointer publication',async()=>{
 const f=fixture(a=>a[1]==='delete-asset');const result=await publishThreatSnapshot({...f,target,manifest,previousVersion:2});
 assert.equal(result.maintenancePending,true);assert(f.calls.some(a=>a.includes('--clobber')));
});
