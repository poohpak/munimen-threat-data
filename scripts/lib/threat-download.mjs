export async function downloadThreatFile(url,limit,{fetcher=fetch,timeoutMs=60000}={}) {
 const response=await fetcher(url,{headers:{'User-Agent':'Munimen-threat-feed/1.0'},credentials:'omit',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(timeoutMs)});
 if(response.status===404)return null;
 if(!response.ok)throw Error(`Source HTTP ${response.status}`);
 const chunks=[];let size=0;const reader=response.body.getReader();
 try {while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit)throw Error('Source exceeds byte limit');chunks.push(value);}}
 finally{await reader.cancel().catch(()=>{});}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}return bytes;
}
