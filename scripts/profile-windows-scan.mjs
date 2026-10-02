import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
fs.mkdirSync('scan-profile',{recursive:true});
const asar=fs.readdirSync('trilium',{recursive:true}).find(n=>n.endsWith('resources'+path.sep+'app.asar'));
if(!asar)throw Error('Release app.asar missing');
const child=spawn(process.execPath,['--max-old-space-size=6144','--inspect=127.0.0.1:9330','src/index.js','-i',path.join('trilium',asar),'--all-files','--offline','--no-source-maps','-o','report.json','--out','scan-profile'],{stdio:['ignore','pipe','pipe']});
for(const [stream,name] of [[child.stdout,'stdout.log'],[child.stderr,'stderr.log']]) stream.on('data',d=>fs.appendFileSync('scan-profile/'+name,d));
let target;for(let i=0;i<60&&!target;i++){try{target=(await(await fetch('http://127.0.0.1:9330/json/list')).json())[0];}catch{}if(!target)await new Promise(r=>setTimeout(r,500));}
if(!target)throw Error('Scanner inspector absent');
const ws=new WebSocket(target.webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
let id=0;const pending=new Map();ws.onmessage=e=>{const m=JSON.parse(e.data),p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result)}};
const send=(method,params={})=>new Promise((resolve,reject)=>{const key=++id;pending.set(key,{resolve,reject});ws.send(JSON.stringify({id:key,method,params}));});
await send('Profiler.enable');await send('Profiler.setSamplingInterval',{interval:1000});await send('Profiler.start');
await new Promise(r=>setTimeout(r,90000));
const {profile}=await send('Profiler.stop');fs.writeFileSync('scan-profile/scanner.cpuprofile',JSON.stringify(profile));
const hits=new Map();for(const sample of profile.samples||[])hits.set(sample,(hits.get(sample)||0)+1);
const hot=profile.nodes.map(n=>({...n.callFrame,samples:hits.get(n.id)||0})).sort((a,b)=>b.samples-a.samples).slice(0,80);fs.writeFileSync('scan-profile/hot-functions.json',JSON.stringify(hot,null,2));console.log(JSON.stringify(hot.slice(0,15),null,2));
ws.close();child.kill();setTimeout(()=>process.exit(0),1000);
