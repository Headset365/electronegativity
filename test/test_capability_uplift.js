import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import { campaignPlan, campaignFromPlan } from '../src/watch/campaign_plan.js';
import { createRequire } from 'node:module';
const { valueFor } = createRequire(import.meta.url)('../src/watch/campaign.cjs');
import * as asar from '@electron/asar';
import run from '../src/runner.js';
chaiShould();
await _i18n();
async function scan(files, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-uplift-'));
  try {
    for (const [name, text] of Object.entries({ 'package.json': '{"name":"uplift","main":"main.js","devDependencies":{"electron":"34.0.0"}}', ...files })) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), text);
    }
    return await run({ input: dir, offline: true, ...options });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

describe('Capability uplift', () => {
  it('traces deep links and second-instance fields through imported file helpers', async () => {
    const { issues } = await scan({
      'main.js': `import {app} from 'electron'; import {read} from './files.js';
app.on('open-url', (e,url) => read(url)); app.on('second-instance', (e,args) => read(args[1]));`,
      'files.js': `import fs from 'node:fs'; export function read(p) { return fs.readFileSync(p); }`,
    });
    const flows = issues.filter(i => i.id === 'FILE_HANDLER_JS_CHECK');
    flows.should.have.length(2);
    for (const flow of flows) {
      flow.properties.context.effects.some(e => e.kind === 'file-read').should.equal(true);
      flow.properties.context.helpers.some(e => e.file.endsWith('files.js')).should.equal(true);
    }
  });
  it('does not downgrade a protocol for an unrelated or late containment check', async () => {
    for (const guard of [`console.log('..');`, `if(!other.startsWith(root)) return;`, `fs.readFileSync(p); if(!p.startsWith(root)) return;`]) {
      const { issues } = await scan({ 'main.js': `import fs from 'fs'; protocol.handle('app', req => { const p=req.url; ${guard} return fs.readFileSync(p); });` });
      issues.filter(i => i.id === 'PROTOCOL_HANDLER_JS_CHECK').some(i => i.severity.name === 'HIGH').should.equal(true);
    }
  });
  it('attaches renderer paste and document-reader source traces across helpers', async () => {
    const { issues } = await scan({
      'main.js': `import {render} from './render.js'; document.addEventListener('paste', e => render(e.clipboardData.getData('text/html')));
const reader = new FileReader(); reader.onload = e => render(e.target.result);`,
      'render.js': `export function render(value) { document.body.innerHTML = value; }`,
    });
    const flows = issues.filter(i => i.id === 'RENDERER_INPUT_JS_CHECK' && ['paste','file-reader'].includes(i.properties?.event));
    flows.should.have.length(2);
    flows.every(i => i.properties.context.effects.some(e => e.kind === 'html-insertion')).should.equal(true);
  });
  it('follows download inputs into an imported shell helper', async () => {
    const { issues } = await scan({
      'main.js': `import {open} from './files.js'; session.defaultSession.on('will-download', (e,item) => open(item.getSavePath()));`,
      'files.js': `import {shell} from 'electron'; export function open(p) { shell.openPath(p); }`,
    });
    issues.find(i => i.id === 'DOWNLOAD_JS_CHECK').properties.context.effects.some(e => e.kind === 'shell-openPath').should.equal(true);
  });
  it('inspects imported validators and refuses constant-return or wrong-field helpers', async () => {
    const { issues } = await scan({
      'main.js': `import {ipcMain} from 'electron'; import fs from 'fs'; import {safePath, wrong, sender} from './guards.js';
ipcMain.handle('fake', (e,p) => { if(!safePath(p)) return; return fs.readFileSync(p); });
ipcMain.handle('wrong', (e,p,other) => { if(!wrong(p,other)) return; return fs.readFileSync(p); });
ipcMain.handle('creds', e => { if(!sender(e)) return; return 'secret'; });`,
      'guards.js': `export function safePath(p) { return true; } export function wrong(p,other) { return other.startsWith('/docs/'); } export function sender(e) { return true; }`,
    });
    for (const channel of ['fake','wrong']) {
      const context = issues.find(i => i.id === 'IPC_HANDLER_JS_CHECK' && i.properties.channel === channel).properties.context;
      context.effects.find(e => e.kind === 'file-read').pathControl.should.equal('not-recognized');
    }
    issues.some(i => i.id === 'IPC_SENDER_VALIDATION_JS_CHECK' && i.properties.channel === 'creds').should.equal(true);
  });
  it('resolves actual origin predicates across modules and maps window URLs and sessions', async () => {
    const { issues } = await scan({
      'main.js': `import {BrowserWindow,ipcMain} from 'electron'; import {sender} from './guards.js';
const w = new BrowserWindow({webPreferences:{preload:'preload.js',partition:'persist:trusted'}}); w.loadURL('https://example.com');
ipcMain.handle('read', e => { if(!sender(e.senderFrame)) return; return 'version'; });`,
      'guards.js': `export function sender(frame) { return frame && frame.origin === 'https://example.com'; }`,
      'preload.js': `const {ipcRenderer,contextBridge} = require('electron'); contextBridge.exposeInMainWorld('api',{read:()=>ipcRenderer.invoke('read')});`,
    });
    issues.some(i => i.id === 'IPC_SENDER_VALIDATION_JS_CHECK' && i.properties.channel === 'read').should.equal(false);
    const access = issues.find(i => i.id === 'IPC_CHANNEL_MAP_GLOBAL_CHECK').properties.windowAccess[0];
    access.partition.should.equal('persist:trusted');
    access.urls[0].value.should.equal('https://example.com');
    access.frameAccess.should.include('unverified');
  });

  it('generates non-executable finding-linked drafts and preserves other API object fields', async () => {
    const { issues } = await scan({
      'main.js': `const {ipcMain}=require('electron'); const fs=require('fs'); ipcMain.handle('open', (e,{filePath,recordId})=>fs.readFileSync(filePath));`,
      'preload.js': `const {contextBridge,ipcRenderer}=require('electron'); contextBridge.exposeInMainWorld('api',{open: p=>ipcRenderer.invoke('open',p)});`,
    });
    const plan = campaignPlan(issues);
    plan.executable.should.equal(false);
    const item = plan.items.find(i=>i.finding.channel==='open');
    item.profile.api.path.should.equal('api.open');
    item.profile.api.mutationPath.should.deep.equal(['filePath']);
    (()=>campaignFromPlan(plan,item.id,{})).should.throw();
    const profile = campaignFromPlan(plan,item.id,{capture:{method:'PUT',route:'https://example.com/test/{id}'},fields:['body'],view:'https://example.com/test/view',
      cases:['api-null'],api:{args:[{filePath:'test.txt',recordId:1}],mutationIndex:0}});
    const payload = valueFor('api-null','uplift_marker',{api:profile.api});
    payload.should.include('&quot;filePath&quot;:null,&quot;recordId&quot;:1');
    profile.api.args[0].filePath.should.equal('test.txt');
    const direct = campaignFromPlan(plan,item.id,{request:{method:'PUT',url:'https://example.com/test/1',body:'{"body":"original"}'},fields:['body'],view:'reload',cases:['text']});
    direct.mode.should.equal('request');
    (()=>campaignFromPlan(plan,item.id,{...profile,capture:{method:'PUT',route:'https://example.com/test/{id}'},api:{...profile.api,mutationPath:['__proto__']}})).should.throw();
  });

  it('scans packaged original sources across modules and retains bundles for incomplete maps', async () => {
    const map = {version:3,sources:['src/main.ts','src/files.ts'],sourcesContent:[
      `import fs from './files'; ipcMain.handle('read',(e,p)=>fs(p));`,
      `import fs from 'node:fs'; export default function read(p:string) { return fs.readFileSync(p); }`],mappings:''};
    const base = {'resources/app/package.json':'{"name":"packaged","main":"bundle.js","devDependencies":{"electron":"34.0.0"}}',
      'resources/app/bundle.js':'console.log(1);\n//# sourceMappingURL=bundle.js.map',
      'resources/app/bundle.js.map':JSON.stringify(map)};
    const {issues} = await scan(base);
    // The directory wrapper is a source checkout; packaged subfolder behavior is verified separately below.
    issues.filter(i=>i.properties?.sourceMap).should.have.length(0);
    const dir=fs.mkdtempSync(path.join(os.tmpdir(),'eng-packaged-'));
    try {
      const app=path.join(dir,'resources','app');fs.mkdirSync(app,{recursive:true});
      for (const [name,text] of Object.entries(base)) fs.writeFileSync(path.join(app,path.basename(name)),text);
      const recovered=await run({input:app,offline:true});
      const handler=recovered.issues.find(i=>i.id==='IPC_HANDLER_JS_CHECK');
      handler.properties.context.effects.some(e=>e.kind==='file-read').should.equal(true);
      handler.properties.sourceMap.source.should.equal(path.join('src','main.ts'));
      (await run({input:app,offline:true,sourceMaps:false})).issues.some(i=>i.id==='IPC_HANDLER_JS_CHECK').should.equal(false);
      map.sourcesContent[1]=null;fs.writeFileSync(path.join(app,'bundle.js.map'),JSON.stringify(map));
      const fallback=await run({input:app,offline:true});
      fallback.errors.some(e=>e.message.includes('bundle retained')).should.equal(true);
    } finally {fs.rmSync(dir,{recursive:true,force:true});}
  });

  it('recovers ASAR maps without extracting supplied source paths', async () => {
    const root=fs.mkdtempSync(path.join(os.tmpdir(),'eng-asar-map-'));
    try {
      const app=path.join(root,'app');fs.mkdirSync(app);
      fs.writeFileSync(path.join(app,'package.json'),'{"name":"mapped","main":"bundle.js","devDependencies":{"electron":"34.0.0"}}');
      fs.writeFileSync(path.join(app,'bundle.js'),'console.log(1);\n//# sourceMappingURL=bundle.js.map');
      fs.writeFileSync(path.join(app,'bundle.js.map'),JSON.stringify({version:3,sources:['main.ts'],sourcesContent:[`const {ipcMain}=require('electron');const fs=require('fs');ipcMain.handle('read',(e,p)=>fs.readFileSync(p));`],mappings:''}));
      const archive=path.join(root,'app.asar');await asar.createPackage(app,archive);
      const report=await run({input:archive,offline:true});
      report.issues.some(i=>i.id==='IPC_HANDLER_JS_CHECK'&&i.properties.sourceMap?.source==='main.ts').should.equal(true);
      fs.existsSync(path.join(archive,'~sources')).should.equal(false);
    } finally {fs.rmSync(root,{recursive:true,force:true});}
  });

});
