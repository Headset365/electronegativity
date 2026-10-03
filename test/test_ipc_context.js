import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { buildShare } from '../src/report/share.js';

chaiShould();
await _i18n();
const PACKAGE = '{"name":"ipc-context","main":"main.js","devDependencies":{"electron":"34.0.0"}}';
async function scan(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-ipc-context-'));
  try {
    for (const [name, text] of Object.entries({ 'package.json': PACKAGE, ...files })) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), text);
    }
    return (await run({ input: dir, offline: true })).issues;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const handler = (issues, channel) => issues.find(issue => issue.id === 'IPC_HANDLER_JS_CHECK' && issue.properties.channel === channel);

describe('IPC codebase context', () => {
  it('keeps a fallback handler reviewable when its contextual definition is incomplete', async () => {
    const issues = await scan({ 'main.js': `const { ipcMain } = require('electron');
const fs = require('node:fs');
function nested() { function read(event, filePath) { return fs.readFileSync(filePath); } }
ipcMain.handle('fallback-read', read);` });
    const item = handler(issues, 'fallback-read');
    item.should.exist;
    item.properties.context.status.should.equal('incomplete');
    item.properties.context.unresolved.some(entry => entry.reason === 'handler-unresolved').should.equal(true);
    item.properties.validatesArguments.should.equal(false);
  });

  it('follows namespace and reexported helpers to local file reads and network uploads', async () => {
    const issues = await scan({
      'main.js': `import { ipcMain } from 'electron'; import * as api from './api.js';
ipcMain.handle('import-file-upload', (event, {filePath, recordId}) => {
  if (typeof recordId !== 'number') return;
  return api.upload(filePath, recordId);
});`,
      'api.js': `export { upload } from './backend/upload.js';`,
      'backend/upload.js': `import fs from 'node:fs';
export function upload(p, id) { const data = fs.readFileSync(p); return fetch('https://example.com/upload/'+id, {method:'POST', body:data}); }`,
    });
    const item = handler(issues, 'import-file-upload');
    item.properties.capabilities.should.include.members(['files', 'network']);
    const context = item.properties.context;
    context.status.should.equal('analyzed');
    context.helpers.some(helper => /backend[\\/]upload\.js$/.test(helper.file)).should.equal(true);
    context.arguments.find(arg => arg.name === 'argument1.filePath').validation.should.equal('not-recognized');
    context.arguments.find(arg => arg.name === 'argument1.recordId').validation.should.equal('recognized-unverified');
    context.effects.find(effect => effect.kind === 'file-read').pathControl.should.equal('not-recognized');
    item.properties.validatesArguments.should.equal(false);
  });

  it('follows compiled CommonJS credential getters and maps the exact exposed member', async () => {
    const issues = await scan({
      'main.js': `const electron_1 = require('electron'); const auth_1 = require('./auth');
new electron_1.BrowserWindow({webPreferences:{preload:'main.preload.js'}});
electron_1.ipcMain.on('auth-get-token', event => { event.returnValue = auth_1.getSessionCreds(); });`,
      'auth.js': `let creds = {}; function getSessionCreds() { return {...creds}; } exports.getSessionCreds = getSessionCreds;`,
      'main.preload.js': `const electron_1 = require('electron');
electron_1.contextBridge.exposeInMainWorld('electronAPI', {auth: () => electron_1.ipcRenderer.sendSync('auth-get-token')});`,
    });
    const item = handler(issues, 'auth-get-token');
    item.properties.issue.should.equal('credential');
    item.properties.context.credentials[0].reference.should.equal('creds');
    const map = issues.find(issue => issue.id === 'IPC_CHANNEL_MAP_GLOBAL_CHECK' && issue.properties.channel === 'auth-get-token');
    map.properties.exposedAPIs[0].api.should.equal('window.electronAPI.auth');
    map.properties.windows.should.have.length(1);
    map.properties.context.credentials.should.have.length(1);
  });

  it('resolves TypeScript interop default objects and local aliases', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const api_1 = __importDefault(require('./api'));
const send = api_1.default.upload;
ipcMain.handle('upload', (event, p) => send(p));`,
      'api.js': `const fs = require('fs'); function upload(file) { return fs.readFileSync(file); } module.exports = {upload};`,
    });
    handler(issues, 'upload').properties.context.effects.some(effect => effect.kind === 'file-read').should.equal(true);
  });

  it('does not count guards after a write or guards inside a different branch', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const fs = require('fs');
ipcMain.handle('late', (event, p) => { fs.writeFileSync(p, 'x'); if(typeof p !== 'string') return; });
ipcMain.handle('branch', (event, p, enabled) => { if(enabled) { if(typeof p !== 'string') return; } fs.writeFileSync(p, 'x'); });`,
    });
    for (const channel of ['late', 'branch']) handler(issues, channel).properties.context.arguments.find(arg => arg.name === 'p').validation.should.equal('not-recognized');
  });

  it('follows argument-specific guards in a helper without calling a type check path containment', async () => {
    const issues = await scan({
      'main.js': `import {ipcMain} from 'electron'; import {write} from './files.js'; ipcMain.handle('write', (event, p, data) => write(p,data));`,
      'files.js': `import fs from 'fs'; export function write(p, data) { if(typeof p !== 'string') return; fs.writeFileSync(p,data); }`,
    });
    const context = handler(issues, 'write').properties.context;
    context.arguments.find(arg => arg.name === 'p').validation.should.equal('recognized-unverified');
    context.arguments.find(arg => arg.name === 'data').validation.should.equal('not-recognized');
    context.effects[0].pathControl.should.equal('not-recognized');
  });

  it('requires guards to reject, rather than merely calling a validator', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const fs = require('fs');
ipcMain.handle('unused-check', (event, p) => { isAllowedPath(p); fs.readFileSync(p); });`,
    });
    handler(issues, 'unused-check').properties.context.effects[0].pathControl.should.equal('not-recognized');
  });

  it('marks rejecting path checks as recognized but unverified', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const fs = require('fs');
ipcMain.handle('contained', (event,p) => { if(!isInsideDocs(p)) return; return fs.readFileSync(p); });`,
    });
    handler(issues, 'contained').properties.context.effects[0].pathControl.should.equal('recognized-unverified');
  });

  it('records callback writes while respecting callback parameter shadowing', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain,shell} = require('electron'); const fs = require('fs');
ipcMain.handle('docx', (event, {fileName,base64File}) => new Promise(resolve => {
 const filePath = fileName; fs.writeFile(filePath,base64File,'base64', err => {if(!err) shell.openPath(filePath);});
}));
ipcMain.handle('shadow', (event, p) => [1].forEach(p => fs.readFileSync(p)));`,
    });
    const effects = handler(issues, 'docx').properties.context.effects;
    effects.map(effect => effect.kind).should.include.members(['file-write', 'shell-openPath']);
    effects.find(effect => effect.kind === 'shell-openPath').pathArguments.should.include('argument1.fileName');
    handler(issues, 'shadow').properties.context.effects[0].arguments.should.not.include('p');
  });

  it('keeps unresolved handlers, dynamic channels and dynamic dispatch visible', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); import {missing} from './missing.js';
ipcMain.handle('missing',missing); ipcMain.handle(channel, (event,p) => handlers[p](p));`,
    });
    handler(issues, 'missing').properties.context.status.should.equal('incomplete');
    handler(issues, '*').properties.context.unresolved.some(item => item.reason === 'callee-unresolved').should.equal(true);
  });

  it('bounds recursive helper traversal and flags the incomplete context', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const {loop} = require('./loop'); ipcMain.handle('loop',(event,p)=>loop(p));`,
      'loop.js': `function loop(p) { return loop(p); } exports.loop=loop;`,
    });
    handler(issues, 'loop').properties.context.unresolved.some(item => item.reason === 'recursive-call').should.equal(true);
  });

  it('does not classify credentials used internally by a helper as returned credentials', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const {check} = require('./auth'); ipcMain.handle('check',()=>check());`,
      'auth.js': `const {safeStorage} = require('electron'); function check() { const secret=safeStorage.decryptString(Buffer.from('x')); return true; } exports.check=check;`,
    });
    handler(issues, 'check').properties.context.credentials.should.have.length(0);
  });

  it('finds module-state writers and their callers across the codebase', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain} = require('electron'); const auth = require('./auth');
ipcMain.on('session-ready', (event,model) => auth.setSessionModel(model));
ipcMain.on('auth-get-token', event => { event.returnValue = auth.getSessionCreds(); });`,
      'auth.js': `let creds={}; function setSessionModel(onLogin) { creds=onLogin.creds; } function getSessionCreds(){return {...creds};}
exports.setSessionModel=setSessionModel; exports.getSessionCreds=getSessionCreds;`,
    });
    const state = handler(issues, 'auth-get-token').properties.context.state[0];
    state.writes[0].source.should.equal('onLogin.creds');
    state.callers.some(caller => caller.writer === 'setSessionModel' && /main.js$/.test(caller.file)).should.equal(true);
  });

  it('handles every supported registration method and ipcMain aliases', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain: ipc} = require('electron');
ipc.on('a',event=>{}); ipc.once('b',event=>{}); ipc.addListener('c',event=>{});
ipc.handle('d',event=>{}); ipc.handleOnce('e',event=>{}); const register=ipc.handle; register('f',event=>{});`,
    });
    for (const channel of ['a','b','c','d','e','f']) {
      handler(issues, channel).properties.context.status.should.equal('analyzed');
      issues.some(issue => issue.id === 'IPC_SENDER_VALIDATION_JS_CHECK' && issue.properties?.channel === channel).should.equal(true);
    }
  });

  it('maps a preload helper to its fixed channel without calling it an arbitrary-channel API', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain,BrowserWindow}=require('electron'); new BrowserWindow({webPreferences:{preload:'preload.js'}}); ipcMain.handle('auth-get-token',()=>({}));`,
      'preload.js': `const {contextBridge}=require('electron'); const {request}=require('./bridge'); contextBridge.exposeInMainWorld('api',{auth:()=>request('auth-get-token')});`,
      'bridge.js': `const {ipcRenderer}=require('electron'); exports.request=function request(channel){return ipcRenderer.sendSync(channel);};`,
    });
    const api = issues.find(issue => issue.id === 'EXPOSED_API_JS_CHECK');
    api.properties.memberChannels.auth.should.deep.equal(['auth-get-token']);
    const map = issues.find(issue => issue.id === 'IPC_CHANNEL_MAP_GLOBAL_CHECK');
    map.properties.exposedAPIs[0].api.should.equal('window.api.auth');
    map.properties.windows.should.have.length(1);
  });

  it('retains multiple registrations of a channel in the map', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); ipcMain.on('a',event=>{}); ipcMain.on('a',event=>console.log('second'));
const {ipcRenderer}=require('electron'); ipcRenderer.send('a');`,
    });
    issues.find(issue => issue.id === 'IPC_CHANNEL_MAP_GLOBAL_CHECK').properties.handlers.should.have.length(2);
  });

  it('does not let an ignored basename transformation protect the original path', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const fs=require('fs'); const path=require('path');
ipcMain.handle('ignored',(event,p)=>{path.basename(p); return fs.readFileSync(p);});
ipcMain.handle('applied',(event,p)=>{const safe=path.basename(p); return fs.readFileSync(path.join('/docs',safe));});`,
    });
    handler(issues, 'ignored').properties.context.effects[0].pathControl.should.equal('not-recognized');
    handler(issues, 'applied').properties.context.effects[0].pathControl.should.equal('recognized-unverified');
  });

  it('distinguishes an extension check from path containment', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const fs=require('fs');
ipcMain.handle('docx',(event,p)=>{if(!p.endsWith('.docx')) return; fs.writeFileSync(p,'x');});`,
    });
    const effect = handler(issues,'docx').properties.context.effects[0];
    effect.extensionControl.should.equal('recognized-unverified');
    effect.pathControl.should.equal('not-recognized');
  });

  it('keeps opaque external helpers and bound class handlers distinguishable', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const upload=require('some-upload-library');
ipcMain.handle('opaque',(event,p)=>upload(p));
class Files { init(){ipcMain.handle('class',this.read.bind(this));} read(event,p){return requireFile(p);} }`,
    });
    handler(issues,'opaque').properties.context.unresolved[0].reason.should.equal('external-helper-opaque');
    handler(issues,'class').properties.context.unresolved[0].reason.should.equal('callee-unresolved');
  });

  it('does not suppress sender findings for a late guard or a guard in a callback', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron');
ipcMain.handle('late-sender',event=>{event.returnValue=getSecrets(); if(!trusted(event.senderFrame)) return;});
ipcMain.handle('callback-sender',event=>{setTimeout(()=>{if(!trusted(event.senderFrame)) return;}); return getSecrets();});`,
    });
    for (const channel of ['late-sender','callback-sender']) issues.some(issue => issue.id==='IPC_SENDER_VALIDATION_JS_CHECK' && issue.properties?.channel===channel).should.equal(true);
  });

  it('preserves contextual evidence in share reports without leaking nested absolute paths', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const {read}=require('./backend/files'); ipcMain.handle('read',(event,p)=>read(p));`,
      'backend/files.js': `const fs=require('fs'); exports.read=function read(p){return fs.readFileSync(p);};`,
    });
    const root = path.dirname(handler(issues,'read').file);
    const share = buildShare({input:root,issues});
    JSON.stringify(share).should.not.include(root);
    const context = share.findings.find(issue => issue.id==='IPC_HANDLER_JS_CHECK').properties.context;
    context.effects[0].file.should.equal('backend/files.js');
    context.helpers[0].file.should.equal('backend/files.js');
  });

  it('keeps different fields of an undestructured payload independent', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const fs=require('fs');
ipcMain.handle('payload',(event,payload)=>{if(typeof payload.recordId!=='number') return; return fs.readFileSync(payload.filePath);});`,
    });
    const context = handler(issues,'payload').properties.context;
    context.arguments.find(arg => arg.name==='payload.filePath').validation.should.equal('not-recognized');
    context.effects[0].pathControl.should.equal('not-recognized');
  });

  it('follows credential returns through Promise resolvers', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const {getSessionCreds}=require('./auth');
ipcMain.handle('promise',()=>new Promise(resolve=>resolve(getSessionCreds())));`,
      'auth.js': `let creds={}; exports.getSessionCreds=function getSessionCreds(){return {...creds};};`,
    });
    handler(issues,'promise').properties.context.credentials[0].reference.should.equal('creds');
  });

  it('does not let a type guard bypass an unresolved upload helper', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const fs=require('fs'); const api=require('upload-library');
ipcMain.handle('upload',(event,p)=>{if(typeof p!=='string') return; fs.statSync(p); return api.upload(p);});`,
    });
    const item = handler(issues,'upload');
    item.properties.context.status.should.equal('incomplete');
    item.properties.validatesArguments.should.equal(false);
  });

  it('reports an incomplete analysis when the call budget is exhausted', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const fs=require('fs');
ipcMain.handle('many',(event,p)=>{${'fs.statSync(p);'.repeat(170)}});`,
    });
    handler(issues,'many').properties.context.unresolved.some(item => item.reason==='call-budget').should.equal(true);
  });

  it('follows returned credential aliases and properties, but not secrets passed to a boolean helper', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const auth=require('./auth');
ipcMain.handle('alias',()=>auth.alias()); ipcMain.handle('property',()=>auth.property()); ipcMain.handle('verify',()=>auth.verify());`,
      'auth.js': `let creds={}; const settings={}; function check(password){return true;}
exports.alias=function alias(){const result=creds; return result;};
exports.property=function property(){return settings.accessToken;};
exports.verify=function verify(){return check(settings.password);};`,
    });
    handler(issues,'alias').properties.context.credentials.some(item => item.reference==='creds').should.equal(true);
    handler(issues,'property').properties.context.credentials.some(item => item.reference==='accessToken').should.equal(true);
    handler(issues,'verify').properties.context.credentials.should.have.length(0);
  });

  it('follows ipcMain and ipcRenderer object aliases', async () => {
    const issues = await scan({
      'main.js': `const e=require('electron'); const ipc=e.ipcMain; ipc.handle('a',event=>{});`,
      'preload.js': `const {ipcRenderer:r,contextBridge}=require('electron'); contextBridge.exposeInMainWorld('api',{call:()=>r.invoke('a')});`,
    });
    handler(issues,'a').properties.context.status.should.equal('analyzed');
    issues.find(issue => issue.id==='EXPOSED_API_JS_CHECK').properties.memberChannels.call.should.deep.equal(['a']);
  });

  it('does not turn a renderer event subscription into permission to invoke a main handler', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); ipcMain.handle('secret',()=>({}));`,
      'preload.js': `const {ipcRenderer,contextBridge}=require('electron'); contextBridge.exposeInMainWorld('api',{listen:()=>ipcRenderer.on('secret',()=>{})});`,
    });
    const map = issues.find(issue => issue.id==='IPC_CHANNEL_MAP_GLOBAL_CHECK');
    map.properties.exposedAPIs.should.have.length(0);
    map.properties.senders.should.have.length(0);
  });

  it('resolves interop default functions and arrow-function state setters', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const getter=__importDefault(require('./getter')); const {set}=require('./state');
ipcMain.handle('get',()=>getter.default()); ipcMain.on('set',(event,model)=>set(model));`,
      'getter.js': `const {get}=require('./state'); module.exports=function getter(){return get();};`,
      'state.js': `let creds={}; const set=model=>{creds=model.creds;}; exports.set=set; exports.get=()=>({...creds});`,
    });
    const context=handler(issues,'get').properties.context;
    context.credentials.some(item=>item.reference==='creds').should.equal(true);
    context.state[0].callers.some(item=>item.writer==='set').should.equal(true);
  });

  it('follows application helpers instead of assuming their names are native APIs', async () => {
    const issues = await scan({
      'main.js': `const {ipcMain}=require('electron'); const api=require('./helpers');
ipcMain.handle('file',(event,p)=>api.openPath(p)); ipcMain.handle('password',()=>api.getPassword());`,
      'helpers.js': `const fs=require('fs'); exports.openPath=p=>fs.readFileSync(p); exports.getPassword=()=>false;`,
    });
    handler(issues,'file').properties.capabilities.should.not.include('shell');
    handler(issues,'file').properties.context.effects[0].kind.should.equal('file-read');
    handler(issues,'password').properties.context.credentials.should.have.length(0);
    handler(issues,'password').properties.should.not.have.property('issue','credential');
  });
});
