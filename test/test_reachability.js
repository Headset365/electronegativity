import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import run from '../src/runner.js';
import { Parser } from '../src/parser/parser.js';
import { ProjectIndex } from '../src/finder/project_index.js';
import { ReachabilityIndex, applyRuntimeReachability } from '../src/finder/reachability.js';
import { severity, confidence } from '../src/finder/attributes.js';
import { groupClientFindings, renderClientMarkdown } from '../src/report/markdown.js';
import { mergeFindingEvidence } from '../src/finder/validation.js';
import _i18n from '../src/locales/i18n.js';
await _i18n();
const unsafe = 'new BrowserWindow({webPreferences:{nodeIntegration:true}});';
describe('Conservative static reachability and runtime overlays', () => {
  let root;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-reachability-')); });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (name, value) => { const file = path.join(root, name); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, value); return file; };
  async function scan(main, files = {}) {
    write('package.json', JSON.stringify({ main: 'main.js', devDependencies: { electron: '38.2.0' } }));
    write('main.js', `const {BrowserWindow,app,ipcMain}=require('electron');\n${main}`);
    for (const [file, code] of Object.entries(files)) write(file, code);
    const result = await run({ input: root, offline: true, dependencies: false, allFiles: true, customScan: ['NodeIntegrationJSCheck'], nvd: false });
    return result.issues.filter(i => i.id === 'NODE_INTEGRATION_JS_CHECK');
  }
  it('keeps reachable entry statements and imported helpers rated, but downgrades a closed unused function', async () => {
    const issues = await scan(`function unused(){${unsafe}}\nfunction used(){${unsafe}}\nused();\nrequire('./helper');`, { 'helper.js': `const {BrowserWindow}=require('electron'); ${unsafe}` });
    assert.equal(issues.filter(i => i.reachability.staticStatus === 'unreferenced').length, 1);
    assert.equal(issues.filter(i => i.reachability.staticStatus === 'called').length, 2);
    assert.ok(issues.filter(i => i.reachability.staticStatus === 'called').every(i => i.severity === severity.HIGH && !i.reachability.exercised));
    assert.equal(issues.find(i => i.reachability.staticStatus === 'unreferenced').severity, severity.INFORMATIONAL);
  });
  it('follows imported function references through callbacks and preserves registered IPC handlers', async () => {
    const issues = await scan(`const {create}=require('./helper'); app.whenReady().then(create); ipcMain.handle('window',()=>{${unsafe}});`, {
      'helper.js': `const {BrowserWindow}=require('electron'); exports.create=function(){${unsafe}};`
    });
    assert.equal(issues.length, 2); assert.ok(issues.every(i => i.severity === severity.HIGH));
    assert.ok(issues.every(i => i.reachability.staticStatus === 'called'));
  });
  for (const [guard, status] of [['!app.isPackaged', 'development-only'], ['app.isPackaged', 'called'], ['isDev', 'called']])
    it(`handles production guard ${guard} without assuming unknown isDev semantics`, async () => {
      const issues = await scan(`if(${guard}){${unsafe}}`); assert.equal(issues[0].reachability.staticStatus, status);
      assert.equal(issues[0].severity, status === 'development-only' ? severity.INFORMATIONAL : severity.HIGH);
    });
  it('handles the alternate branch and electron-is-dev import, but retains ratings for shadowed app bindings', async () => {
    const issues = await scan(`if(app.isPackaged){}else{${unsafe}}\nconst isDev=require('electron-is-dev'); if(isDev){${unsafe}}`);
    assert.ok(issues.every(i => i.reachability.staticStatus === 'development-only'));
    const shadow = await scan(`function callback(app){if(!app.isPackaged){${unsafe}}} app.on('event',callback);`);
    assert.equal(shadow[0].severity, severity.HIGH);
  });
  for (const dynamic of ["require(getPlugin());", "eval('callback()');", 'new Function(source);', "import(getPlugin());"])
    it(`retains an unused finding in an open graph (${dynamic})`, async () => {
      const issues = await scan(`function callback(){${unsafe}} ${dynamic}`);
      assert.equal(issues[0].severity, severity.HIGH); assert.equal(issues[0].reachability.staticStatus, 'unresolved');
    });
  it('keeps exported plugin modules and findings with a missing entry point unresolved', async () => {
    const issues = await scan('', { 'plugin.js': `const {BrowserWindow}=require('electron'); exports.create=()=>{${unsafe}};` });
    assert.equal(issues[0].severity, severity.HIGH); assert.equal(issues[0].reachability.staticStatus, 'unresolved');
    write('package.json', JSON.stringify({ main: 'missing.js' }));
    const result = await run({ input: root, offline: true, dependencies: false, customScan: ['NodeIntegrationJSCheck'] });
    assert.ok(result.issues.filter(i => i.id === 'NODE_INTEGRATION_JS_CHECK').every(i => i.severity === severity.HIGH));
  });
  function ipcGraph(preload, renderer = '') {
    const files = new Map([['package.json', '{"main":"main.js"}'], ['main.js', 'require("./preload");'], ['preload.js', preload], ['ui.js', renderer], ['index.html', '<script src="ui.js"></script>']]);
    const loader = { list_files: [...files.keys()], load_buffer: file => Buffer.from(files.get(file)) };
    const parser = new Parser(false, true), index = new ProjectIndex(loader, parser), reach = new ReachabilityIndex(index);
    for (const [file, code] of files) if (/\.js$/.test(file)) { const [, ast] = parser.parse(file, code); reach.collect(file, ast, code); }
    const issue = { id: 'IPC_HANDLER_JS_CHECK', properties: { channel: 'save-file' }, severity: severity.HIGH, confidence: confidence.FIRM,
      file: 'main.js', location: { line: 1, column: 0 }, description: 'IPC file capability' };
    reach.annotate([issue]); return issue;
  }
  it('retains an unused preload capability and remote-UI note, while recording packaged direct senders', () => {
    const preload = 'const {contextBridge,ipcRenderer}=require("electron"); contextBridge.exposeInMainWorld("api",{save:()=>ipcRenderer.invoke("save-file")});';
    const exposed = ipcGraph(preload); assert.equal(exposed.reachability.staticStatus, 'exposed'); assert.equal(exposed.severity, severity.HIGH);
    assert.match(exposed.reachability.reason, /remote UI or injected script/);
    const called = ipcGraph(preload, 'const {ipcRenderer}=require("electron"); ipcRenderer.invoke("save-file");');
    assert.equal(called.reachability.staticStatus, 'called');
    const generic = ipcGraph('const {contextBridge,ipcRenderer}=require("electron"); contextBridge.exposeInMainWorld("api",{invoke:channel=>ipcRenderer.invoke(channel)});');
    assert.equal(generic.reachability.staticStatus, 'exposed');
  });
  it('never promotes all RPC procedures because the multiplexed channel was observed', () => {
    const issues = ['saveFile', 'deleteFile'].map(procedure => ({ id: 'IPC_RPC_PROCEDURE_JS_CHECK', properties: { procedure }, severity: severity.MEDIUM,
      reachability: { staticStatus: 'exposed', label: 'Exposed but not called', exercised: false, originalSeverity: 'MEDIUM' } }));
    applyRuntimeReachability(issues, { usedChannelNames: ['electron-trpc'], usedProcedures: ['files.saveFile'] });
    assert.equal(issues[0].reachability.exercised, true); assert.equal(issues[1].reachability.exercised, false);
  });
  it('restores a reduced rating when runtime use contradicts the static graph, retaining that evidence across later scans', () => {
    const issue = { id: 'IPC_HANDLER_JS_CHECK', properties: { channel: 'read' }, severity: severity.INFORMATIONAL,
      reachability: { staticStatus: 'unreferenced', originalSeverity: 'HIGH', exercised: false } };
    applyRuntimeReachability([issue], { usedChannelNames: ['read'] });
    assert.equal(issue.severity, severity.HIGH); assert.equal(issue.reachability.label, 'Exercised'); assert.ok(issue.reachability.contradiction);
    const merged = mergeFindingEvidence(issue, { ...issue, severity: severity.INFORMATIONAL, reachability: { exercised: false, staticStatus: 'unreferenced' } });
    assert.equal(merged.severity, severity.HIGH); assert.equal(merged.reachability.exercised, true);
  });
  it('renders unused and development statements as N/A Additional Security Observations with removal advice', async () => {
    const issues = await scan(`function unused(){${unsafe}} if(!app.isPackaged){${unsafe}}`);
    const groups = groupClientFindings(issues); assert.equal(groups.length, 1); assert.equal(groups[0].definition[0], 'Additional Security Observations');
    assert.deepEqual(groups[0].rating, { consequence: 'N/A', likelihood: 'N/A' });
    const markdown = renderClientMarkdown(issues, { input: root, app: { name: 'Example' } });
    assert.match(markdown, /Unreferenced/); assert.match(markdown, /Development-only/); assert.match(markdown, /Remove unused/);
    assert.equal(markdown.includes('serious harm'), false);
  });
  it('labels global and dependency findings unresolved without changing their rating', async () => {
    write('package.json', JSON.stringify({ main: 'main.js' })); write('main.js', 'const x=1;');
    const result = await run({ input: root, offline: true, dependencies: false });
    assert.ok(result.issues.length); assert.ok(result.issues.filter(i => !/^RUNTIME_/.test(i.id)).every(i => i.reachability));
  });
  it('retains the production downgrade for expected development-only use in an unpackaged session', () => {
    const issue = { id: 'IPC_HANDLER_JS_CHECK', properties: { channel: 'debug' }, severity: severity.INFORMATIONAL,
      reachability: { staticStatus: 'development-only', originalSeverity: 'HIGH', exercised: false } };
    applyRuntimeReachability([issue], { packaged: false, usedChannelNames: ['debug'] });
    assert.equal(issue.reachability.exercised, true); assert.equal(issue.severity, severity.INFORMATIONAL); assert.equal(issue.reachability.staticStatus, 'development-only');
  });
  it('resolves duplicate leaf procedure names through an explicitly registered nested router', async () => {
    write('package.json', JSON.stringify({ main: 'main.js', devDependencies: { electron: '38.2.0' } }));
    write('main.js', `const fs=require('fs'); const {createIPCHandler}=require('electron-trpc/main');
const first=t.router({saveFile:t.procedure.input(schema).mutation(({input})=>fs.writeFileSync(input.path,input.data))});
const second=t.router({saveFile:t.procedure.input(schema).mutation(({input})=>fs.writeFileSync(input.path,input.data))});
const root=t.router({files:first,other:second}); createIPCHandler({router:root});`);
    const result = await run({ input: root, offline: true, dependencies: false, customScan: ['IpcRpcProcedureJSCheck'] });
    assert.deepEqual(result.issues.filter(i => i.id === 'IPC_RPC_PROCEDURE_JS_CHECK').map(i => i.properties.procedurePath).sort(), ['files.saveFile', 'other.saveFile']);
  });
});
