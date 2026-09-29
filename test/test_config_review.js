import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { directiveProblems } from '../src/finder/checks/GlobalChecks/ConfigReviewGlobalChecks.js';
import { readCacheEntry, reviewCaches } from '../src/storage/at_rest.js';
import { sourceMapIssues } from '../src/production/sourcemaps.js';
import { interactionOf, consequenceOf } from '../src/finder/consequences.js';
import { splitOutputs, unwritableOutput } from '../src/util/file.js';
import { maskCode, buildShare } from '../src/report/share.js';
import { createReportFolder, reportFolderName, reportFiles } from '../src/util/reportdir.js';

chaiShould();
await _i18n();

const tmp = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
async function scan(files, options = {}, sub = '') {
  const dir = tmp('eng-config-review-');
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, sub, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, sub, name), content);
  }
  const result = await run({ input: path.join(dir, sub), offline: true, ...options });
  return { dir, issues: result.issues, of: (id) => result.issues.filter(i => i.id === id) };
}
const PACKAGE = '{"name":"app","main":"main.js","devDependencies":{"electron":"30.0.0"}}';

describe('Configuration review checks', () => {
  describe('IPC handlers', () => {
    const main = `
const { app, ipcMain, BrowserWindow, shell } = require('electron');
const fs = require('fs');
const path = require('path');
const Store = require('electron-store');
const store = new Store();
const root = app.getPath('documents');
const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js') } });
ipcMain.handle('read-doc', (event, file) => fs.readFileSync(file, 'utf8'));
ipcMain.handle('save-export', async (event, name, data) => {
  await fs.promises.writeFile(path.join(app.getPath('downloads'), path.basename(name)), data);
});
ipcMain.handle('safe-read', (event, name) => {
  const full = path.resolve(root, name);
  if (!full.startsWith(root)) throw new Error('outside');
  return fs.readFileSync(full);
});
ipcMain.handle('get-token', () => store.get('authToken'));
ipcMain.handle('get-theme', () => store.get('theme'));
ipcMain.on('focus-window', (event, id) => { BrowserWindow.fromId(id).focus(); });
ipcMain.handle('open-doc', (event, p) => { if (typeof p !== 'string') return; shell.openPath(p); });
ipcMain.handle('debug-dump', () => process.memoryUsage());`;
    const preload = `
const { contextBridge, ipcRenderer, clipboard } = require('electron');
const fs = require('fs');
contextBridge.exposeInMainWorld('api', {
  read: (f) => ipcRenderer.invoke('read-doc', f),
  save: (n, d) => ipcRenderer.invoke('save-export', n, d),
  token: () => ipcRenderer.invoke('get-token'),
  theme: () => ipcRenderer.invoke('get-theme'),
  focus: (id) => ipcRenderer.send('focus-window', id),
  open: (p) => ipcRenderer.invoke('open-doc', p),
  safe: (p) => ipcRenderer.invoke('safe-read', p),
});
contextBridge.exposeInMainWorld('util', { copy(t) { clipboard.writeText(t); }, load: (p) => fs.readFileSync(p) });`;

    it('reports renderer-chosen paths reaching the file system, with the Windows name pitfalls', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': main, 'preload.js': preload });
      const found = of('IPC_FILE_ACCESS_JS_CHECK').filter(i => /main\.js$/.test(i.file));
      found.map(i => [i.location.line, i.severity.name]).should.deep.equal([[9, 'HIGH'], [11, 'LOW'], [16, 'LOW']]);
      found[0].description.should.match(/UNC/);
      found[1].properties.hygiene.should.equal(true);
      found[1].description.should.match(/reserved names.*alternate data streams/);
      // the preload's own file access, reachable from the page through contextBridge
      of('IPC_FILE_ACCESS_JS_CHECK').some(i => /preload\.js$/.test(i.file) && i.severity.name === 'HIGH').should.equal(true);
    });

    it('does not take isAbsolute or names that merely contain "valid" for a folder check', async () => {
      const handlers = `const { ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
ipcMain.handle('read-a', (e, p) => { if (!path.isAbsolute(p)) return; return fs.readFileSync(p); });
ipcMain.handle('read-b', (e, p) => { cache.invalidate(); return fs.readFileSync(p); });
ipcMain.handle('read-c', (e, p) => { if (!isInsideDocs(p)) return; return fs.readFileSync(p); });`;
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': handlers });
      const found = of('IPC_FILE_ACCESS_JS_CHECK').filter(i => /main\.js$/.test(i.file)).map(i => [i.location.line, i.severity.name]);
      found.should.deep.include([4, 'HIGH']);
      found.should.deep.include([5, 'HIGH']);
      found.some(([line, sev]) => line === 6 && sev === 'HIGH').should.equal(false);
    });

    it('does not take includes, normalize or isAbsolute for a folder check in a protocol handler', async () => {
      const handlers = `const { protocol, net } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
protocol.handle('a', (request) => { const u = request.url; if (u.includes('?')) return; return net.fetch(pathToFileURL(path.join(__dirname, new URL(u).pathname)).toString()); });
protocol.handle('b', (request) => net.fetch(pathToFileURL(path.normalize(path.join(__dirname, new URL(request.url).pathname))).toString()));
protocol.handle('c', (request) => { const p = new URL(request.url).pathname; if (/\\.\\./.test(p)) return; return net.fetch(pathToFileURL(path.join(__dirname, p)).toString()); });
protocol.handle('d', (request) => { const p = path.resolve(__dirname, new URL(request.url).pathname.slice(1)); if (!isInsideApp(p)) return; return net.fetch(pathToFileURL(p).toString()); });`;
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': handlers });
      of('PROTOCOL_HANDLER_JS_CHECK').map(i => [i.location.line, i.severity.name]).should.deep.equal([[4, 'HIGH'], [5, 'HIGH'], [6, 'LOW'], [7, 'LOW']]);
    });

    it('lists what each handler does, and flags unchecked arguments, window targeting and credentials sent back', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': main, 'preload.js': preload });
      const byChannel = (channel) => of('IPC_HANDLER_JS_CHECK').filter(i => i.properties.channel === channel);
      byChannel('read-doc')[0].properties.should.include({ issue: 'unvalidated', validatesArguments: false });
      byChannel('read-doc')[0].properties.capabilities.should.include('files');
      byChannel('save-export')[0].severity.name.should.equal('INFORMATIONAL'); // path.basename counts as a check
      byChannel('get-token').map(i => i.properties.issue).should.deep.equal(['credential']);
      byChannel('get-theme')[0].severity.name.should.equal('INFORMATIONAL');
      byChannel('focus-window').map(i => i.properties.issue).should.deep.equal(['window-target']);
      byChannel('open-doc')[0].properties.should.include({ validatesArguments: true });
    });

    it('does not count logging a sender or an unused type expression as validation', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': `
const { ipcMain, shell } = require('electron');
ipcMain.handle('read', (event, filename) => {
  console.log(event.senderFrame.url);
  const unused = typeof filename;
  return shell.openPath(filename);
});` });
      of('IPC_SENDER_VALIDATION_JS_CHECK').some(i => i.properties.channel === 'read').should.equal(true);
      const handler = of('IPC_HANDLER_JS_CHECK').find(i => i.properties.channel === 'read');
      handler.properties.validatesArguments.should.equal(false);
      handler.properties.issue.should.equal('unvalidated');
    });

    it('maps each channel to the preloads that send it and the windows loading them', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': main, 'preload.js': preload });
      const map = of('IPC_CHANNEL_MAP_GLOBAL_CHECK');
      const read = map.find(i => i.properties.channel === 'read-doc');
      read.properties.windows.should.deep.equal(['main.js:8']);
      read.properties.senders.map(f => path.basename(f)).should.deep.equal(['preload.js']);
      const dead = map.find(i => i.properties.channel === 'debug-dump');
      dead.severity.name.should.equal('LOW');
      dead.description.should.match(/no scanned renderer code sends it/);
    });

    it('says what each exposed preload member can do', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': main, 'preload.js': preload });
      const api = of('EXPOSED_API_JS_CHECK').find(i => i.properties.world === 'api');
      api.properties.channels.should.include.members(['read-doc', 'get-token']);
      api.description.should.match(/uses ipc \(read-doc/);
      const util = of('EXPOSED_API_JS_CHECK').find(i => i.properties.world === 'util');
      util.properties.capabilities.should.deep.equal({ copy: ['clipboard'], load: ['files'] });
    });

    it('inventories direct window globals that contextBridge does not cover', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'preload.js': `
window.files = { open: (p) => require('fs').readFileSync(p) };
Object.assign(window, { bridge: () => 1, count: 2 });
Object.defineProperty(window, 'legacy', { value: () => 1 });
window.location = '/home';` });
      const globals = of('GLOBAL_EXPOSURE_JS_CHECK');
      globals.flatMap(i => i.properties.members).should.include.members(['files', 'bridge', 'count', 'legacy']);
      globals.flatMap(i => i.properties.members).should.not.include('location');
      globals.every(i => i.severity.name === 'INFORMATIONAL').should.equal(true);
    });

    it('treats a pass-through preload as reaching every channel', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': `
const { ipcMain, BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { preload: 'bridge.js' } });
ipcMain.handle('admin-reset', () => 1);`, 'bridge.js': `
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('bridge', { invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args) });` });
      const reset = of('IPC_CHANNEL_MAP_GLOBAL_CHECK')[0];
      reset.description.should.match(/reachable through the pass-through in bridge\.js/);
    });
  });

  describe('Windows, navigation and CSP', () => {
    const files = {
      'package.json': PACKAGE,
      'main.js': `
const { BrowserWindow } = require('electron');
const path = require('path');
const main = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js') } });
const viewer = new BrowserWindow({ webPreferences: { sandbox: true } });
const isolated = new BrowserWindow({ webPreferences: { partition: 'persist:docs' } });
main.webContents.on('will-navigate', (event, url) => { if (!url.startsWith('https://app.example.com/')) event.preventDefault(); });
main.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));`,
      'preload.js': '',
      'index.html': `<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; img-src *; connect-src https:; style-src 'self' 'unsafe-inline'"></head></html>`,
      'viewer.html': `<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; img-src *; connect-src https:; style-src 'self' 'unsafe-inline'"></head></html>`,
    };

    it('reports windows of different privilege sharing a session', async () => {
      const { of } = await scan(files);
      const shared = of('WINDOW_SESSION_GLOBAL_CHECK');
      shared.should.have.length(1);
      shared[0].severity.name.should.equal('LOW');
      shared[0].properties.should.deep.include({ partition: 'default', privileged: ['main.js:4'], unprivileged: ['main.js:5'] });
      of('WINDOW_SUMMARY_JS_CHECK').some(i => i.properties.partition === 'persist:docs').should.equal(true);
    });

    it('reports a will-navigate allowlist that server redirects get around, unless a redirect handler blocks', async () => {
      (await scan(files)).of('NAVIGATION_REDIRECT_GLOBAL_CHECK').should.have.length(1);
      const guarded = { ...files, 'main.js': files['main.js'] + `
main.webContents.on('will-redirect', (event, url) => { if (!url.startsWith('https://app.example.com/')) event.preventDefault(); });` };
      (await scan(guarded)).of('NAVIGATION_REDIRECT_GLOBAL_CHECK').should.have.length(0);
      const logging = { ...files, 'main.js': files['main.js'] + `
main.webContents.on('will-redirect', (event, url) => console.log(url));` };
      (await scan(logging)).of('NAVIGATION_REDIRECT_GLOBAL_CHECK')[0].confidence.name.should.equal('TENTATIVE');
    });

    it('rates the CSP directives csp-evaluator leaves out, and notes one policy for every page', async () => {
      const { of } = await scan(files);
      const found = of('CSP_DIRECTIVES_GLOBAL_CHECK');
      found.filter(i => i.properties.directives).map(i => i.properties.directives).should.deep.equal([
        ['connect-src', 'img-src', 'style-src', 'form-action'], ['connect-src', 'img-src', 'style-src', 'form-action']]);
      found.some(i => i.properties.sharedPolicy).should.equal(true);
      directiveProblems("default-src 'none'; form-action 'self'").should.deep.equal([]);
      directiveProblems("default-src *; form-action 'self'").map(p => p.directive).should.deep.equal(['frame-src', 'connect-src', 'img-src', 'style-src']);
      directiveProblems("default-src 'self'; frame-src blob:; style-src 'self'; form-action 'none'").map(p => p.text).should.deep.equal(['frame-src allows data: or blob: documents']);
    });
  });

  describe('Production build', () => {
    const main = `
const { app, BrowserWindow, ipcMain } = require('electron');
const fs = require('fs');
const isDev = process.env.NODE_ENV === 'development';
const log = require('electron-log');
log.transports.file.level = 'debug';
const win = new BrowserWindow({});
if (isDev) { win.loadURL('http://localhost:3000'); ipcMain.handle('dev-reset', () => fs.rmSync(app.getPath('userData'), { recursive: true })); }
if (!app.isPackaged) require('electron-reload')(__dirname);
if (!app.isPackaged) log.transports.console.level = 'silly';
win.loadURL('http://127.0.0.1:5173/index.html');`;

    it('reports development behavior left in, and what switches it on', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': main });
      of('DEVELOPMENT_CODE_JS_CHECK').map(i => [i.location.line, i.severity.name, i.properties.gate]).should.deep.equal([
        [8, 'LOW', 'env'], [8, 'LOW', 'env'], [11, 'MEDIUM', 'none']]);
      of('DEBUG_LOGGING_JS_CHECK').map(i => i.location.line).should.deep.equal([6]);
    });

    it('reports the source maps a packaged app ships, with or without the original sources', async () => {
      const dir = tmp('eng-maps-');
      const app = path.join(dir, 'resources', 'app');
      fs.mkdirSync(app, { recursive: true });
      fs.writeFileSync(path.join(app, 'renderer.js'), 'console.log(1)\n//# sourceMappingURL=renderer.js.map');
      fs.writeFileSync(path.join(app, 'renderer.js.map'), JSON.stringify({ version: 3, sources: ['src/a.ts'], sourcesContent: ['const a = 1'], mappings: '' }));
      const inline = Buffer.from(JSON.stringify({ version: 3, sources: ['b.ts'], mappings: '' })).toString('base64');
      fs.writeFileSync(path.join(app, 'other.js'), `x()\n//# sourceMappingURL=data:application/json;base64,${inline}`);
      const [issue] = sourceMapIssues(app, { packaged: true });
      issue.severity.name.should.equal('LOW');
      issue.properties.should.deep.equal({ maps: 1, inline: 1, withSources: 1 });
      sourceMapIssues(app, { packaged: false }).should.deep.equal([]);
      // through the runner, for a packaged app only
      (await run({ input: app, offline: true })).issues.filter(i => i.id === 'SOURCE_MAP_SHIPPED').should.have.length(1);
      (await run({ input: app, offline: true, excludeFromScan: ['SourceMapsCheck'] })).issues.filter(i => i.id === 'SOURCE_MAP_SHIPPED').should.have.length(0);
    });
  });

  describe('Word and documents', () => {
    const main = `
const { ipcMain, shell } = require('electron');
const { execFile, exec } = require('child_process');
ipcMain.handle('open-in-word', (event, name) => { exec(\`start winword "\${name}"\`); });
ipcMain.handle('open-word-2', (event, file) => { execFile('C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE', ['/t', file]); });
ipcMain.handle('ofe', (event, url) => shell.openExternal('ms-word:ofe|u|' + url));
function openLocal(file) { execFile('winword.exe', [file]); }
function preview(doc) { shell.openPath(doc + '.docx'); }
module.exports = { openLocal, preview };`;

    it('reports how Word is found and started, and what content controls', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': main });
      const found = of('WORD_LAUNCH_JS_CHECK');
      found.map(i => [i.location.line, i.severity.name]).should.deep.equal([[4, 'HIGH'], [5, 'MEDIUM'], [6, 'HIGH'], [7, 'LOW'], [8, 'LOW']]);
      found[0].properties.shell.should.equal(true);
      found[1].properties.should.deep.include({ locate: 'at a fixed path', flags: ['/t'] });
      found[3].properties.locate.should.match(/PATH/);
      found[4].description.should.match(/extension is not checked/);
    });

    it('lists the document parsers by process and flags their risky options and zip slip', async () => {
      const { of } = await scan({ 'package.json': PACKAGE, 'main.js': `
const { ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const libxml = require('libxmljs');
const mammoth = require('mammoth');
const JSZip = require('jszip');
const MarkdownIt = require('markdown-it');
const md = new MarkdownIt({ html: true });
ipcMain.handle('parse', (event, xml) => libxml.parseXml(xml, { noent: true }));
ipcMain.handle('docx', (event, buf) => mammoth.convertToHtml({ buffer: buf }, { externalFileAccess: true }));
async function unzip(buf, dir) { const zip = await JSZip.loadAsync(buf); zip.forEach(async (relativePath, entry) => { fs.writeFileSync(path.join(dir, relativePath), await entry.async('nodebuffer')); }); }
async function unzipSafe(buf, dir) { const zip = await JSZip.loadAsync(buf); zip.forEach(async (relativePath, entry) => { const to = path.resolve(dir, relativePath); if (!to.startsWith(dir)) return; fs.writeFileSync(to, await entry.async('nodebuffer')); }); }
module.exports = { unzip, unzipSafe };` });
      const found = of('DOCUMENT_PIPELINE_JS_CHECK');
      found.filter(i => i.properties.library && i.severity.name === 'INFORMATIONAL').map(i => [i.properties.library, i.properties.process]).should.deep.equal([
        ['libxmljs', 'main'], ['mammoth', 'main'], ['jszip', 'main'], ['markdown-it', 'main']]);
      found.filter(i => i.severity.name !== 'INFORMATIONAL').map(i => [i.location.line, i.severity.name]).should.deep.equal([[9, 'LOW'], [10, 'HIGH'], [11, 'MEDIUM'], [12, 'HIGH']]);
    });
  });

  describe('Evidence', () => {
    it('says what the victim has to do for each kind of finding', () => {
      interactionOf('OPEN_EXTERNAL_JS_CHECK').should.equal('A click on a crafted link');
      interactionOf('XSS_SINK_JS_CHECK').should.equal('Viewing the content');
      interactionOf('CERTIFICATE_ERROR_EVENT_JS_CHECK').should.match(/network/);
      interactionOf('WINDOW_SUMMARY_JS_CHECK').should.equal('Not applicable');
    });

    it('has a consequence for every new check', () => {
      for (const id of ['IPC_FILE_ACCESS_JS_CHECK', 'IPC_HANDLER_JS_CHECK', 'IPC_CHANNEL_MAP_GLOBAL_CHECK', 'WINDOW_SESSION_GLOBAL_CHECK', 'NAVIGATION_REDIRECT_GLOBAL_CHECK',
        'CSP_DIRECTIVES_GLOBAL_CHECK', 'DEVELOPMENT_CODE_JS_CHECK', 'DEBUG_LOGGING_JS_CHECK', 'WORD_LAUNCH_JS_CHECK', 'DOCUMENT_PIPELINE_JS_CHECK', 'SOURCE_MAP_SHIPPED',
        'RUNTIME_REDIRECT', 'RUNTIME_PRELOAD_FOREIGN_ORIGIN', 'RUNTIME_WINDOW_SESSION', 'STORAGE_CACHED_RESPONSES'])
        (consequenceOf(id) !== undefined).should.equal(true, id);
    });
  });

  describe('Cached responses at rest', () => {
    // a Chromium simple cache entry: magic, version, key length, key hash, padding, key, body
    const entry = (key, body) => {
      const header = Buffer.alloc(24);
      Buffer.from('305c72a71b6dfbfc', 'hex').copy(header, 0);
      header.writeUInt32LE(5, 8);
      header.writeUInt32LE(Buffer.byteLength(key), 12);
      return Buffer.concat([header, Buffer.from(key), Buffer.from(body)]);
    };

    it('reads the URL and body of a cache entry', () => {
      const read = readCacheEntry(entry('1/0/_dk_https://a.test https://a.test https://a.test/api/me?x=1', '{"ok":1}'));
      read.url.should.equal('https://a.test/api/me?x=1');
      String(read.body).should.equal('{"ok":1}');
      (readCacheEntry(Buffer.from('not a cache entry, long enough')) === undefined).should.equal(true);
    });

    it('counts cached responses by host and finds secrets in them', () => {
      const profile = tmp('eng-cache-');
      const dir = path.join(profile, 'Cache', 'Cache_Data');
      fs.mkdirSync(dir, { recursive: true });
      const token = ['sk_live_', 'Cz9Lm2Vt9Rk4Zp8Wn3Yb6Hs7Tx'].join('');
      fs.writeFileSync(path.join(dir, '0123456789abcdef_0'), entry('1/0/_dk_https://a.test https://a.test https://a.test/api/me?session=1', JSON.stringify({ apiToken: token })));
      fs.writeFileSync(path.join(dir, 'fedcba9876543210_0'), entry('https://cdn.test/logo.png', 'PNG'));
      const out = reviewCaches(profile);
      out.stores['HTTP cache'].should.deep.equal({ entries: 2, hosts: { 'a.test': 1, 'cdn.test': 1 } });
      out.secrets.should.have.length(1);
      out.secrets[0].url.should.equal('https://a.test/api/me');
      out.secrets[0].shown.should.not.include(token);
    });
  });

  describe('Output options', () => {
    it('takes -o lists separated by commas, or by spaces as PowerShell passes an unquoted list', () => {
      splitOutputs('a.html,b.json').should.deep.equal(['a.html', 'b.json']);
      splitOutputs('a.html b.json c.cdx.json d.sarif e.docx').should.deep.equal(['a.html', 'b.json', 'c.cdx.json', 'd.sarif', 'e.docx']);
      splitOutputs('my report.html').should.deep.equal(['my report.html']);
    });

    it('writes every -o format for each step of a guided run (--app)', function () {
      this.timeout(120000);
      const out = tmp('eng-guided-');
      const app = path.join(import.meta.dirname, 'apps', 'vulnerable-app');
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--app', app, '--sessions', '0', '--offline', '--out', out,
        '-o', 'report.html,findings.md,components.xlsx', '--share', 'shareable-report.md'];
      const result = spawnSync(process.execPath, cli, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      result.status.should.equal(0, result.stderr);
      for (const file of ['static-report.html', 'static-findings.md', 'static-components.xlsx', 'static-share.md', 'static-diag.json'])
        fs.existsSync(path.join(out, file)).should.equal(true, file);
      fs.readFileSync(path.join(out, 'static-findings.md'), 'utf8').should.include('# Renderer Isolation Weakened');
      fs.rmSync(out, { recursive: true, force: true });
    });

    it('finds an output folder that cannot be written before the scan starts', () => {
      (unwritableOutput([path.join(tmp('eng-out-'), 'r.html')]) === undefined).should.equal(true);
      unwritableOutput([path.join(os.tmpdir(), 'no-such-folder-eng', 'r.html')]).reason.should.equal('ENOENT');
    });
  });

  describe('Shareable report (--share)', () => {
    const TOKEN = ['ghp_', 'Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs7Tx4Wv1Yp8Nb2Qm'].join('');
    const files = {
      'package.json': '{"name":"acmematters","productName":"Acme Matters","main":"main.js","devDependencies":{"electron":"30.0.0"},"author":"Contoso Legal"}',
      'main.js': `
const { BrowserWindow, ipcMain, shell } = require('electron');
const { exec } = require('child_process');
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });
win.loadURL('https://portal.acmematters.example/app?tenant=contoso-legal');
ipcMain.handle('open-in-word', (event, name) => { exec(\`start winword "\${name}"\`); });
ipcMain.handle('link', (event, url) => shell.openExternal(url));
const support = 'jane.doe@contoso.example';
const token = '${TOKEN}';
const server = 'http://10.20.30.40:8080/api';
fetch('http://10.20.30.40:8080/api');`,
    };

    it('keeps what judging a finding needs and removes what identifies the app', async () => {
      const dir = tmp('eng-share-');
      const app = path.join(dir, 'AcmeMatters');
      fs.mkdirSync(app);
      for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(app, name), content);
      const md = path.join(dir, 'share.md');
      const json = path.join(dir, 'share.json');
      await run({ input: app, offline: true, share: md, redact: ['Contoso'] });
      await run({ input: app, offline: true, share: json, shareCode: true, redact: ['Contoso'] });
      for (const file of [md, json]) {
        const text = fs.readFileSync(file, 'utf8');
        for (const leak of ['acmematters', 'Acme Matters', 'AcmeMatters', 'Contoso', 'contoso', 'portal.', 'tenant=', 'jane.doe', '10.20.30.40', TOKEN, dir])
          text.should.not.include(leak, `${path.basename(file)} leaks ${leak}`);
      }
      const markdown = fs.readFileSync(md, 'utf8');
      markdown.should.match(/### WORD_LAUNCH_JS_CHECK/);
      markdown.should.match(/`main\.js:6`/);
      markdown.should.not.include('```js'); // code only with --share-code
      const report = JSON.parse(fs.readFileSync(json, 'utf8'));
      const word = report.findings.find(f => f.id === 'WORD_LAUNCH_JS_CHECK');
      word.should.include({ severity: 'HIGH', file: 'main.js', line: 6, exploitableBy: 'Shared content' });
      word.code.should.equal('ipcMain.handle(\'open-in-word\', (event, name) => { exec(`start winword "${name}"`); });');
      report.counts.total.should.equal(report.findings.length);
    });

    it('preserves structured versions and full arrays while redacting bare hosts', () => {
      const report = buildShare({ input: '/work/demo', version: '2.0.0', issues: [{
        id: 'TEST', file: '/work/demo/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'portal.example.test and https://portal.example.test/path?private=1', manualReview: true,
        validation: { status: 'observed', text: 'Seen on portal.example.test, script not proven' },
        properties: { package: 'electron', version: '34.5.8', advisories: Array.from({ length: 25 }, (_, i) => `CVE-2025-${String(i).padStart(4, '0')}`), name: 'sample@1.2.3' }
      }] });
      report.findings[0].properties.advisories.should.have.length(25);
      report.findings[0].properties.name.should.equal('sample@1.2.3');
      report.findings[0].properties.version.should.equal('34.5.8');
      JSON.stringify(report).should.not.include('portal.example.test').and.not.include('private=1');
      report.findings[0].runtimeEvidence.should.include('host-');
    });

    it('removes client identity that only shows in package.json links, bare domains, UNC paths and ids', async () => {
      const dir = tmp('eng-share-id-');
      const app = path.join(dir, 'app');
      fs.mkdirSync(app);
      fs.writeFileSync(path.join(app, 'package.json'), JSON.stringify({ name: 'desk', main: 'main.js', devDependencies: { electron: '30.0.0' },
        author: 'Jo <jo@northwind-legal.com>', homepage: 'https://desk.northwind-legal.com', repository: 'github:northwindlaw/desk-client', build: { copyright: 'Copyright 2024 Northwind Holdings' } }));
      fs.writeFileSync(path.join(app, 'main.js'), `
const { BrowserWindow, shell, ipcMain } = require('electron');
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });
// sign in at sso.northwind-legal.com, cookies for .northwind-legal.com, share \\\\fs01\\cases, id 3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b
ipcMain.handle('link', (event, url) => shell.openExternal(url));`);
      const json = path.join(dir, 'share.json');
      await run({ input: app, offline: true, share: json });
      const text = fs.readFileSync(json, 'utf8');
      for (const leak of ['northwind', 'Northwind', 'desk-client', 'fs01', '3f2b8c1e', 'jo@', dir]) text.should.not.include(leak, `leaks ${leak}`);
      JSON.parse(text).audit.finalPassReplacements.should.be.a('number');
    });

    it('leaves code samples out when the run used --show-secrets, as they can hold full secret values', () => {
      const issues = [{ id: 'TRAFFIC_SECRET_IN_URL', file: 'runtime', location: { line: 0 }, severity: { name: 'HIGH' }, confidence: { name: 'FIRM' },
        description: 'secret in a URL', sample: 'GET https://api.test/x?jwt=REVEALEDSECRETVALUE0123456789abcdef' }];
      const revealed = buildShare({ input: '/work/demo', version: '2.0.0', issues, code: true, reveal: true });
      (revealed.findings[0].code === undefined).should.equal(true);
      JSON.stringify(revealed).should.not.include('REVEALEDSECRET');
      revealed.about.should.include('--show-secrets');
      buildShare({ input: '/work/demo', version: '2.0.0', issues, code: true }).findings[0].code.should.be.a('string');
    });

    it('does not treat punctuation after a scheme as a host, which would replace every comma in the report', () => {
      const report = buildShare({ input: '/work/demo', version: '2.0.0', code: true, issues: [{
        id: 'TEST', file: '/work/demo/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'loaded over file:// (extra), see (324 critical, 1214 high), 12 of them; urls like "https://, " and ws://, wss://',
        sample: "ipcMain.on('is-mac', event => { const scheme = ['http://', 'https://,']; })" }] });
      report.findings[0].description.should.equal('loaded over file:// (extra), see (324 critical, 1214 high), 12 of them; urls like "https://, " and ws://, wss://');
      report.findings[0].code.should.include("ipcMain.on('is-mac', event").and.not.include('host-');
    });

    it('replaces cookie domains with a leading dot, random-looking names and numeric ids in paths', () => {
      const report = buildShare({ input: '/work/demo', version: '2.0.0', issues: [{
        id: 'TEST', file: '/work/demo/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'cookie ph_phc_tRgYsMLEaQgFz9uCcRwscqRC0h5vI6GDL1huLHiz8A2_posthog for .tracker.example-corp.com and .www.example-corp.com from https://cdn.example-corp.net/release-asset/599254612/file' }] });
      const text = report.findings[0].description;
      text.should.not.include('tRgYs').and.not.include('example-corp').and.not.include('599254612');
      text.should.match(/for \.host-[0-9a-f]{8} and \.host-[0-9a-f]{8} from/).and.include('<id>');
    });

    it('keeps documentation links and Electron API names that look like domains', () => {
      const report = buildShare({ input: '/work/demo', version: '2.0.0', issues: [{
        id: 'TEST', file: '/work/demo/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'see www.electronjs.org and electron.net, then sso.customer-x.com and customer-x.dev' }] });
      const text = report.findings[0].description;
      text.should.include('www.electronjs.org').and.include('electron.net');
      text.should.not.include('customer-x');
    });

    it('replaces names left in fields no earlier step covers, keeping earlier placeholders whole', () => {
      const report = buildShare({ input: '/work/AcmeDesk', version: '2.0.0', redact: ['red'], issues: [{
        id: 'TEST', file: '/work/AcmeDesk/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'plain text', properties: { source: 'x' } }] });
      report.audit.finalPassReplacements.should.equal(0);
      JSON.stringify(report).should.not.include('AcmeDesk');
      const clean = buildShare({ input: '/work/demo', version: '2.0.0', redact: ['red', 'edac'], issues: [{
        id: 'TEST', file: '/work/demo/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'a red flag at user@site.example.test' }] });
      clean.findings[0].description.should.equal('a <redacted> flag at <email>');
    });

    it('replaces hosts named like code (app., api.), newer endings and hosts in runtime evidence', () => {
      const report = buildShare({ input: '/work/demo', version: '2.0.0', issues: [{
        id: 'TEST', file: '/work/demo/main.js', location: { line: 1 }, severity: { name: 'LOW' }, confidence: { name: 'FIRM' },
        description: 'calls app.getPath at app.contoso.com, api.contoso.co.uk and portal.contoso.ai',
        validation: { status: 'confirmed', text: 'https://billing.contoso.ai/admin loaded; also sso.contoso.me' } }] });
      JSON.stringify(report.findings).should.not.include('contoso');
      report.findings[0].description.should.include('app.getPath');
    });

    it('withholds the text of findings that carry secret values when the run used --show-secrets', () => {
      const issues = [{ id: 'TRAFFIC_SECRET_IN_RESPONSE', file: 'runtime', location: { line: 0 }, severity: { name: 'HIGH' }, confidence: { name: 'FIRM' },
        description: 'session=custom-format-value-7Hq2 in a response', validation: { status: 'confirmed', text: 'seen custom-format-value-7Hq2' } }];
      const revealed = buildShare({ input: '/work/demo', version: '2.0.0', issues, reveal: true });
      JSON.stringify(revealed).should.not.include('custom-format-value');
      revealed.findings[0].description.should.include('withheld');
      buildShare({ input: '/work/demo', version: '2.0.0', issues }).findings[0].description.should.include('in a response');
    });

    it('masks strings that could carry data in code, keeping code tokens', () => {
      const same = (text) => text;
      maskCode("store.get('Acme'); ipcMain.handle('open-doc', f)", same).should.equal("store.get('<str>'); ipcMain.handle('open-doc', f)");
      maskCode('x = `Hello ${name}, from Jane` // note', same).should.equal('x = `… ${name}… from …`');
      maskCode("const t = 'Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs7Tx4W'", same).should.equal("const t = '<str>'");
    });
  });
  describe('Report folder (--report-dir)', () => {
    it('names the folder after the UTC date and time, safe for Windows', () => {
      reportFolderName(new Date('2026-09-28T14:30:05.123Z')).should.equal('electronegativity-2026-09-28T14-30-05Z');
    });

    it('creates it inside the given folder, making that folder if needed, and never reuses a folder', () => {
      const parent = path.join(tmp('eng-reports-'), 'nested', 'reports');
      const when = new Date('2026-09-28T14:30:05Z');
      const first = createReportFolder(parent, when);
      const second = createReportFolder(parent, when);
      path.dirname(first).should.equal(path.resolve(parent));
      path.basename(first).should.equal('electronegativity-2026-09-28T14-30-05Z');
      path.basename(second).should.equal('electronegativity-2026-09-28T14-30-05Z-2');
      fs.statSync(first).isDirectory().should.equal(true);
      fs.statSync(second).isDirectory().should.equal(true);
    });

    it('fails when the parent is a file', () => {
      const file = path.join(tmp('eng-reports-'), 'file');
      fs.writeFileSync(file, '');
      (() => createReportFolder(file)).should.throw();
    });

    it('lays out the report, shareable report and diagnostics files', () => {
      const files = reportFiles('/r');
      files.outputs.map(f => path.basename(f)).should.deep.equal(['report.html', 'report.json']);
      files.shares.map(f => path.basename(f)).should.deep.equal(['shareable-report.md', 'shareable-report.json']);
      path.basename(files.diagnostics).should.equal('diagnostics.json');
    });
  });
});
