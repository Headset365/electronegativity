// Regressions from the DivorceMate 2.1.2 review: TypeScript's (0, mod.fn)(...) calls, state a page sets through IPC
// that decides where windows load and credentials go, write-then-open handlers, allowlists in helpers, allowed windows
// child preload configuration, and the shortcut and second-instance false positives.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Parser } from '../src/parser/index.js';
import run from '../src/runner.js';
import _i18n from '../src/locales/i18n.js';

await _i18n();

describe('Gaps from the DivorceMate review', () => {
  let root;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-dm-')); });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const app = (files) => {
    const dir = path.join(root, 'app');
    for (const [name, content] of Object.entries({ 'package.json': JSON.stringify({ name: 'dm', main: 'out/app.js', devDependencies: { electron: '38.0.0' } }), ...files })) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), content);
    }
    return dir;
  };
  const scan = async (files, checks) => (await run({ input: app(files), offline: true, customScan: checks })).issues;

  it('reads (0, module.fn)(…) as module.fn(…), as TypeScript and Babel compile imported calls', () => {
    const [, data] = new Parser(false, true).parse('x.js', 'const cp = require("node:child_process"); (0, cp.exec)("lsof " + f);');
    const call = data.body[1].expression;
    assert.equal(call.callee.type, 'MemberExpression');
    assert.equal(call.callee.property.name, 'exec');
  });

  it('finds a shell command built from a variable through a compiled call', async () => {
    const issues = await scan({ 'out/check.js': 'const node_child_process_1 = require("node:child_process");\nfunction openInMac(filePath) { (0, node_child_process_1.exec)(\'lsof "\' + filePath + \'"\', () => {}); }\nmodule.exports = { openInMac };' },
      ['commandinjectionjscheck']);
    assert.equal(issues.filter(issue => issue.id === 'COMMAND_INJECTION_JS_CHECK').length, 1);
  });

  it('follows a page-supplied value stored in module state to window loads and credentialed requests', async () => {
    const issues = await scan({
      'out/auth.js': `const electron_1 = require("electron");
let endpoints = { api: '', ui: 'https://app.example.com' };
let creds = {};
function setLoginModel(model) { creds = model.creds; endpoints = model.endpoints; }
function getEndpoints() { return { ...endpoints }; }
function getAuthCreds() { return { ...creds }; }
exports.setLoginModel = setLoginModel; exports.getEndpoints = getEndpoints; exports.getAuthCreds = getAuthCreds;`,
      'out/login.js': `const electron_1 = require("electron");\nconst auth_1 = require("./auth");
electron_1.ipcMain.handle('login-success', (event, model) => { (0, auth_1.setLoginModel)(model); });`,
      'out/main.window.js': `const electron_1 = require("electron");\nconst auth_1 = require("./auth");
function createMainWindow() { const w = new electron_1.BrowserWindow({ webPreferences: { preload: 'p.js' } }); w.loadURL((0, auth_1.getEndpoints)().ui); return w; }
exports.createMainWindow = createMainWindow;`,
      'out/api.js': `const axios = require("axios");\nconst auth_1 = require("./auth");
function upload(form) { return axios.post((0, auth_1.getEndpoints)().api + 'blobs', form, { headers: { Authorization: 'Bearer ' + (0, auth_1.getAuthCreds)().token } }); }
exports.upload = upload;`,
    }, ['ipcstatedestinationjscheck']);
    const found = issues.filter(issue => issue.id === 'IPC_STATE_DESTINATION_JS_CHECK');
    assert.equal(found.length, 1);
    assert.equal(found[0].severity.name, 'HIGH');
    assert.deepEqual(found[0].properties.loads, ['out/main.window.js']);
    assert.deepEqual(found[0].properties.credentialed, ['out/api.js']);
  });

  it('rates a handler that writes a page-named file and opens it as HIGH', async () => {
    const issues = await scan({ 'out/files.js': `const electron_1 = require("electron");\nconst fs_1 = require("fs");\nconst path_1 = require("path");
electron_1.ipcMain.handle('file-open-docx', (event, { base64File, fileName, matterId }) => {
  const filePath = path_1.join('/data', 'matter_' + matterId, fileName);
  fs_1.writeFile(filePath, base64File, 'base64', () => { electron_1.shell.openPath(filePath); });
});` }, ['ipchandlerjscheck']);
    assert.ok(issues.some(issue => issue.id === 'IPC_HANDLER_JS_CHECK' && issue.severity.name === 'HIGH' && issue.properties.issue === 'write-then-open'));
  });

  it('reads helper allowlists and avoids assuming preload inheritance without child options', async () => {
    const issues = await scan({ 'out/window.js': `const electron_1 = require("electron");\nconst node_url_1 = require("node:url");
const whitelistHosts = ['app.example.com', 'partner.example.net'];
function isAllowedUrl(target) { const host = new node_url_1.URL(target).hostname; return whitelistHosts.some(a => host === a || host.endsWith(\`.\${a}\`)); }
function windowCommonConfig(win) {
  win.webContents.setWindowOpenHandler(({ url }) => isAllowedUrl(url) ? { action: 'allow' } : { action: 'deny' });
  win.webContents.on('will-navigate', (event, url) => { if (!isAllowedUrl(url)) event.preventDefault(); });
}
const main = new electron_1.BrowserWindow({ webPreferences: { preload: 'main.preload.js' } });
windowCommonConfig(main);` }, ['limitnavigationjscheck', 'windowopenhandlerjscheck']);
    const navigation = issues.find(issue => issue.id === 'LIMIT_NAVIGATION_JS_CHECK' && issue.properties.event === 'will-navigate');
    assert.equal(navigation.severity.name, 'MEDIUM');
    assert.equal(navigation.properties.hostOnly, true);
    assert.equal(navigation.properties.subdomains, true);
    assert.deepEqual(navigation.properties.hosts, ['app.example.com', 'partner.example.net']);
    const open = issues.find(issue => issue.id === 'WINDOW_OPEN_HANDLER_JS_CHECK');
    assert.equal(open.severity.name, 'LOW');
    assert.equal(open.properties.inheritsPreload, false);
    assert.equal(open.properties.childPreloadConfigured, false);
  });

  it('does not rate the app’s own shortcut or a switch-only second-instance handler', async () => {
    const issues = await scan({ 'out/app.js': `const electron_1 = require("electron");\nconst path_1 = require("path");
electron_1.shell.writeShortcutLink(path_1.join(electron_1.app.getPath('desktop'), 'Calc.lnk'), { target: process.execPath, args: '--quick-calc' });
electron_1.app.on('second-instance', (event, commandLine) => { if (commandLine.includes('--quick-calc')) showCalc(); else focusMain(); });
electron_1.app.on('second-instance', (event, commandLine) => { openDocument(commandLine[1]); });` }, ['writeshortcutjscheck', 'filehandlerjscheck']);
    assert.equal(issues.find(issue => issue.id === 'WRITE_SHORTCUT_JS_CHECK').severity.name, 'INFORMATIONAL');
    const handlers = issues.filter(issue => issue.id === 'FILE_HANDLER_JS_CHECK').map(issue => issue.severity.name).sort();
    assert.deepEqual(handlers, ['INFORMATIONAL', 'MEDIUM']);
  });
});
