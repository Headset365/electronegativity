import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import net from 'node:net';
import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
import * as asar from '@electron/asar';
import run from '../src/runner.js';
import { analyzeWatchLog, readWatchLog } from '../src/watch/analyze.js';
import { watchDebug, connectDebug } from '../src/watch/debug.js';
import { createAssistant, followLog } from '../src/watch/assistant.js';
import { resolveApp } from '../src/watch/launch.js';
import { readFuseWire, analyzePackagedFuses, fuseBinaryFor } from '../src/watch/fuses.js';
import { reconcileRuntime } from '../src/watch/reconcile.js';
import { locateApp } from '../src/watch/locate.js';

chaiShould();

// A session as hook.cjs records it
const SESSION = [
  { kind: 'start', electron: '38.8.6' },
  { kind: 'window', id: 1, ctor: 'BrowserWindow', preload: 'preload.js', prefs: { nodeIntegration: true, contextIsolation: false, preload: 'preload.js' } },
  { kind: 'window', id: 2, ctor: 'BrowserWindow', preload: 'viewer-preload.js', prefs: { preload: 'viewer-preload.js' } },
  { kind: 'ipc-register', channel: 'documents:get', mode: 'handle' },
  { kind: 'ipc-register', channel: 'documents:delete', mode: 'handle' },
  { kind: 'ipc-register', channel: 'log', mode: 'on' },
  { kind: 'page', id: 1, type: 'window', url: 'file:///app/editor.html', prefs: { nodeIntegration: true, contextIsolation: false, sandbox: false, webSecurity: true } },
  { kind: 'response', url: 'file:///app/editor.html', resourceType: 'mainFrame', webContents: 1 },
  { kind: 'page-meta-csp', id: 1, url: 'file:///app/editor.html', csp: null },
  { kind: 'did-navigate', id: 1, url: 'file:///app/editor.html' },
  { kind: 'page', id: 2, type: 'window', url: 'https://app.example.com/viewer', prefs: { nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true } },
  { kind: 'response', url: 'https://app.example.com/viewer', resourceType: 'mainFrame', webContents: 2, csp: "default-src 'self'; script-src 'self' 'unsafe-inline'" },
  { kind: 'page-meta-csp', id: 2, url: 'https://app.example.com/viewer', csp: null },
  { kind: 'did-navigate', id: 2, url: 'https://app.example.com/viewer' },
  { kind: 'did-navigate', id: 2, url: 'https://elsewhere.example.org/page' },
  { kind: 'response', url: 'http://cdn.example.net/lib.js', resourceType: 'script', webContents: 1 },
  { kind: 'response', url: 'http://127.0.0.1:8080/api', resourceType: 'xhr', webContents: 2 },
  { kind: 'ipc', channel: 'documents:get', mode: 'invoke', sender: 'https://app.example.com/viewer', args: ['number'] },
  { kind: 'ipc', channel: 'log', mode: 'send', sender: 'https://app.example.com/viewer', args: ['string'] },
  { kind: 'shell', method: 'openExternal', target: 'https://example.com/help' },
  { kind: 'shell', method: 'openExternal', target: 'file:///C:/Windows/System32/calc.exe' },
  { kind: 'shell', method: 'openPath', target: '/home/user/Downloads/report.docx' },
  { kind: 'shell', method: 'openPath', target: '/home/user/Downloads/setup.exe' },
  { kind: 'permission', permission: 'media', origin: 'https://app.example.com/viewer', granted: true, default: true },
  { kind: 'permission', permission: 'notifications', origin: 'https://app.example.com/viewer', granted: true, default: false },
  { kind: 'permission-check', permission: 'geolocation', origin: 'https://app.example.com/viewer', granted: true, default: true },
  { kind: 'permission-check', permission: 'clipboard-read', origin: 'https://app.example.com/viewer', granted: true, default: false },
  { kind: 'webview', src: 'https://embed.example.com/', prefs: { nodeIntegration: true }, prevented: false },
  { kind: 'child-window', url: 'https://popup.example.com/', disposition: 'new-window' },
  { kind: 'certificate-error', url: 'https://self-signed.example.com/', error: 'net::ERR_CERT_AUTHORITY_INVALID' },
  { kind: 'quit' },
];

describe('Watch mode', () => {
  describe('session analysis', () => {
    const { issues, summary } = analyzeWatchLog(SESSION);
    const find = (id, pattern) => issues.filter(i => i.id === id && (!pattern || pattern.test(i.description)));

    it('summarizes the session and what it did not cover', () => {
      summary.should.include({ started: true, windows: 2, channels: 3, usedChannels: 2 });
      summary.unusedChannels.should.deep.equal(['documents:delete']);
      find('RUNTIME_COVERAGE')[0].description.should.match(/1 of 3 IPC channels .* documents:delete/);
    });

    it('reports the settings windows really ran with', () => {
      find('RUNTIME_NODE_INTEGRATION')[0].should.include({ file: 'file:///app/editor.html' });
      find('RUNTIME_NODE_INTEGRATION')[0].severity.name.should.equal('HIGH');
      find('RUNTIME_CONTEXT_ISOLATION').should.have.length(1);
      find('RUNTIME_WINDOW_SUMMARY').should.have.length(2);
      find('RUNTIME_SANDBOX').should.have.length(0); // the Node.js finding covers the unsandboxed editor
    });

    it('records preload scripts captured where the window was constructed', () => {
      const windows = find('RUNTIME_WINDOW_SUMMARY');
      windows.find(w => w.properties.webContents === 1).properties.preload.should.equal('preload.js');
      windows.find(w => w.properties.webContents === 2).properties.preload.should.equal('viewer-preload.js');
    });

    it('reports synchronous permission checks the app allows', () => {
      find('RUNTIME_PERMISSION_CHECK', /'geolocation'.*automatically/)[0].severity.name.should.equal('MEDIUM');
      find('RUNTIME_PERMISSION_CHECK', /'clipboard-read'/)[0].severity.name.should.equal('INFORMATIONAL');
    });

    it('checks the Content Security Policy each page got', () => {
      find('RUNTIME_CSP', /without a Content Security Policy: file:\/\/\/app\/editor\.html/).should.have.length(1);
      find('RUNTIME_CSP', /allows inline scripts/)[0].severity.name.should.equal('LOW');
    });

    it('reports plain http loads, except from the local machine', () => {
      const loads = find('RUNTIME_INSECURE_LOAD');
      loads.should.have.length(1);
      loads[0].severity.name.should.equal('HIGH'); // loaded into the window with Node.js integration
    });

    it('reports navigation to other origins, new windows, webviews and certificate errors', () => {
      find('RUNTIME_NAVIGATION', /elsewhere\.example\.org/).should.have.length(1);
      find('RUNTIME_NEW_WINDOW').should.have.length(1);
      find('RUNTIME_WEBVIEW')[0].severity.name.should.equal('HIGH');
      find('RUNTIME_CERTIFICATE_ERROR').should.have.length(1);
    });

    it('tells expected shell calls from risky ones', () => {
      find('RUNTIME_OPEN_EXTERNAL', /non-web URL/)[0].severity.name.should.equal('HIGH');
      find('RUNTIME_OPEN_EXTERNAL', /example\.com\/help/)[0].severity.name.should.equal('INFORMATIONAL');
      find('RUNTIME_OPEN_PATH', /setup\.exe/)[0].severity.name.should.equal('HIGH');
      find('RUNTIME_OPEN_PATH', /report\.docx/)[0].severity.name.should.equal('INFORMATIONAL');
    });

    it('flags permissions granted only because the app has no handler', () => {
      find('RUNTIME_PERMISSION', /'media'.*automatically/)[0].severity.name.should.equal('MEDIUM');
      find('RUNTIME_PERMISSION', /'notifications'/)[0].severity.name.should.equal('INFORMATIONAL');
    });

    it('lists the IPC channels pages used', () => {
      find('RUNTIME_IPC').map(i => i.properties.channel).should.deep.equal(['documents:get', 'log']);
    });

    it('ignores permission checks Chromium makes without a page origin', () => {
      const { issues } = analyzeWatchLog([{ kind: 'start' },
        { kind: 'permission-check', permission: 'media', origin: '', granted: true, default: true },
        { kind: 'permission-check', permission: 'geolocation', origin: 'https://app.example.com/', granted: true, default: true }]);
      const checks = issues.filter(i => i.id === 'RUNTIME_PERMISSION_CHECK');
      checks.should.have.length(1);
      checks[0].description.should.match(/geolocation.*https:\/\/app\.example\.com/);
    });

    it('notices when the hook never ran', () => {
      analyzeWatchLog([]).summary.started.should.equal(false);
    });

    it('reports what the renderer-side observer saw inside pages', () => {
      const { issues } = analyzeWatchLog([
        { kind: 'start', electron: '38.0.0' },
        { kind: 'dom-observed', id: 1, url: 'file:///app/editor.html', event: 'event-handler', detail: 'onerror' },
        { kind: 'dom-observed', id: 1, url: 'file:///app/editor.html', event: 'javascript-url', detail: 'href' },
        { kind: 'dom-observed', id: 1, url: 'file:///app/editor.html', event: 'script', detail: 'src' },
        { kind: 'dom-observed', id: 2, url: 'https://app.example.com/note', event: 'marker', detail: 'ENGCANARY42', live: true },
        { kind: 'dom-observed', id: 3, url: 'https://app.example.com/safe', event: 'marker', detail: 'ENGCANARY42', live: false },
      ]);
      const dom = issues.filter(i => i.id === 'RUNTIME_DOM_INJECTION');
      dom.map(i => i.properties.event).should.have.members(['event-handler', 'javascript-url']); // 'script' is not reported
      const live = issues.filter(i => i.id === 'RUNTIME_MARKER' && i.properties.live);
      live.should.have.length(1);
      live[0].severity.name.should.equal('LOW');
      issues.filter(i => i.id === 'RUNTIME_MARKER' && !i.properties.live)[0].severity.name.should.equal('INFORMATIONAL');
    });
  });

  describe('API endpoints', () => {
    const records = [
      { kind: 'start' },
      { kind: 'api', method: 'POST', url: 'https://api.example.com/documents/42', status: 200, bodyBytes: 120, htmlBody: true },
      { kind: 'api', method: 'POST', url: 'https://api.example.com/documents/43', status: 201, bodyBytes: 90, htmlBody: false },
      { kind: 'api', method: 'GET', url: 'https://api.example.com/documents/3f2b9c1e-8d4a-4c2b-9f1e-2a3b4c5d6e7f', status: 200 },
      { kind: 'api', method: 'PUT', url: 'https://api.example.com/comments/7', status: 403, bodyBytes: 40, htmlBody: true },
      { kind: 'entry', detail: 'paste-html' },
      { kind: 'entry', detail: 'paste-html' },
    ];
    const { issues, summary } = analyzeWatchLog(records);

    it('groups the calls by method and route, with identifiers generalized', () => {
      summary.api.map(e => `${e.method} ${e.route}`).should.have.members(['POST https://api.example.com/documents/{id}', 'GET https://api.example.com/documents/{id}', 'PUT https://api.example.com/comments/{id}']);
      const post = summary.api.find(e => e.method === 'POST');
      post.should.include({ calls: 2, htmlBody: true, maxBodyBytes: 120 });
      post.statuses.should.deep.equal([200, 201]);
    });

    it('points out endpoints that accepted HTML, for server-side testing', () => {
      const html = issues.filter(i => i.id === 'RUNTIME_HTML_ENDPOINT');
      html.should.have.length(1, 'a request the server refused (403) is not reported');
      html[0].description.should.match(/^POST https:\/\/api\.example\.com\/documents\/\{id\} accepted a request body containing HTML/);
      html[0].manualReview.should.equal(true);
    });

    it('counts the entry points used', () => {
      summary.entryPoints.should.deep.equal({ 'paste-html': 2 });
    });
  });

  describe('launcher', () => {
    const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'eng-watch-'));

    it('explains what is missing to start an app folder', () => {
      const dir = tmp();
      (() => resolveApp(dir)).should.throw(/no package\.json/);
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"app"}');
      (() => resolveApp(dir)).should.throw(/Electron is not installed/);
    });

    it('finds the app.asar of a packaged app to scan', () => {
      const dir = tmp();
      fs.mkdirSync(path.join(dir, 'resources'));
      fs.writeFileSync(path.join(dir, 'resources', 'app.asar'), '');
      fs.writeFileSync(path.join(dir, 'myapp'), '');
      const app = resolveApp(path.join(dir, 'myapp'), ['--flag']);
      app.should.include({ command: path.join(dir, 'myapp'), staticInput: path.join(dir, 'resources', 'app.asar') });
      app.args.should.deep.equal(['--flag']);
    });
  });

  describe('reconciling static and runtime findings', () => {
    const build = () => ([
      { id: 'WINDOW_SUMMARY_JS_CHECK', file: 'main.js', location: { line: 10 }, properties: { window: 'BrowserWindow', preload: '/app/preload.js' } },
      { id: 'WINDOW_SUMMARY_JS_CHECK', file: 'settings.js', location: { line: 5 }, properties: { window: 'BrowserWindow', preload: '/app/settings-preload.js' } },
      { id: 'RUNTIME_WINDOW_SUMMARY', file: 'file:///app/index.html', location: { line: 0 }, properties: { url: 'file:///app/index.html', preload: 'preload.js' } },
      { id: 'NODE_INTEGRATION_JS_CHECK', file: 'main.js', location: { line: 10 }, description: 'nodeIntegration is on', properties: {} },
      { id: 'RUNTIME_NODE_INTEGRATION', file: 'file:///app/index.html', location: { line: 0 }, description: 'A page ran with Node.js integration', properties: {} },
    ]);

    it('links a window observed at runtime to its static definition by preload', () => {
      const issues = reconcileRuntime(build());
      const runtimeWindow = issues.find(i => i.id === 'RUNTIME_WINDOW_SUMMARY');
      runtimeWindow.properties.staticWindow.should.equal('main.js:10');
      issues.find(i => i.id === 'WINDOW_SUMMARY_JS_CHECK' && i.file === 'main.js').properties.observedAt.should.equal('file:///app/index.html');
    });

    it('does not equate same-type findings across different windows', () => {
      const issues = reconcileRuntime(build());
      issues.find(i => i.id === 'RUNTIME_NODE_INTEGRATION').description.should.not.match(/also found/);
      (issues.find(i => i.id === 'NODE_INTEGRATION_JS_CHECK').properties.confirmedByRuntime === undefined).should.equal(true);
    });

    it('reports static windows that were never opened during the session', () => {
      const coverage = reconcileRuntime(build()).find(i => i.id === 'RUNTIME_WINDOW_COVERAGE');
      coverage.description.should.match(/1 of 2 window definition\(s\).*settings-preload\.js.*settings\.js:5/);
    });

    it('lists ways content comes in that the code handles but the session did not try', () => {
      const issues = [...build(),
        { id: 'XSS_SINK_JS_CHECK', file: 'editor.js', location: { line: 3 }, properties: { origin: 'pasted or dropped content' } },
        { id: 'FILE_HANDLER_JS_CHECK', file: 'main.js', location: { line: 20 }, properties: {} }];
      const coverage = reconcileRuntime(issues, { entryPoints: { 'paste-html': 2, 'second-instance': 1 } }).find(i => i.id === 'RUNTIME_ENTRY_COVERAGE');
      coverage.properties.untried.should.deep.equal(['dragging and dropping content or files']);
      // nothing handled by the code, nothing to list
      reconcileRuntime(build(), { entryPoints: {} }).some(i => i.id === 'RUNTIME_ENTRY_COVERAGE').should.equal(false);
    });

    it('does nothing when watch mode observed no windows', () => {
      const issues = [{ id: 'WINDOW_SUMMARY_JS_CHECK', file: 'main.js', location: { line: 1 }, properties: { preload: '/app/preload.js' } }];
      reconcileRuntime(issues).should.have.length(1);
    });
  });

  describe('locating the app', () => {
    const SENTINEL_WIRE = Buffer.concat([Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), Buffer.from([1, 2]), Buffer.from('01')]);
    // an installed app: <folder>/<exe> with its fuse wire, and resources/app.asar
    const install = (folder, exe = 'MyApp.exe') => {
      fs.mkdirSync(path.join(folder, 'resources'), { recursive: true });
      fs.writeFileSync(path.join(folder, 'resources', 'app.asar'), 'asar');
      fs.writeFileSync(path.join(folder, exe), SENTINEL_WIRE, { mode: 0o755 });
      fs.writeFileSync(path.join(folder, 'Uninstall MyApp.exe'), 'uninstaller', { mode: 0o755 });
      return folder;
    };
    const root = () => fs.mkdtempSync(path.join(os.tmpdir(), 'eng-locate-'));

    it('finds the executable and app.asar from the install folder, the executable, app.asar or the resources folder', () => {
      const folder = install(path.join(root(), 'MyApp'));
      for (const target of [folder, path.join(folder, 'MyApp.exe'), path.join(folder, 'resources', 'app.asar'), path.join(folder, 'resources')]) {
        const found = locateApp(target);
        found.kind.should.equal('packaged');
        found.executable.should.equal(path.join(folder, 'MyApp.exe'));
        found.code.should.equal(path.join(folder, 'resources', 'app.asar'));
      }
    });

    it('picks the newest app-<version> folder of a Squirrel install, not the launcher', () => {
      const squirrel = path.join(root(), 'MyApp');
      fs.mkdirSync(squirrel, { recursive: true });
      fs.writeFileSync(path.join(squirrel, 'MyApp.exe'), 'launcher stub');
      fs.writeFileSync(path.join(squirrel, 'Update.exe'), 'squirrel');
      install(path.join(squirrel, 'app-1.9.0'));
      install(path.join(squirrel, 'app-1.10.2'));
      const found = locateApp(squirrel);
      found.executable.should.equal(path.join(squirrel, 'app-1.10.2', 'MyApp.exe'));
      found.name.should.equal('MyApp');
    });

    it('looks one folder down (C:\\Program Files\\<Company>), and explains what it expected otherwise', () => {
      const company = root();
      install(path.join(company, 'MyApp'));
      fs.mkdirSync(path.join(company, 'Docs'));
      locateApp(company).executable.should.equal(path.join(company, 'MyApp', 'MyApp.exe'));
      install(path.join(company, 'OtherApp'));
      (() => locateApp(company)).should.throw(/several Electron apps: .*MyApp.*OtherApp|several Electron apps: .*OtherApp.*MyApp/);
      (() => locateApp(root())).should.throw(/No Electron app found .*app\.asar/);
    });

    it('treats a folder with a package.json as a project to run with its own Electron', () => {
      const project = root();
      fs.writeFileSync(path.join(project, 'package.json'), '{"name":"x","main":"main.js"}');
      locateApp(project).should.include({ kind: 'project', code: project });
    });
  });

  describe('packaged fuses', () => {
    const SENTINEL = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX';
    // version 1, 8 fuses; RunAsNode enabled ('1') is insecure, the rest set to their safe values
    const wire = (states) => Buffer.concat([Buffer.from('\0\0binary junk\0\0'), Buffer.from(SENTINEL), Buffer.from([1, states.length]), Buffer.from(states)]);
    const write = (buf) => { const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eng-fuse-')), 'app.bin'); fs.writeFileSync(f, buf); return f; };

    it('reads the fuse states written into the binary', () => {
      const file = write(wire('10011100'));
      const parsed = readFuseWire(file);
      parsed.version.should.equal(1);
      parsed.states.RunAsNode.should.equal('enabled');
      parsed.states.EnableNodeOptionsEnvironmentVariable.should.equal('disabled');
      parsed.states.LoadBrowserProcessSpecificV8Snapshot.should.equal('disabled');
    });

    it('flags the insecure fuse read from the binary', () => {
      const { read, issues } = analyzePackagedFuses(write(wire('11001100'))); // RunAsNode + cookie encryption on = one insecure (RunAsNode)
      read.should.equal(true);
      const run = issues.filter(i => i.id === 'PACKAGED_FUSES' && /RunAsNode/.test(i.description));
      run.should.have.length(1);
      run[0].severity.name.should.equal('HIGH');
    });

    it('reports a clean binary and handles one without a fuse wire', () => {
      // RunAsNode off, cookie encryption on, node options off, inspect off, asar integrity on, only-asar on, v8 inherit, file-protocol off
      const clean = analyzePackagedFuses(write(wire('01001110')));
      clean.issues.filter(i => i.severity.name !== 'INFORMATIONAL').should.have.length(0);
      analyzePackagedFuses(write(Buffer.from('no fuses here'))).read.should.equal(false);
    });

    it('reads the fuses of the executable when scanning a packaged app statically', async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-packaged-'));
      const source = path.join(dir, 'src');
      fs.mkdirSync(source);
      fs.writeFileSync(path.join(source, 'package.json'), '{"name":"app","main":"main.js"}');
      fs.writeFileSync(path.join(source, 'main.js'), 'const { app } = require("electron");');
      fs.mkdirSync(path.join(dir, 'app', 'resources'), { recursive: true });
      await asar.createPackage(source, path.join(dir, 'app', 'resources', 'app.asar'));
      // named as the platform names it: an .exe on Windows, where files have no executable bit
      fs.writeFileSync(path.join(dir, 'app', process.platform === 'win32' ? 'myapp.exe' : 'myapp'),
        Buffer.concat([Buffer.from('Mozilla/5.0 Chrome/140.0 Electron/37.4.1 Safari\0'), wire('11001100')]), { mode: 0o755 });
      fs.writeFileSync(path.join(dir, 'app', 'chrome-sandbox'), 'helper', { mode: 0o755 });
      const result = await run({ input: path.join(dir, 'app', 'resources', 'app.asar'), offline: true, isRelative: true });
      const ids = result.issues.map(i => i.id);
      ids.should.include('PACKAGED_FUSES');
      ids.should.not.include('FUSES_GLOBAL_CHECK'); // the binary is the ground truth
      // app.asar doesn't name the Electron version: it is read from the executable
      result.electronVersion.should.equal('37.4.1');
      result.electronVersionSource.should.equal('packaged executable');
      result.issues.filter(i => i.id === 'PACKAGED_FUSES' && /RunAsNode/.test(i.description))[0].severity.name.should.equal('HIGH');
    });

    it('reads the Electron Framework of a macOS app bundle, where the fuses live', () => {
      fuseBinaryFor('/Applications/My App.app/Contents/MacOS/My App')
        .should.equal(path.join(path.resolve('/Applications/My App.app'), 'Contents', 'Frameworks', 'Electron Framework.framework', 'Electron Framework'));
      fuseBinaryFor('/opt/my-app/my-app').should.equal(path.resolve('/opt/my-app/my-app'));
      // a bundle whose framework holds the wire
      const bundle = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eng-mac-')), 'My App.app');
      const framework = path.join(bundle, 'Contents', 'Frameworks', 'Electron Framework.framework');
      fs.mkdirSync(framework, { recursive: true });
      fs.mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true });
      fs.writeFileSync(path.join(bundle, 'Contents', 'MacOS', 'My App'), 'launcher without fuses');
      fs.writeFileSync(path.join(framework, 'Electron Framework'), wire('11001100'));
      analyzePackagedFuses(path.join(bundle, 'Contents', 'MacOS', 'My App')).read.should.equal(true);
    });
  });

  // Runs the test app for real: needs Electron (npm install --no-save electron) and, on Linux, xvfb-run
  describe('end to end', function () {
    this.timeout(240000);
    let electron;
    try {
      electron = createRequire(import.meta.url)('electron');
    } catch {
      electron = undefined;
    }
    const xvfb = process.platform !== 'linux' || spawnSync('which', ['xvfb-run']).status === 0;
    if (process.env.ELECTRONEGATIVITY_REQUIRE_RUNTIME_TESTS === '1' && (!electron || !xvfb))
      throw new Error('Required runtime tests need Electron and, on Linux, xvfb-run; skipping is not allowed');
    const run = electron && xvfb ? it : it.skip;
    // The CLI, with a time limit: spawnSync blocks the event loop, so without one a session that never ends hangs the run
    // instead of failing it. ELECTRONEGATIVITY_TRACE shows how far loading the observer got.
    const runCli = (cli, env = process.env) => {
      const options = { encoding: 'utf8', env: { ...env, ELECTRONEGATIVITY_TRACE: '1' }, timeout: 150000 };
      return process.platform === 'linux' ? spawnSync('xvfb-run', ['-a', process.execPath, ...cli], options) : spawnSync(process.execPath, cli, options);
    };
    const why = (command) => `${command.error ? `${command.error.message}\n` : ''}${command.signal ? `killed by ${command.signal}\n` : ''}${command.stderr}\n${String(command.stdout).slice(-3000)}`;

    run('launches and closes a real app through a managed renderer debug port', async () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-managed-cdp-'));
      const output = path.join(root, 'report.json'), diagnostics = path.join(root, 'diag.json');
      const fixture = path.join(import.meta.dirname, 'apps', 'debug-app');
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--watch', fixture, '--debug-launch', '--debug-duration', '2',
        '--watch-args', '--no-sandbox', '--offline', '--no-watch-traffic', '--no-report-dir', '-o', output, '--diagnostics', diagnostics];
      const env = { ...process.env, DEBUG_APP_PROFILE: path.join(root, 'profile') };
      try {
        const command = runCli(cli, env);
        (command.status === 0).should.equal(true, why(command));
        const watch = JSON.parse(fs.readFileSync(diagnostics, 'utf8')).watch;
        watch.mode.should.equal('debug-launched'); watch.hookStarted.should.equal(false);
        watch.injection.should.include({ method: 'renderer-cdp', launched: true, mainProcess: false, loaded: true });
        watch.records['debug-launch-exit'].should.equal(1);
        const report = JSON.parse(fs.readFileSync(output, 'utf8'));
        report.issues.some(i => i.id === 'RUNTIME_DEBUG_COVERAGE').should.equal(true);
        const window = report.issues.find(i => i.id === 'RUNTIME_WINDOW_SUMMARY');
        window.properties.settings.contextIsolation.source.should.equal('unavailable');
        let reachable = true;
        try { await fetch(`${watch.injection.endpoint}/json/list`, { signal: AbortSignal.timeout(1000) }); } catch { reachable = false; }
        reachable.should.equal(false, 'managed debug port closed with the owned app');
      } finally { fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 500 }); }
    });

    run('captures and runs a campaign through a real debug port with DevTools UI disabled', async () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-cdp-app-'));
      const server = net.createServer();
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const port = server.address().port;
      await new Promise(resolve => server.close(resolve));
      const endpoint = `http://127.0.0.1:${port}`;
      const fixture = path.join(import.meta.dirname, 'apps', 'debug-app');
      const args = [fixture, '--no-sandbox', `--user-data-dir=${path.join(root, 'profile')}`, `--remote-debugging-port=${port}`];
      const child = process.platform === 'linux' ? spawn('xvfb-run', ['-a', electron, ...args], { stdio: 'ignore' }) : spawn(electron, args, { stdio: 'ignore' });
      const log = path.join(root, 'session.jsonl'), commands = path.join(root, 'commands.jsonl');
      fs.writeFileSync(log, ''); fs.writeFileSync(commands, '');
      const profiles = [], marker = 'ENG_DEBUG_REAL';
      const assistant = createAssistant({ marker, active: true, autoCampaign: true, saveCampaign: p => { profiles.push(p); }, print: () => {} });
      assistant.useChannel({ ask: async () => '', confirm: async () => true,
        send: c => fs.appendFileSync(commands, JSON.stringify(c) + '\n') });
      const stop = followLog(log, record => assistant.handle(record), 50);
      let running, seedClient;
      try {
        let ready = false;
        for (let attempt = 0; attempt < 150; attempt++) {
          try {
            const list = await (await fetch(`${endpoint}/json/list`)).json();
            ready = list.some(item => item.type === 'page' && item.url.endsWith('/view'));
          } catch { /* Electron is starting */ }
          if (ready) break;
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        ready.should.equal(true, 'renderer debug endpoint opened');
        process.env.ELECTRONEGATIVITY_TRACE = '1';
        running = watchDebug(endpoint, { marker, active: true, campaign: true, duration: 150, traffic: false, log, commands });
        for (let attempt = 0; attempt < 100 && !readWatchLog(log).some(r => r.kind === 'start'); attempt++) await new Promise(resolve => setTimeout(resolve, 50));
        seedClient = await connectDebug(endpoint);
        await seedClient.send('Runtime.evaluate', { expression: 'document.getElementById("save").click()' });
        seedClient.close(); seedClient = undefined;
        await running;
        const records = readWatchLog(log), report = analyzeWatchLog(records);
        const kinds = {};
        for (const r of records) kinds[r.kind] = (kinds[r.kind] || 0) + 1;
        profiles.should.have.length(1, `records: ${JSON.stringify(kinds)}; api: ${JSON.stringify(records.filter(r => r.kind === 'api').slice(0, 5))}; errors: ${JSON.stringify(records.filter(r => /error/.test(r.kind)).slice(0, 5))}`);
        profiles[0].fields.should.deep.equal(['body']);
        profiles[0].cases.should.have.length(28);
        records.filter(r => r.kind === 'campaign-done').should.have.length(1);
        records.some(r => r.kind === 'campaign-restore' && r.ok).should.equal(true);
        report.summary.campaign.cases.should.have.length(28);
        report.summary.campaign.cases.some(c => c.case === 'event-handler' && c.execution === 'observed').should.equal(true, JSON.stringify(report.summary.campaign));
        report.issues.some(i => i.id === 'RUNTIME_DEBUG_COVERAGE').should.equal(true);
      } finally {
        delete process.env.ELECTRONEGATIVITY_TRACE;
        seedClient?.close(); child.kill(); if (running) await running.catch(() => {});
        stop(); assistant.clearChannel(); fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 500 });
      }
    });

    run('observes a packaged app, which ignores NODE_OPTIONS, through the Node inspector', async () => {
      // package the test app the way installers ship it: Electron's binary with resources/app.asar next to it
      const dist = path.join(path.dirname(createRequire(import.meta.url).resolve('electron')), 'dist');
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-packaged-app-'));
      let executable;
      let resources;
      if (process.platform === 'darwin') {
        fs.cpSync(path.join(dist, 'Electron.app'), path.join(root, 'MyApp.app'), { recursive: true, verbatimSymlinks: true });
        executable = path.join(root, 'MyApp.app');
        resources = path.join(executable, 'Contents', 'Resources');
      } else {
        fs.cpSync(dist, path.join(root, 'MyApp'), { recursive: true, verbatimSymlinks: true });
        executable = path.join(root, 'MyApp', process.platform === 'win32' ? 'electron.exe' : 'electron');
        resources = path.join(root, 'MyApp', 'resources');
      }
      fs.rmSync(path.join(resources, 'default_app.asar'), { force: true });
      await asar.createPackage(path.join(import.meta.dirname, 'apps', 'runtime-app'), path.join(resources, 'app.asar'));

      const output = path.join(root, 'report.json');
      const diagnostics = path.join(root, 'diag.json');
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--watch', executable, '--watch-args', '--no-sandbox', '--offline', '--no-report-dir', '-r', '-o', output, '--diagnostics', diagnostics];
      const command = runCli(cli);
      (command.status === 0).should.equal(true, why(command));
      const watch = JSON.parse(fs.readFileSync(diagnostics, 'utf8')).watch;
      watch.injection.should.include({ method: 'inspector', loaded: true });
      watch.hookStarted.should.equal(true, JSON.stringify(watch));
      const report = JSON.parse(fs.readFileSync(output, 'utf8'));
      const ids = report.issues.map(i => i.id);
      ids.should.include.members(['RUNTIME_NODE_INTEGRATION', 'RUNTIME_IPC', 'RUNTIME_HTML_ENDPOINT']);
      // loaded before the app's code: windows it constructs are observed with their preload
      report.issues.filter(i => i.id === 'RUNTIME_WINDOW_SUMMARY').some(i => i.properties.preload === 'preload.js').should.equal(true);
    });

    run('checks the traffic, consoles and errors of a real session', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-traffic-app-'));
      fs.cpSync(path.join(import.meta.dirname, 'apps', 'traffic-app'), dir, { recursive: true });
      fs.symlinkSync(path.join(import.meta.dirname, '..', 'node_modules'), path.join(dir, 'node_modules'), 'junction');
      const output = path.join(dir, 'report.json');
      // the app keeps its profile here (app.setPath), and remembers this test password base64-encoded
      const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-traffic-profile-'));
      const shots = path.join(dir, 'shots');
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--watch', dir, '--watch-args', '--no-sandbox', '--offline', '--no-report-dir', '-r', '--canary', 'Zq7-test-Pw!2026', '--watch-screenshots', shots, '-o', output];
      const env = { ...process.env, TRAFFIC_APP_PROFILE: profile };
      const command = runCli(cli, env);
      (command.status === 0).should.equal(true, why(command));
      const report = JSON.parse(fs.readFileSync(output, 'utf8'));
      const ids = report.issues.map(i => i.id);
      // the profile Chromium wrote (Local Storage LevelDB, the cookie store) and where the password went
      ids.should.include.members(['STORAGE_SECRET_AT_REST', 'STORAGE_COOKIE_AT_REST', 'STORAGE_CREDENTIAL_AT_REST']);
      report.atRest.profile.path.should.equal(profile);
      JSON.stringify(report).should.not.include('Zq7-test-Pw!2026');
      ids.should.include.members(['TRAFFIC_CLEARTEXT_HTTP', 'TRAFFIC_SECRET_IN_URL', 'TRAFFIC_INSECURE_COOKIE', 'TRAFFIC_AUTH_TO_THIRD_PARTY', 'TRAFFIC_USER_INPUT_TO_THIRD_PARTY',
        'TRAFFIC_IDOR_CANDIDATE', 'TRAFFIC_SECRET_IN_RESPONSE', 'TRAFFIC_WS_CLEARTEXT', 'TRAFFIC_WS_HTML_MESSAGE',
        'RUNTIME_SECRET_IN_CONSOLE', 'RUNTIME_UNCAUGHT_EXCEPTION', 'RUNTIME_CSP_VIOLATION']);
      // the main process's own requests (Node http) are checked too
      report.issues.some(i => i.id === 'TRAFFIC_SECRET_IN_URL' && /api\/status/.test(i.description)).should.equal(true);
      // secrets are redacted in everything written
      JSON.stringify(report).should.not.include('A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8');
      JSON.stringify(report).should.not.include('Zk2Qm9Lr7Tx4Wv1Yp8Nb');
      report.runtime.traffic.sources.debugger.should.be.above(0);
      // Node's global fetch in the main process (undici) is observed too
      report.issues.some(i => i.id === 'TRAFFIC_SECRET_IN_URL' && /api\/fetched/.test(i.description)).should.equal(true, 'main-process fetch is observed');
      JSON.stringify(report).should.not.include('Tr4ff1cF3tchM41nPr0c3ss7');
      // a server redirect the window followed to another origin, with its preload; two windows of different privilege in one session
      ids.should.include.members(['RUNTIME_REDIRECT', 'RUNTIME_PRELOAD_FOREIGN_ORIGIN', 'RUNTIME_WINDOW_SESSION']);
      report.issues.find(i => i.id === 'RUNTIME_WINDOW_SESSION').severity.should.equal('LOW');
      // the evidence screenshot of the script inserted into the page
      fs.readdirSync(shots).some(f => /dom-injection\.png$/.test(f)).should.equal(true, 'a screenshot was saved');
      report.issues.some(i => i.properties && i.properties.screenshot).should.equal(true, 'the screenshot is attached to its finding');
      // the API response kept in the HTTP cache, with the token in it
      ids.should.include('STORAGE_CACHED_RESPONSES', JSON.stringify(report.atRest && report.atRest.profile));
      report.issues.some(i => i.id === 'STORAGE_SECRET_AT_REST' && i.properties.store === 'HTTP cache' && /api\/profile/.test(i.properties.url)).should.equal(true, 'the cached token is found');
      JSON.stringify(report).should.not.include('Cz9Lm2Vt9Rk4Zp8Wn3Yb6Hs7Tx');
      // every finding says what the victim has to do
      report.issues.filter(i => i.id === 'TRAFFIC_SECRET_IN_URL').every(i => typeof i.interaction === 'string').should.equal(true);
    });

    run('observes a real session without disturbing the app', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-watch-app-'));
      fs.cpSync(path.join(import.meta.dirname, 'apps', 'runtime-app'), dir, { recursive: true });
      fs.symlinkSync(path.join(import.meta.dirname, '..', 'node_modules'), path.join(dir, 'node_modules'), 'junction');
      const output = path.join(dir, 'report.json');
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--watch', dir, '--watch-args', '--no-sandbox', '--watch-marker', 'ENGCANARY', '--offline', '--no-report-dir', '-r', '-o', output];
      const command = runCli(cli);
      (command.status === 0).should.equal(true, why(command));
      const report = JSON.parse(fs.readFileSync(output, 'utf8'));
      const ids = report.issues.map(i => i.id);
      ids.should.include.members(['RUNTIME_NODE_INTEGRATION', 'RUNTIME_CONTEXT_ISOLATION', 'RUNTIME_CSP', 'RUNTIME_PERMISSION', 'RUNTIME_COVERAGE']);
      const ipc = report.issues.filter(i => i.id === 'RUNTIME_IPC').map(i => i.description);
      ipc.some(d => /documents:get/.test(d)).should.equal(true, 'the IPC call went through the wrapped handler');
      // the preload script is captured at window construction, not from getLastWebPreferences()
      report.issues.filter(i => i.id === 'RUNTIME_WINDOW_SUMMARY').some(i => i.properties.preload === 'preload.js')
        .should.equal(true, 'the viewer window preload was recorded');
      report.issues.filter(i => /token=secret/.test(JSON.stringify(i))).should.have.length(0, 'query strings are not recorded');
      // the renderer-side observer saw the runtime DOM injection and that the planted marker rendered as live HTML
      ids.should.include('RUNTIME_DOM_INJECTION');
      const live = report.issues.filter(i => i.id === 'RUNTIME_MARKER' && i.properties.live);
      live.should.have.length.above(0, 'the planted marker came back as live HTML');
      live.some(i => /editor\.html/.test(i.file)).should.equal(true, 'the editor renders the marker as markup');
      live.some(i => /safe-view\.html/.test(i.file)).should.equal(false, 'the safe view does not');
      // inside the editor's iframe too, with the sink that wrote it there
      live.some(i => i.properties.frame).should.equal(true, 'the marker rendered inside the editor iframe is seen');
      report.issues.some(i => i.id === 'RUNTIME_MARKER_SINK' && i.properties.frame).should.equal(true, 'the sink inside the iframe is recorded');
      // the marker traced through the app: the HTML sink that wrote it (at the script line), the request fields that
      // carried it, the blocked link and window, the IPC channel and the file path
      const sink = report.issues.find(i => i.id === 'RUNTIME_MARKER_SINK' && /\/static\/viewer\.js$/.test(i.properties.frames[0].url));
      (sink !== undefined).should.equal(true, 'the viewer script that wrote the marker is recorded');
      sink.properties.sink.should.equal('innerHTML');
      const sent = report.issues.find(i => i.id === 'RUNTIME_MARKER_SENT');
      sent.properties.fields.should.have.members(['title', 'body']);
      report.issues.find(i => i.id === 'RUNTIME_MARKER_NAVIGATION').properties.blocked.should.equal(true);
      report.issues.find(i => i.id === 'RUNTIME_MARKER_NEW_WINDOW').properties.blocked.should.equal(true);
      report.issues.find(i => i.id === 'RUNTIME_MARKER_IPC').properties.channel.should.equal('log');
      ids.should.include('RUNTIME_MARKER_OPEN_PATH');
      const moduleEvidence = report.issues.find(i => i.id === 'RUNTIME_MARKER_MODULE');
      moduleEvidence.properties.loaded.should.equal(true);
      moduleEvidence.properties.resolved.should.match(/ENGCANARY-module\.cjs$/);
      // The marker links the sink to its source; it does not establish execution.
      const observed = report.issues.filter(i => i.id === 'XSS_SINK_JS_CHECK' && i.validation && i.validation.status === 'observed');
      observed.should.have.length(1);
      observed[0].file.should.match(/static\/viewer\.js \(source: src\/viewer\.js\)/);
      // and the assistant said so while the app ran
      command.stdout.should.match(/\[validate\] ✓ The marker was sent with PUT http:\/\/127\.0\.0\.1:\d+\/api\/documents\/\{id\} in: title, body/);
      command.stdout.should.match(/\[validate\] ! Marker markup reached innerHTML by http:\/\/127\.0\.0\.1:\d+\/static\/viewer\.js:1:\d+/);
      command.stdout.should.match(/\[validate\] ✓ The app blocked the window from navigating to the marker link/);
      // windows in the code link to the windows observed at runtime through their preload (path.join(__dirname, 'preload.js'))
      const staticWithPreload = report.issues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK' && i.properties.preload === 'preload.js');
      staticWithPreload.should.have.length(2);
      // both use preload.js, so the preload can't tell which runtime window is which: neither is guessed
      staticWithPreload.some(i => i.properties.observedAt).should.equal(false, 'windows sharing one preload are not linked by guesswork');
      report.issues.filter(i => i.id === 'RUNTIME_MARKER' && /safe-view\.html/.test(i.file) && !i.properties.live).should.have.length(1, 'text in a form field value is shown safely');
      report.issues.filter(i => i.id === 'RUNTIME_DOM_INJECTION' && /safe-view\.html/.test(i.file)).should.have.length(0, 'attributes merely starting with "on" are not event handlers');
      // the static scan of the same app ran too
      ids.should.include('NODE_INTEGRATION_JS_CHECK');

      // guided mode: pointed at the app, it scans it and runs one watch session, writing everything to one folder
      const out = path.join(dir, 'results');
      const guided = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--app', dir, '--sessions', '1', '--watch-args', '--no-sandbox', '--offline', '--out', out];
      const guidedRun = runCli(guided);
      (guidedRun.status === 0).should.equal(true, why(guidedRun));
      const files = fs.readdirSync(out).sort();
      files.filter(f => !/^ENG[A-Z0-9]{6}/.test(f)).should.deep.equal(['session-1-diag.json', 'session-1-share.json', 'session-1-share.md', 'session-1.html',
        'static-diag.json', 'static-share.json', 'static-share.md', 'static.html']);
      // the marker files the assistant hands the tester: a page to copy formatted content from, and a file to attach
      files.filter(f => /^ENG[A-Z0-9]{6}/.test(f)).map(f => f.replace(/^ENG[A-Z0-9]{6}/, 'M')).sort().should.deep.equal(['M-paste-me.html', 'M.txt']);
      guidedRun.stdout.should.match(/\[validate\] Validation across all sessions:/);
      JSON.parse(fs.readFileSync(path.join(out, 'session-1-diag.json'), 'utf8')).watch.hookStarted.should.equal(true);
      guidedRun.stdout.should.match(/marker for this run: ENG[A-Z0-9]{6}/);
      // the backend page's script was captured with the app's session, and its original source (from the source map)
      // scanned: the finding points at the URL it was served from
      const remote = report.issues.filter(i => i.id === 'XSS_SINK_JS_CHECK' && /static\/viewer\.js \(source: src\/viewer\.js\)/.test(i.file));
      remote.should.have.length(1, 'the remote script was captured and scanned from its source map');
      remote[0].severity.should.equal('HIGH');
      // the endpoint that received HTML is listed for server-side testing, with the id in its path generalized
      const endpoints = report.issues.filter(i => i.id === 'RUNTIME_HTML_ENDPOINT');
      endpoints.map(e => e.description.split(' ')[0]).sort().should.deep.equal(['POST', 'PUT']);
      endpoints.every(e => /^(POST|PUT) http:\/\/127\.0\.0\.1:\d+\/api\/documents\/\{id\}/.test(e.description)).should.equal(true);
    });
  });
});
