import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { resolveApp } from '../src/watch/launch.js';
import { readFuseWire, analyzePackagedFuses } from '../src/watch/fuses.js';
import { reconcileRuntime } from '../src/watch/reconcile.js';

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
      live[0].severity.name.should.equal('HIGH');
      issues.filter(i => i.id === 'RUNTIME_MARKER' && !i.properties.live)[0].severity.name.should.equal('INFORMATIONAL');
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

    it('marks a problem confirmed by both static and runtime analysis', () => {
      const issues = reconcileRuntime(build());
      issues.find(i => i.id === 'RUNTIME_NODE_INTEGRATION').description.should.match(/also found by static analysis: NODE_INTEGRATION_JS_CHECK/);
      issues.find(i => i.id === 'NODE_INTEGRATION_JS_CHECK').properties.confirmedByRuntime.should.equal('RUNTIME_NODE_INTEGRATION');
    });

    it('reports static windows that were never opened during the session', () => {
      const coverage = reconcileRuntime(build()).find(i => i.id === 'RUNTIME_WINDOW_COVERAGE');
      coverage.description.should.match(/1 of 2 window\(s\).*settings-preload\.js.*settings\.js:5/);
    });

    it('does nothing when watch mode observed no windows', () => {
      const issues = [{ id: 'WINDOW_SUMMARY_JS_CHECK', file: 'main.js', location: { line: 1 }, properties: { preload: '/app/preload.js' } }];
      reconcileRuntime(issues).should.have.length(1);
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
  });

  // Runs the test app for real: needs Electron (npm install --no-save electron) and, on Linux, xvfb-run
  describe('end to end', function () {
    this.timeout(120000);
    let electron;
    try {
      electron = createRequire(import.meta.url)('electron');
    } catch {
      electron = undefined;
    }
    const xvfb = process.platform !== 'linux' || spawnSync('which', ['xvfb-run']).status === 0;
    const run = electron && xvfb ? it : it.skip;

    run('observes a real session without disturbing the app', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-watch-app-'));
      fs.cpSync(path.join(import.meta.dirname, 'apps', 'runtime-app'), dir, { recursive: true });
      fs.symlinkSync(path.join(import.meta.dirname, '..', 'node_modules'), path.join(dir, 'node_modules'), 'junction');
      const output = path.join(dir, 'report.json');
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--watch', dir, '--watch-args', '--no-sandbox', '--watch-marker', 'ENGCANARY', '--offline', '-r', '-o', output];
      const command = process.platform === 'linux' ? spawnSync('xvfb-run', ['-a', process.execPath, ...cli], { encoding: 'utf8' }) : spawnSync(process.execPath, cli, { encoding: 'utf8' });
      command.status.should.equal(0, command.stderr);
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
      report.issues.filter(i => i.id === 'RUNTIME_MARKER' && i.properties.live).should.have.length.above(0, 'the planted marker came back as live HTML');
      // the static scan of the same app ran too
      ids.should.include('NODE_INTEGRATION_JS_CHECK');
    });
  });
});
