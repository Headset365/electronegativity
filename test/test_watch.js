import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { resolveApp } from '../src/watch/launch.js';

chaiShould();

// A session as hook.cjs records it
const SESSION = [
  { kind: 'start', electron: '38.8.6' },
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
      const cli = [path.join(import.meta.dirname, '..', 'src', 'index.js'), '--watch', dir, '--watch-args', '--no-sandbox', '--offline', '-r', '-o', output];
      const command = process.platform === 'linux' ? spawnSync('xvfb-run', ['-a', process.execPath, ...cli], { encoding: 'utf8' }) : spawnSync(process.execPath, cli, { encoding: 'utf8' });
      command.status.should.equal(0, command.stderr);
      const report = JSON.parse(fs.readFileSync(output, 'utf8'));
      const ids = report.issues.map(i => i.id);
      ids.should.include.members(['RUNTIME_NODE_INTEGRATION', 'RUNTIME_CONTEXT_ISOLATION', 'RUNTIME_CSP', 'RUNTIME_PERMISSION', 'RUNTIME_COVERAGE']);
      const ipc = report.issues.filter(i => i.id === 'RUNTIME_IPC').map(i => i.description);
      ipc.some(d => /documents:get/.test(d)).should.equal(true, 'the IPC call went through the wrapped handler');
      report.issues.filter(i => /token=secret/.test(JSON.stringify(i))).should.have.length(0, 'query strings are not recorded');
      // the static scan of the same app ran too
      ids.should.include('NODE_INTEGRATION_JS_CHECK');
    });
  });
});
