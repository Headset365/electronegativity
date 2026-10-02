// Regressions from the SiYuan 3.6.0 and Trilium 0.102.1 reviews: campaign delivery, which saves a campaign is offered for,
// the app's own local server, web code shipped next to resources/app, launcher scripts, public-by-design keys, local
// service exposure and runtime noise.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { routeIntent } from '../src/watch/assistant.js';
import { isLoopbackUrl } from '../src/remote/fetch.js';
import { launcherScriptIssues } from '../src/binary/index.js';
import { analyzeProofs } from '../src/watch/proof-analysis.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import run from '../src/runner.js';
import _i18n from '../src/locales/i18n.js';

await _i18n();
const require = createRequire(import.meta.url);
const { discoverFields, runCampaign } = require('../src/watch/campaign.cjs');
const secrets = require('../src/traffic/secrets.cjs');

describe('Gaps from the SiYuan and Trilium reviews', () => {
  let root;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-sy-tr-')); });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (dir, files) => {
    for (const [name, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), content);
    }
    return dir;
  };

  describe('campaigns', () => {
    it('tells reads and deletes of RPC-style APIs from writes', () => {
      assert.equal(routeIntent('http://127.0.0.1:6806/api/notebook/lsNotebooks'), 'read');
      assert.equal(routeIntent('http://127.0.0.1:6806/api/system/getConf'), 'read');
      assert.equal(routeIntent('http://127.0.0.1:6806/api/notebook/removeNotebook'), 'delete');
      assert.equal(routeIntent('http://app.test/api/notes/remove-attachment'), 'delete');
      assert.equal(routeIntent('http://127.0.0.1:6806/api/block/updateBlock'), 'unknown');
      assert.equal(routeIntent('http://app.test/api/notes/42'), 'unknown');
      assert.equal(routeIntent('http://app.test/api/block/isolate'), 'unknown');
    });

    it('leaves record identifiers and control fields out of the content fields', () => {
      assert.deepEqual(discoverFields(JSON.stringify({ notebook: '20261002150519-mc4r8gp', rootID: 'abc', callback: 'cb', path: '/x.sy', dataType: 'markdown', data: 'Some text' })), ['data']);
      assert.deepEqual(discoverFields(JSON.stringify({ noteId: 'y6hpRYzH31hk', title: 'Shopping list', content: '<p>milk</p>' })), ['title', 'content']);
    });

    it('counts only requests that reached the app, and restores nothing when none did', async () => {
      const records = [];
      const failing = async () => { throw new Error('net::ERR_INVALID_ARGUMENT'); };
      const fill = (body, marker, fields, active, value) => ({ body: JSON.stringify({ data: value }), contentType: 'application/json' });
      await runCampaign({ profile: { request: { method: 'POST', url: 'http://127.0.0.1:1/api/block/updateBlock', body: '{"data":"x"}', headers: {} }, cases: ['text', 'html'], fields: ['data'], waitMs: 0 },
        marker: 'ENGTEST1234', fetch: failing, fill, write: (kind, data) => records.push({ kind, ...data }), delay: async () => {} });
      assert.equal(records.filter(r => r.kind === 'campaign-restore').length, 0);
      const done = records.find(r => r.kind === 'campaign-done');
      assert.equal(done.delivered, 0);
      assert.equal(done.failed, 2);
      assert.match(done.error, /ERR_INVALID_ARGUMENT/);
      const { issues } = analyzeWatchLog([{ kind: 'start' }, ...records]);
      assert.ok(issues.some(issue => issue.id === 'RUNTIME_CAMPAIGN_COVERAGE' && /not delivered/.test(issue.description)));
    });
  });

  describe('the app’s own files and server', () => {
    it('knows the app’s own loopback server', () => {
      for (const url of ['http://127.0.0.1:6806/x', 'http://localhost:37840/', 'http://[::1]:8080/']) assert.equal(isLoopbackUrl(url), true, url);
      assert.equal(isLoopbackUrl('https://app.example.com/'), false);
    });

    it('scans web code shipped next to resources/app, labelled with its resources path', async () => {
      const resources = path.join(root, 'SiYuan', 'resources');
      write(path.join(resources, 'app'), { 'package.json': JSON.stringify({ name: 'siyuan', main: 'main.js' }), 'main.js': 'console.log(1);' });
      write(path.join(resources, 'stage', 'build', 'app'), { 'main.js': 'function show(x) { document.body.innerHTML = x.content; }' });
      write(path.join(resources, 'kernel'), { 'readme.js': 'document.body.innerHTML = location.hash;' });
      const { issues } = await run({ input: path.join(resources, 'app'), offline: true, customScan: ['xsssinkjscheck'] });
      const files = issues.filter(issue => issue.id === 'XSS_SINK_JS_CHECK').map(issue => issue.file);
      assert.deepEqual(files, ['resources/stage/build/app/main.js']);
    });

    it('reads security settings in shipped launcher scripts', () => {
      write(root, {
        'app-no-cert-check.bat': '@echo off\r\n:: NODE_TLS_REJECT_UNAUTHORIZED=0 in a comment does not count\r\nset NODE_TLS_REJECT_UNAUTHORIZED=0\r\nstart app.exe\r\n',
        'app-debug.ps1': 'Start-Process ./app.exe -ArgumentList "--remote-debugging-port=9222"',
        'app-portable.bat': 'set APP_DATA_DIR=%~dp0data\r\nstart app.exe',
      });
      const found = launcherScriptIssues(root).map(issue => [issue.id, path.basename(issue.file), issue.location.line]).sort();
      assert.deepEqual(found, [['CUSTOM_ARGUMENTS_SCRIPT', 'app-debug.ps1', 1], ['NODE_TLS_REJECT_UNAUTHORIZED_SCRIPT', 'app-no-cert-check.bat', 3]]);
    });
  });

  describe('secrets', () => {
    it('skips translated text, grammar tokens, protocol methods and regular expressions', () => {
      for (const text of ['"no_tokens_yet": "目前还没有令牌哦"', 'token:"variable-2"', 'O.DIALOG_PASSWORD = "dialog-password"',
        'x.method = "textDocument/semanticTokens/full"', 'tokens = "+JSON|NaN|Infinity"', '"secret": "secret-password"'])
        assert.deepEqual(secrets.findSecrets(text), [], text);
    });

    it('names public-by-design keys, and reports them only from the package', () => {
      const jwt = ['eyJhbGciOiJFUzI1NiJ9', Buffer.from(JSON.stringify({ exp: 1787270400, distributionChannel: 'app', features: ['APP'] })).toString('base64url'), 'c2lnbmF0dXJlLXZhbHVl'].join('.');
      assert.deepEqual(secrets.findSecrets(`const licenseKey = "${jwt}";`, { includePublic: true }).map(hit => hit.kind), ['Product licence key (JWT)']);
      assert.deepEqual(secrets.findSecrets(`const licenseKey = "${jwt}";`).map(hit => hit.kind), []);
      const firebase = '{apiKey:"AIza' + 'SyAd15pYlMci_xIp9ko6wkEsDzAAA0Dn0RU",authDomain:"x.firebaseapp.com"}';
      assert.deepEqual(secrets.findSecrets(firebase, { includePublic: true }).map(hit => hit.kind), ['Firebase web API key']);
    });
  });

  describe('scan cost', () => {
    it('does not follow the assignments of a minified variable as a dispatch table', async function () {
      this.timeout(30000);
      // e[a] = e[b] for a hundred keys: followed as a table, one computed call fans out exponentially
      const lines = Array.from({ length: 100 }, (_, i) => `e[k${i}] = e[k${(i + 1) % 100}];`).join('\n');
      const app = write(path.join(root, 'bundle'), { 'package.json': JSON.stringify({ name: 'bundle', main: 'main.js' }),
        'main.js': `const { shell } = require('electron');\nconst e = {};\n${lines}\nfunction go(url) { e[url](url); shell.openExternal(url); }\nfunction later(t) { go(t); }\ngo('https://example.com');` });
      const started = Date.now();
      const { issues } = await run({ input: app, offline: true, customScan: ['openexternaljscheck'] });
      assert.ok(Date.now() - started < 20000);
      assert.ok(issues.some(issue => issue.id === 'OPEN_EXTERNAL_JS_CHECK'));
    });
  });

  describe('runtime', () => {
    it('reports a local service that other origins can read, or that listens on every interface', () => {
      const { issues } = analyzeProofs([
        { kind: 'proof', test: 'local-service-cors', outcome: 'foreign-origin-allowed', port: 6806, address: '127.0.0.1', exposed: false, status: 200,
          origins: [{ origin: 'chrome-extension://engprooftestextensionid', method: 'GET', allowOrigin: 'chrome-extension://engprooftestextensionid', credentials: false }] },
        { kind: 'proof', test: 'local-service-cors', outcome: 'no-cors-for-foreign-origin', port: 37840, address: '0.0.0.0', exposed: true, status: 302, origins: [] },
        { kind: 'proof', test: 'local-service-cors', outcome: 'no-cors-for-foreign-origin', port: 50450, address: '127.0.0.1', exposed: false, status: 200, origins: [] },
      ]);
      const services = issues.filter(issue => issue.id === 'RUNTIME_LOCAL_SERVICE');
      assert.deepEqual(services.map(issue => [issue.properties.port, issue.severity.name]), [[6806, 'HIGH'], [37840, 'MEDIUM']]);
      assert.equal(issues.filter(issue => issue.properties && issue.properties.port === 50450 && issue.severity.name !== 'INFORMATIONAL').length, 0);
    });

    it('reports default permission checks once per origin, and the app moving to its own server as expected', () => {
      const { issues } = analyzeWatchLog([{ kind: 'start' },
        { kind: 'windows-listener', pid: 1, address: '127.0.0.1', port: 50450, transport: 'tcp' },
        ...['media', 'geolocation', 'background-sync'].map(permission => ({ kind: 'permission-check', permission, origin: 'http://127.0.0.1:50450/', granted: true, default: true })),
        { kind: 'did-navigate', id: 1, url: 'file:///app/boot.html' },
        { kind: 'did-navigate', id: 1, url: 'http://127.0.0.1:50450/stage/build/app/' },
        { kind: 'will-redirect', id: 1, url: 'http://127.0.0.1:50450/stage/', from: 'file:///app/boot.html' }]);
      const checks = issues.filter(issue => issue.id === 'RUNTIME_PERMISSION_CHECK');
      assert.equal(checks.length, 1);
      assert.deepEqual(checks[0].properties.permissions, ['media', 'geolocation', 'background-sync']);
      assert.ok(issues.filter(issue => issue.id === 'RUNTIME_NAVIGATION').every(issue => issue.severity.name === 'INFORMATIONAL'));
      assert.equal(issues.filter(issue => issue.id === 'RUNTIME_REDIRECT').length, 0);
    });
  });
});
