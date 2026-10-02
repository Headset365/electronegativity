// Regressions from the Notesnook 3.3.14 review: the misses (end of life read from the executable, pdf.js, RPC procedures)
// and the false positives (timers, page input reported as deep links, placeholder secrets, signed download links, the
// tool's own ports, captured copies of packaged files, unverifiable signatures).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { detectLibraries } from '../src/util/libraries.js';
import { annotateShipment } from '../src/util/shipment.js';
import { componentTable } from '../src/report/xlsx.js';
import { analyzeProofs } from '../src/watch/proof-analysis.js';
import { inconclusiveSignature } from '../src/binary/signature.js';
import { LoaderDirectory } from '../src/loader/loader_directory.js';
import { LoaderCombined } from '../src/loader/loader_combined.js';
import run from '../src/runner.js';
import _i18n from '../src/locales/i18n.js';

await _i18n();
const require = createRequire(import.meta.url);
const secrets = require('../src/traffic/secrets.cjs');
const { TrafficAnalyzer } = require('../src/traffic/detectors.cjs');

const check = (exchanges) => {
  const analyzer = new TrafficAnalyzer();
  for (const ex of exchanges) analyzer.learn(ex);
  for (const ex of exchanges) analyzer.exchange(ex);
  return analyzer.results();
};
const get = (url) => ({ method: 'GET', url, requestHeaders: [], responseHeaders: [], status: 200 });

describe('Gaps from the Notesnook review', () => {
  let root;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-gaps-')); });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (dir, files) => {
    for (const [name, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), content);
    }
    return dir;
  };

  describe('component inventory', () => {
    it('names the React sub-package a banner heads, and finds pdf.js with its eval setting', () => {
      const banner = (version, file) => `/**\n * @license React v${version}\n * ${file}\n *\n * Copyright (c) Facebook, Inc.\n */var a=1;`;
      assert.deepEqual(detectLibraries(banner('16.13.1', 'react-is.production.min.js')), [{ name: 'react-is', version: '16.13.1' }]);
      assert.deepEqual(detectLibraries(banner('18.3.1', 'react-jsx-runtime.production.min.js')), [{ name: 'react', version: '18.3.1' }]);
      assert.deepEqual(detectLibraries(banner('18.3.1', 'react-dom.production.min.js')), [{ name: 'react-dom', version: '18.3.1' }]);
      const pdf = 'const de={docId:H,apiVersion:"3.6.172",data:B};';
      assert.deepEqual(detectLibraries(pdf), [{ name: 'pdfjs-dist', version: '3.6.172' }]);
      const [mitigated] = detectLibraries(`${pdf} transformGetDocumentParams:ie=>(ie.isEvalSupported=!1,ie)`);
      assert.match(mitigated.note, /isEvalSupported is turned off/);
    });

    it('labels a library seen only on the app server, and shows a mitigation note in the workbook', () => {
      const rows = annotateShipment([
        { name: 'dompurify', version: '3.3.3', kinds: ['served by the app server'], locations: ['https://app.test/a.js'], dev: true, advisories: [{ id: 'GHSA-x', severity: 'HIGH' }] },
        { name: 'pdfjs-dist', version: '3.6.172', kinds: ['bundled library'], locations: ['build/a.js'], advisories: [{ id: 'GHSA-y', severity: 'HIGH' }],
          fixedIn: '4.2.67', notes: ['isEvalSupported is turned off in this file'] },
      ], { packaged: true });
      assert.equal(rows[0].shipment.status, 'loaded-from-server');
      assert.equal(rows[0].dev, false);
      assert.equal(rows[1].shipment.status, 'present-in-package');
      const table = componentTable({ rows });
      const pdf = table.rows.find(row => row[0] === 'pdfjs-dist');
      assert.ok(pdf.some(cell => /Note: isEvalSupported is turned off/.test(String(cell))));
      const served = table.catalog.find(row => row[0] === 'dompurify');
      assert.match(served[3], /served by the app server/);
      assert.equal(served[1], 'JS library');
    });
  });

  describe('Electron version from the executable', () => {
    it('gives the version checks an Electron version when only the executable names it', async () => {
      // a packaged layout: <install>/resources/app with an executable next to resources/
      const install = path.join(root, 'App');
      write(path.join(install, 'resources', 'app'), { 'package.json': JSON.stringify({ name: 'packaged', main: 'main.js' }), 'main.js': 'console.log(1);' });
      fs.writeFileSync(path.join(install, 'App.exe'), Buffer.concat([Buffer.from('MZ'), Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), Buffer.from([1, 2]),
        Buffer.from('01'), Buffer.alloc(64), Buffer.from('Electron/37.6.1 Chrome/138.0.7204.251')]));
      const result = await run({ input: path.join(install, 'resources', 'app'), offline: true, customScan: ['electronversionjsoncheck'] });
      assert.equal(result.electronVersionSource, 'packaged executable');
      const version = result.issues.filter(issue => issue.id === 'ELECTRON_VERSION_JSON_CHECK');
      assert.equal(version.length, 1);
      assert.equal(version[0].properties.versionNumber, '37.6.1');
    });
  });

  describe('false positives', () => {
    it('ignores template placeholders, routes, selectors and constant names as secrets', () => {
      for (const text of ['help: "http://username:password@foobar:80"', 'x\\nhttp://user:pass@proxy:8080', 'a = "https://[username]:[password]@host"',
        'password: "/login/forgot-password"', 'inboxApiKeys: "/inbox/api-keys"', 'passwordField: "[type=password]"', 'RequiredPassword: "RequiredPasswordValue"'])
        assert.deepEqual(secrets.findSecrets(text), [], text);
      assert.deepEqual(secrets.findSecrets('db = "https://admin:Zq8Lm2Vt9R@db.internal"').map(hit => hit.kind), ['Basic-auth credentials in URL']);
      assert.deepEqual(secrets.findSecrets('const token = "ghx8Kq2LmP0vZr7TnB4w";').map(hit => hit.kind), ['Hard-coded token']);
    });

    it('reports a signed download link as informational, and a JSON query value not at all', () => {
      const signed = check([get('https://release-assets.githubusercontent.com/a/1?sp=r&sv=2018-11-09&sr=b&se=2026-10-01T10%3A00%3A00Z&sig=' +
        'Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs1Xc5Vb7Nm9Qw2Er4Ty6Ui8Op' + '&jwt=' + ['eyJhbGciOiJIUzI1NiJ9', 'eyJleHAiOjE3OTB9', 'c2lnbmF0dXJlLXZhbHVl'].join('.'))])
        .find(f => f.id === 'TRAFFIC_SECRET_IN_URL');
      assert.equal(signed.severity, 'INFORMATIONAL');
      assert.equal(signed.properties.presigned, true);
      const rpc = check([get(`https://themes-api.test/updateTheme?input=${encodeURIComponent('{"0":{"json":{"id":"Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs1Xc5Vb7"}}}')}`)]);
      assert.equal(rpc.filter(f => f.id === 'TRAFFIC_SECRET_IN_URL').length, 0);
      const token = check([get('https://api.test/x?access_token=Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs')]).find(f => f.id === 'TRAFFIC_SECRET_IN_URL');
      assert.equal(token.severity, 'HIGH');
    });

    it('summarises UDP endpoints and leaves out the tool’s own ports', () => {
      const { issues } = analyzeProofs([
        { kind: 'windows-listener', pid: 10, address: '127.0.0.1', port: 60944, transport: 'tcp', toolInspector: true },
        { kind: 'windows-listener', pid: 11, address: '0.0.0.0', port: 58311, transport: 'udp', toolInspector: false },
        { kind: 'windows-listener', pid: 11, address: '0.0.0.0', port: 55902, transport: 'udp', toolInspector: false },
        { kind: 'windows-listener', pid: 11, address: '127.0.0.1', port: 8080, transport: 'tcp', toolInspector: false },
      ]);
      const listeners = issues.filter(issue => issue.id === 'WINDOWS_LOCAL_LISTENER');
      assert.equal(listeners.length, 2);
      assert.ok(listeners.some(issue => /listens on 127\.0\.0\.1:8080/.test(issue.description)));
      assert.ok(listeners.some(issue => /2 UDP endpoint/.test(issue.description)));
      assert.ok(!listeners.some(issue => /60944/.test(issue.description)));
    });

    it('treats a signature Windows could not finish checking as inconclusive', () => {
      assert.equal(inconclusiveSignature({ status: 'UnknownError', signer: 'CN=Vendor', verifiedBy: 'windows' }), true);
      assert.equal(inconclusiveSignature({ status: 'Unknown', signer: 'CN=Vendor', verifiedBy: 'windows' }), true);
      assert.equal(inconclusiveSignature({ status: 'HashMismatch', signer: 'CN=Vendor', verifiedBy: 'windows' }), false);
      assert.equal(inconclusiveSignature({ status: 'Unknown', verifiedBy: 'windows' }), false);
    });

    it('scans a captured copy of a packaged file once, as the package file', async () => {
      const app = write(path.join(root, 'app'), { 'package.json': '{"name":"a"}', 'build/assets/app-Cz12.js': 'document.body.innerHTML = location.hash;' });
      const capture = write(path.join(root, 'capture'), { 'app.test/assets/app-Cz12.js': 'document.body.innerHTML = location.hash;', 'app.test/assets/other.js': 'var x = 1;' });
      const primary = new LoaderDirectory();
      await primary.load(app, { packaged: true });
      const extra = new LoaderDirectory();
      await extra.load(capture, { packaged: true });
      const combined = new LoaderCombined(primary, [extra]);
      assert.equal(combined.duplicatesOfPackage.length, 1);
      const files = [...combined.list_files].map(file => path.relative(root, file).split(path.sep).join('/'));
      assert.ok(files.includes('capture/app.test/assets/other.js'));
      assert.ok(!files.includes('capture/app.test/assets/app-Cz12.js'));
    });

    it('reports page input routes under their own check, and only when they reach something', async () => {
      const app = write(path.join(root, 'flows'), {
        'package.json': JSON.stringify({ name: 'flows', main: 'main.js', devDependencies: { electron: '38.0.0' } }),
        'main.js': `document.addEventListener('drop', e => handle(e));\ndocument.addEventListener('paste', e => { document.body.innerHTML = e.clipboardData.getData('text/html'); });`,
      });
      const { issues } = await run({ input: app, offline: true, customScan: ['entrypointflowsjscheck'] });
      assert.equal(issues.filter(issue => issue.id === 'FILE_HANDLER_JS_CHECK').length, 0);
      const flows = issues.filter(issue => issue.id === 'RENDERER_INPUT_JS_CHECK');
      const paste = flows.find(issue => issue.properties.event === 'paste');
      assert.equal(paste.severity.name, 'MEDIUM');
      for (const flow of flows.filter(issue => issue.properties.event === 'drop')) assert.equal(flow.severity.name, 'INFORMATIONAL');
    });
  });
});
