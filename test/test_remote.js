import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { crawl } from '../src/remote/fetch.js';
import { prepareScanFolder, referencedUrls, sourceMapUrl, originalSources } from '../src/remote/sources.js';

chaiShould();
await _i18n();

// A remote front end: a page, a minified bundle whose source map carries the original sources, a lazily loaded chunk and
// an AngularJS template named in the code
const editorSource = `document.querySelector('#ed').addEventListener('paste', (e) => {
  const html = e.clipboardData.getData('text/html');
  preview.innerHTML = html;
});`;
const configSource = `tinymce.init({ selector: '#ed', valid_elements: '*[*]' });
angular.module('app').directive('doc', () => ({ templateUrl: 'views/doc.html' }));`;
const map = JSON.stringify({ version: 3, file: 'app.min.js', mappings: '', names: [],
  sources: ['webpack://app/./src/editor.js', 'webpack://app/./src/config.js', 'webpack:///node_modules/some-lib/index.js', 'webpack://app/./src/styles.css'],
  sourcesContent: [editorSource, configSource, 'module.exports = 1;', 'body { color: red }'] });
const SITE = {
  '/': ['text/html', '<!doctype html><html><head><script src="/static/app.min.js"></script></head><body ng-app="app"><div id="ed"></div></body></html>'],
  '/static/app.min.js': ['application/javascript', `!function(){document.querySelector("#ed").addEventListener("paste",function(e){preview.innerHTML=e.clipboardData.getData("text/html")});import("./chunk.js")}();\n//# sourceMappingURL=app.min.js.map`],
  '/static/app.min.js.map': ['application/json', map],
  '/static/chunk.js': ['application/javascript', 'export function show(res) { panel.innerHTML = res.data; }'],
  '/views/doc.html': ['text/html', '<div ng-bind-html-unsafe="doc.body"></div>'],
};

describe('Remote front end', () => {
  let server;
  let base;
  const requests = [];
  before(async () => {
    server = http.createServer((req, res) => {
      requests.push({ url: req.url, cookie: req.headers.cookie });
      const page = SITE[req.url.split('?')[0]];
      if (!page) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'content-type': page[0] });
      res.end(page[1]);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => server.close());

  describe('helpers', () => {
    it('finds scripts, module imports and templates a page or script refers to, on the same origin only', () => {
      const html = '<script src="/a.js"></script><script src="https://cdn.example.com/lib.js"></script><link rel="modulepreload" href="/m.js">';
      referencedUrls(html, 'https://app.example.com/', 'https://app.example.com').should.have.members(['https://app.example.com/a.js', 'https://app.example.com/m.js']);
      const code = `import x from './dep.js'; const t = { templateUrl: 'views/editor.html' }; const n = 'x.js'; fetch(\`/api/\${id}.json\`);`;
      // module imports resolve against the script, other paths against the page, as the browser loads them
      referencedUrls(code, 'https://app.example.com/static/main.js', 'https://app.example.com', 'https://app.example.com/app/')
        .should.have.members(['https://app.example.com/static/dep.js', 'https://app.example.com/app/views/editor.html']);
    });

    it('reads the source map reference and the original sources', () => {
      sourceMapUrl('code\n//# sourceMappingURL=main.js.map', 'https://x.test/s/main.js').should.equal('https://x.test/s/main.js.map');
      const sources = originalSources(map);
      sources.map(s => s.name).should.deep.equal(['src/editor.js', 'src/config.js', 'node_modules/some-lib/index.js']);
    });
  });

  it('downloads a remote front end, scans the original sources and reports findings by URL', async () => {
    const capture = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-'));
    const stats = await crawl(capture, [`${base}/`], { headers: { Cookie: 'session=test' } });
    stats.fetched.should.equal(5); // page, bundle, map, chunk, template
    stats.failed.should.have.length(0);
    requests.filter(r => r.url === '/').every(r => r.cookie === 'session=test').should.equal(true);

    const prepared = prepareScanFolder(capture);
    prepared.counts.should.include({ pages: 1, bundlesReplaced: 1, recoveredSources: 3 });

    const result = await run({ input: prepared.dir, extraInputs: [prepared], offline: true, isRelative: true });
    const byId = (id) => result.issues.filter(i => i.id === id);
    // the paste handler, from the original source (not the minified bundle)
    const paste = byId('XSS_SINK_JS_CHECK').find(i => /pasted/.test(i.description));
    paste.file.should.equal(`${base}/static/app.min.js (source: src/editor.js)`);
    paste.location.line.should.equal(3);
    paste.severity.name.should.equal('HIGH');
    byId('SANITIZER_CONFIG_JS_CHECK')[0].file.should.match(/source: src\/config\.js/);
    // the lazily loaded chunk and the template were never linked from the page, but were found and scanned
    byId('XSS_SINK_JS_CHECK').some(i => i.file === `${base}/static/chunk.js`).should.equal(true);
    byId('ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK')[0].file.should.equal(`${base}/views/doc.html`);
    // library sources inside the map are left out like node_modules
    result.issues.some(i => /some-lib/.test(i.file)).should.equal(false);
  });

  it('completes what watch mode captured: source maps and files that were never loaded', async () => {
    const capture = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-watch-'));
    fs.mkdirSync(path.join(capture, 'files'));
    // as the hook records it: the page and bundle were saved, the map was not fetched
    fs.writeFileSync(path.join(capture, 'files', 'w1.html'), SITE['/'][1]);
    fs.writeFileSync(path.join(capture, 'files', 'w2.js'), SITE['/static/app.min.js'][1]);
    fs.writeFileSync(path.join(capture, 'manifest.jsonl'), [
      { kind: 'page', url: `${base}/`, file: 'files/w1.html' },
      { kind: 'script', url: `${base}/static/app.min.js`, file: 'files/w2.js' },
    ].map(e => JSON.stringify(e)).join('\n') + '\n');
    const stats = await crawl(capture, []);
    stats.fetched.should.equal(3); // map, chunk, template
    const prepared = prepareScanFolder(capture);
    [...prepared.labels.values()].should.include(`${base}/static/app.min.js (source: src/editor.js)`);
    [...prepared.labels.values()].should.include(`${base}/views/doc.html`);
  });
});
