import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { crawl } from '../src/remote/fetch.js';
import remoteHosts from '../src/remote/hosts.cjs';
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

  describe('--remote hosts and --remote-header names', () => {
    const { parseRemote, parseRemoteHeaders, hostAllowed, pickHeaders } = remoteHosts;
    it('takes host names, subdomain patterns and URLs, comma-separated or repeated', () => {
      parseRemote(['app.example.com, *.api.example.com', 'https://portal.example.com/login', 'cdn.example.com:8443']).should.deep.equal({
        seeds: ['https://app.example.com/', 'https://portal.example.com/login', 'https://cdn.example.com:8443/'],
        guessed: ['https://app.example.com/', 'https://cdn.example.com:8443/'],
        hosts: ['app.example.com', '*.api.example.com', 'portal.example.com', 'cdn.example.com'], invalid: [] });
      // a start page also given as a URL is not a guess
      parseRemote(['app.example.com', 'https://app.example.com/']).guessed.should.deep.equal([]);
      parseRemote(['bad host', '*.example.com/path', 'https://user:pw@example.com/']).invalid.should.have.length(3);
    });
    it('matches a host exactly, and a pattern on its subdomains only', () => {
      const hosts = ['app.example.com', '*.api.example.com'];
      hostAllowed('https://APP.example.com/x', hosts).should.equal(true);
      hostAllowed('https://v1.api.example.com/', hosts).should.equal(true);
      hostAllowed('https://api.example.com/', hosts).should.equal(false);
      hostAllowed('https://app.example.com.evil.test/', hosts).should.equal(false);
      hostAllowed('https://evilapp.example.com/', hosts).should.equal(false);
    });
    it('takes header names to copy, and Name: value headers whole', () => {
      parseRemoteHeaders(['Authorization,', 'ClientID, cookie', 'User-Agent', 'Accept: text/html, application/json', 'COOKIE']).should.deep.equal({
        fixed: { Accept: 'text/html, application/json' }, names: ['Authorization', 'ClientID', 'cookie', 'User-Agent'], invalid: [] });
      parseRemoteHeaders(['Bad Name']).invalid.should.deep.equal(['Bad Name']);
      pickHeaders({ authorization: 'Bearer t', Cookie: 'a=1', Other: 'x' }, ['Authorization', 'Cookie', 'ClientID']).should.deep.equal({ Authorization: 'Bearer t', Cookie: 'a=1' });
    });
  });

  it('with --remote, fetches from its hosts only, each with the headers copied for it', async () => {
    // another host (a different name for this machine): captured, redirected to and named in a page
    const seen = [];
    const other = http.createServer((req, res) => {
      seen.push(req.url);
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end('var x = 1;');
    });
    await new Promise(resolve => other.listen(0, resolve));
    const elsewhere = `http://localhost:${other.address().port}`;
    const mineSeen = [];
    const site = http.createServer((req, res) => {
      mineSeen.push({ url: req.url, cookie: req.headers.cookie, auth: req.headers.authorization, client: req.headers.clientid });
      if (req.url === '/go.js') { res.writeHead(302, { location: `${elsewhere}/landing.js` }); res.end(); return; }
      if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end('var app = 1;'); return; }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<script src="/app.js"></script><script src="/go.js"></script><script src="${elsewhere}/lib.js"></script>`);
    });
    await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
    const mine = `http://127.0.0.1:${site.address().port}`;
    try {
      const capture = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-hosts-'));
      fs.mkdirSync(path.join(capture, 'files'));
      fs.writeFileSync(path.join(capture, 'manifest.jsonl'), JSON.stringify({ kind: 'script', url: `${elsewhere}/captured.js` }) + '\n');
      const stats = await crawl(capture, [`${mine}/`], { allowHosts: ['127.0.0.1'], headers: { ClientID: 'fixed' },
        headersByHost: { '127.0.0.1': { Cookie: 'session=copied', Authorization: 'Bearer copied', ClientID: 'copied' }, localhost: { Cookie: 'other=1' } } });
      seen.should.deep.equal([], 'nothing is fetched from another host');
      // a start page guessed from a host name that doesn't answer is not an error
      const guess = await crawl(fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-guess-')), [], { allowHosts: ['127.0.0.1'], guessedSeeds: ['https://127.0.0.1:1/'] });
      guess.failed.should.deep.equal([]);
      guess.notFound.should.equal(1);
      stats.outOfScope.should.equal(2); // the captured script and the redirect (third-party scripts are never crawled)
      mineSeen.map(r => r.url).should.include.members(['/', '/app.js', '/go.js']);
      // the values copied for this host, and a header set by hand wins over a copied one
      mineSeen.every(r => r.cookie === 'session=copied' && r.auth === 'Bearer copied' && r.client === 'fixed').should.equal(true, JSON.stringify(mineSeen));
      // and its start page is fetched even when the session captured other files from it, over the scheme and port the app used
      mineSeen.length = 0;
      const started = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-guess-'));
      fs.mkdirSync(path.join(started, 'files'));
      fs.writeFileSync(path.join(started, 'files', 'w1.js'), 'var app = 1;');
      fs.writeFileSync(path.join(started, 'manifest.jsonl'), JSON.stringify({ kind: 'script', url: `${mine}/app.js`, file: 'files/w1.js' }) + '\n');
      const stats2 = await crawl(started, [], { allowHosts: ['127.0.0.1'], guessedSeeds: ['https://127.0.0.1/'] });
      mineSeen.map(r => r.url).should.include('/');
      stats2.failed.should.deep.equal([]);
    } finally {
      site.close();
      other.close();
    }
  });

  it('sends --remote-header only to the named site: not to captured third parties, nor across a redirect', async () => {
    // a third party the session happened to load (a sign-in provider, an embedded frame), and a redirect to it
    const seen = [];
    const other = http.createServer((req, res) => {
      seen.push({ url: req.url, cookie: req.headers.cookie, token: req.headers['x-api-key'] });
      res.writeHead(200, { 'content-type': req.url.endsWith('.js') ? 'application/javascript' : 'text/html' });
      res.end(req.url.endsWith('.js') ? 'var x = 1;' : '<script src="/embed.js"></script>');
    });
    await new Promise(resolve => other.listen(0, '127.0.0.1', resolve));
    const third = `http://127.0.0.1:${other.address().port}`;
    const site = http.createServer((req, res) => {
      if (req.url === '/go') { res.writeHead(302, { location: `${third}/landing.js` }); res.end(); return; }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<script src="/go"></script>');
    });
    await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
    const mine = `http://127.0.0.1:${site.address().port}`;
    try {
      const capture = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-scope-'));
      fs.mkdirSync(path.join(capture, 'files'));
      fs.writeFileSync(path.join(capture, 'files', 'w1.html'), '<script src="/embed.js"></script>');
      fs.writeFileSync(path.join(capture, 'manifest.jsonl'), JSON.stringify({ kind: 'page', url: `${third}/frame`, file: 'files/w1.html' }) + '\n');
      await crawl(capture, [`${mine}/`], { headers: { Cookie: 'session=test', 'X-Api-Key': 'k' } });
      seen.length.should.be.above(0, 'the third party was fetched');
      seen.every(r => !r.cookie && !r.token).should.equal(true, JSON.stringify(seen));
      // a later step with no seeds of its own: only the sites named with --remote get the headers
      const later = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-remote-scope-'));
      fs.mkdirSync(path.join(later, 'files'));
      fs.writeFileSync(path.join(later, 'manifest.jsonl'), JSON.stringify({ kind: 'page', url: `${third}/frame2` }) + '\n');
      seen.length = 0;
      await crawl(later, [], { headers: { Cookie: 'session=test' }, headerSites: [`${mine}/`] });
      seen.some(r => r.url === '/frame2').should.equal(true);
      seen.every(r => !r.cookie).should.equal(true);
    } finally {
      site.close();
      other.close();
    }
  });
});
