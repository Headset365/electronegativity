import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { parseHar, parseBurp, parseCapture, splitMessage, analyzeCaptures, IngestError } from '../src/traffic/ingest.js';
import { reconcileTraffic } from '../src/traffic/reconcile.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { severity, confidence } from '../src/finder/attributes.js';

const require = createRequire(import.meta.url);
const secrets = require('../src/traffic/secrets.cjs');
const { TrafficAnalyzer, registrableDomain, isLoopback } = require('../src/traffic/detectors.cjs');
const { createTrafficObserver } = require('../src/watch/traffic_hook.cjs');

chaiShould();
await _i18n();

const FIXTURE = path.join(import.meta.dirname, 'traffic', 'insecure.har');
const b64 = (text) => Buffer.from(text).toString('base64');
const burp = (items) => Buffer.from(`<?xml version="1.0"?>\n<items>${items}</items>`);
// runs the checks on exchanges, the way a capture is: scope first, then the checks
function check(exchanges, options) {
  const analyzer = new TrafficAnalyzer(options);
  for (const ex of exchanges) analyzer.learn(ex);
  for (const ex of exchanges) analyzer.exchange(ex);
  return Object.fromEntries(analyzer.results().map(f => [f.id, f]));
}
// fake credentials, split so secret scanners don't take the test source for a leak
const AWS_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
const ex = (method, url, { req = [], res = [], status = 200, body, rbody } = {}) => ({ method, url, requestHeaders: req, responseHeaders: res, status, requestBody: body, responseBody: rbody });

describe('Traffic', () => {
  describe('secrets', () => {
    it('recognizes provider keys and secret-named assignments, and redacts', () => {
      const found = secrets.findSecrets(`key ${AWS_KEY} and ghp_` + 'a'.repeat(36) + ' const apiKey = "Zq8Lm2Vt9Rk4Zp8W";');
      found.map(f => f.kind).should.include.members(['AWS access key id', 'GitHub token', 'Hard-coded apiKey']);
      secrets.redact(AWS_KEY).should.equal('AKIA…[redacted 20 chars]');
      secrets.redactText(`x ${AWS_KEY} y`).should.equal('x AKIA…[redacted 20 chars] y');
    });

    it('checks config values by entropy, but not hashes or words', () => {
      const config = 'API_TOKEN=Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs\nintegrity: sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\nsomeKey: "' + ['aB3dE5gH7jK9mN1pQ3sT5vX7', 'zA9cE1gI3kM5oQ7s'].join('') + '"\nlabel: ThisIsAVeryLongCamelCaseIdentifierName';
      const kinds = secrets.findSecrets(config, { config: true }).map(f => f.kind);
      kinds.should.include('Hard-coded API_TOKEN');
      kinds.should.include('High-entropy value (someKey)');
      kinds.some(k => /integrity|label/.test(k)).should.equal(false);
    });

    it('tells secret parameter names by whole words', () => {
      ['access_token', 'apiKey', 'X-Api-Key', 'session', 'client_secret'].forEach(name => secrets.isSensitiveParam(name).should.equal(true, name));
      ['author', 'side', 'design', 'page'].forEach(name => secrets.isSensitiveParam(name).should.equal(false, name));
      secrets.isAuthHeader('X-Custom-Token').should.equal(true);
      secrets.isAuthHeader('Accept').should.equal(false);
    });
  });

  describe('captures', () => {
    it('reads a HAR file, with base64 gzip bodies and WebSocket messages', () => {
      const gz = zlib.gzipSync('hello gzipped world');
      const har = { log: { entries: [
        { request: { method: 'POST', url: 'https://x.test/a?b=1', headers: [{ name: 'Content-Type', value: 'application/json' }], postData: { text: '{"k":1}' } },
          response: { status: 201, headers: [{ name: 'Content-Type', value: 'application/json' }], content: { text: '{"ok":true}' } } },
        { request: { method: 'GET', url: 'https://x.test/g', headers: [] },
          response: { status: 200, headers: [{ name: 'Content-Encoding', value: 'gzip' }], content: { encoding: 'base64', text: gz.toString('base64') } } },
        { request: { method: 'GET', url: 'ws://x.test/s', headers: [] }, response: { status: 101, headers: [] },
          _webSocketMessages: [{ type: 'receive', opcode: 1, data: '<b>hi</b>' }, { type: 'send', opcode: 1, data: 'ping' }] },
      ] } };
      const capture = parseHar(JSON.stringify(har));
      capture.exchanges.length.should.equal(2);
      capture.exchanges[0].should.include({ method: 'POST', url: 'https://x.test/a?b=1', status: 201, requestBody: '{"k":1}', responseBody: '{"ok":true}' });
      capture.exchanges[1].responseBody.should.equal('hello gzipped world');
      capture.websockets.should.deep.equal([{ url: 'ws://x.test/s', messages: [{ direction: 'receive', data: '<b>hi</b>' }, { direction: 'send', data: 'ping' }] }]);
      (() => parseHar('{not json')).should.throw(IngestError);
      (() => parseHar('{"notlog": 1}')).should.throw(IngestError);
    });

    it('reads Burp Suite items, base64 and chunked', () => {
      const req = 'GET /path?token=abc HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer xyz\r\n\r\n';
      const res = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello';
      let capture = parseBurp(burp(`<item><url>https://api.test/path?token=abc</url><method>GET</method><request base64="true">${b64(req)}</request><response base64="true">${b64(res)}</response><status>200</status></item>`));
      capture.exchanges.length.should.equal(1);
      capture.exchanges[0].should.include({ method: 'GET', status: 200, responseBody: 'hello' });
      capture.exchanges[0].requestHeaders.should.deep.include(['Authorization', 'Bearer xyz']);
      const chunked = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n';
      capture = parseBurp(burp(`<item><url>http://h.test/</url><method>GET</method><request base64="true">${b64('GET / HTTP/1.1\r\nHost: h.test\r\n\r\n')}</request><response base64="true">${b64(chunked)}</response></item>`));
      capture.exchanges[0].responseBody.should.equal('hello world');
      // no <url>: rebuilt from the request line and Host header
      capture = parseBurp(burp(`<item><request base64="true">${b64('POST /save HTTP/1.1\r\nHost: h.test\r\n\r\nx=1')}</request></item>`));
      capture.exchanges[0].should.include({ method: 'POST', url: 'http://h.test/save', requestBody: 'x=1' });
      (() => parseBurp(Buffer.from('<html></html>'))).should.throw(IngestError);
    });

    it('splits raw messages and tells formats apart by content', () => {
      const { startLine, headers, body } = splitMessage(Buffer.from('HTTP/1.1 200 OK\nA: b\n\nbody'));
      startLine.should.equal('HTTP/1.1 200 OK');
      headers.should.deep.equal([['A', 'b']]);
      body.toString().should.equal('body');
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-capture-'));
      fs.writeFileSync(path.join(dir, 'capture.txt'), '{"log":{"entries":[]}}');
      parseCapture(path.join(dir, 'capture.txt')).kind.should.equal('har');
      fs.writeFileSync(path.join(dir, 'items.txt'), '<?xml version="1.0"?><items></items>');
      parseCapture(path.join(dir, 'items.txt')).kind.should.equal('burp');
    });
  });

  describe('checks', () => {
    it('reports the problems in a capture of an insecure app', () => {
      const { issues, summary } = analyzeCaptures([FIXTURE]);
      const ids = issues.map(i => i.id);
      ids.should.include.members(['TRAFFIC_CLEARTEXT_HTTP', 'TRAFFIC_SECRET_IN_URL', 'TRAFFIC_AUTH_TO_THIRD_PARTY', 'TRAFFIC_USER_INPUT_TO_THIRD_PARTY',
        'TRAFFIC_IDOR_CANDIDATE', 'TRAFFIC_REFLECTED_INPUT', 'TRAFFIC_SECRET_IN_RESPONSE', 'TRAFFIC_INSECURE_COOKIE', 'TRAFFIC_WS_CLEARTEXT',
        'TRAFFIC_WS_SECRET_IN_URL', 'TRAFFIC_WS_HTML_MESSAGE']);
      summary.firstParty.should.deep.equal(['insecure-fixture.test']);
      // evidence never carries a whole secret
      const text = JSON.stringify(issues);
      text.should.not.include('abcdef123456SECRETtoken');
      text.should.not.include('s3cr3ttok3nABCDEF');
      // markup sent in a parameter coming back unencoded in HTML
      issues.find(i => i.id === 'TRAFFIC_REFLECTED_INPUT').severity.should.equal(severity.MEDIUM);
      issues.every(i => i.constructorName === 'Runtime' && i.properties.source === 'capture').should.equal(true);
    });

    it('leaves the local machine and settings without a known first party alone', () => {
      check([ex('GET', 'http://localhost:3000/x')]).should.not.have.property('TRAFFIC_CLEARTEXT_HTTP');
      check([ex('GET', 'https://who.test/x', { req: [['Authorization', 'Bearer zzzzzzzz']] })]).should.not.have.property('TRAFFIC_AUTH_TO_THIRD_PARTY');
      const found = check([ex('GET', 'https://cdn.other.test/x', { req: [['Authorization', 'Bearer zzzzzzzz']] })], { scope: ['app.test'] });
      found.should.have.property('TRAFFIC_AUTH_TO_THIRD_PARTY');
      isLoopback('127.0.0.5').should.equal(true);
      isLoopback('[::1]').should.equal(true);
      registrableDomain('a.b.example.co.uk').should.equal('example.co.uk');
    });

    it('reports each check on the exchanges that call for it', () => {
      const found = check([
        ex('POST', 'https://app.test/save', { res: [['Set-Cookie', 's=x1234567; Path=/']], req: [['Content-Type', 'application/x-www-form-urlencoded']], body: 'display=UniqueAlice123' }),
        ex('GET', 'https://ads.other/t?u=UniqueAlice123'),
        ex('GET', 'https://app.test/api/user/4092/profile', { req: [['Authorization', 'Bearer tok12345']] }),
        ex('DELETE', 'https://app.test/item/1'),
        ex('GET', 'https://app.test/s?q=NEEDLE12345', { res: [['Content-Type', 'text/html']], rbody: '<html>results for NEEDLE12345</html>' }),
        ex('GET', 'https://app.test/me', { res: [['Content-Type', 'application/json']], rbody: '{"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.aaaaaaaaaaaaaaaaaaaa"}' }),
        ex('GET', 'http://app.test/x', { req: [['Authorization', 'Basic dXNlcjpwYXNz']] }),
      ]);
      found.should.include.keys('TRAFFIC_USER_INPUT_TO_THIRD_PARTY', 'TRAFFIC_IDOR_CANDIDATE', 'TRAFFIC_STATE_CHANGE_NO_AUTH', 'TRAFFIC_REFLECTED_INPUT', 'TRAFFIC_SECRET_IN_RESPONSE', 'TRAFFIC_BASIC_AUTH', 'TRAFFIC_INSECURE_COOKIE');
      found.TRAFFIC_BASIC_AUTH.severity.should.equal('HIGH'); // over http
      check([ex('GET', 'https://app.test/api/user/4092')]).should.not.have.property('TRAFFIC_IDOR_CANDIDATE'); // not authenticated
      check([ex('DELETE', 'https://app.test/item/1', { req: [['Authorization', 'Bearer t']] })]).should.not.have.property('TRAFFIC_STATE_CHANGE_NO_AUTH');
      check([ex('GET', 'https://app.test/x', { res: [['Set-Cookie', 'sid=abc; Secure; HttpOnly; Path=/']] })]).should.not.have.property('TRAFFIC_INSECURE_COOKIE');
    });

    it('merges repeats into one finding with a count', () => {
      const found = check([ex('GET', 'http://app.test/a'), ex('GET', 'http://app.test/b')]);
      found.TRAFFIC_CLEARTEXT_HTTP.count.should.equal(2);
      found.TRAFFIC_CLEARTEXT_HTTP.evidence.length.should.equal(2);
    });

    it('checks WebSocket connections and messages', () => {
      const analyzer = new TrafficAnalyzer();
      analyzer.wsOpen('ws://chat.test/s?token=SECRETtoken12345');
      analyzer.wsMessage('ws://chat.test/s', 'receive', `{"body":"<img src=x onerror=alert(1)>","key":"${AWS_KEY}"}`);
      analyzer.wsMessage('ws://chat.test/s', 'send', '<b>sent by us</b>');
      analyzer.results().map(f => f.id).should.deep.equal(['TRAFFIC_WS_CLEARTEXT', 'TRAFFIC_WS_SECRET_IN_URL', 'TRAFFIC_WS_HTML_MESSAGE', 'TRAFFIC_WS_SECRET_IN_MESSAGE']);
    });

    it('confirms static findings the traffic backs', () => {
      const issue = (id, extra = {}) => ({ id, file: 'main.js', sample: '', description: '', location: { line: 1, column: 0 }, severity: severity.MEDIUM, confidence: confidence.FIRM, ...extra });
      const issues = [
        issue('HTTP_RESOURCES_JS_CHECK', { sample: "win.loadURL('http://app.test/index.html')" }),
        issue('CERTIFICATE_PINNING_GLOBAL_CHECK'),
        issue('XSS_SINK_JS_CHECK', { properties: { origin: 'a WebSocket message' } }),
        issue('TRAFFIC_CLEARTEXT_HTTP', { properties: { host: 'app.test' } }),
        issue('TRAFFIC_WS_HTML_MESSAGE', { properties: { host: 'chat.test' } }),
      ];
      reconcileTraffic(issues, { interceptedHttps: 3 });
      issues[0].validation.status.should.equal('confirmed');
      issues[1].validation.status.should.equal('confirmed');
      issues[2].validation.status.should.equal('observed');
      const noProxy = [issue('CERTIFICATE_PINNING_GLOBAL_CHECK')];
      reconcileTraffic(noProxy, {});
      (noProxy[0].validation === undefined).should.equal(true);
    });
  });

  describe('scan', () => {
    it('adds the findings of --ingest captures to a scan, with or without code', async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-ingest-'));
      fs.writeFileSync(path.join(dir, 'main.js'), "const { BrowserWindow } = require('electron');\nnew BrowserWindow({}).loadURL('http://app.insecure-fixture.test/');\n");
      const output = path.join(dir, 'report.json');
      const result = await run({ input: dir, captures: [FIXTURE], offline: true, output });
      result.issues.map(i => i.id).should.include.members(['TRAFFIC_CLEARTEXT_HTTP', 'TRAFFIC_WS_HTML_MESSAGE']);
      result.traffic.files.should.equal(1);
      const loaded = result.issues.find(i => i.id === 'HTTP_RESOURCES_JS_CHECK');
      if (loaded) loaded.validation.status.should.equal('confirmed');
      JSON.parse(fs.readFileSync(output, 'utf8')).traffic.http.should.equal(4);
      const html = path.join(dir, 'report.html');
      await run({ input: dir, captures: [FIXTURE], offline: true, output: html });
      fs.readFileSync(html, 'utf8').should.include('Captured traffic');
      // a capture that can't be read is an error, not a crash
      fs.writeFileSync(path.join(dir, 'broken.har'), '{nope');
      const broken = await run({ input: dir, captures: [path.join(dir, 'broken.har')], offline: true });
      broken.errors.some(e => e.file === 'capture' && /invalid HAR/.test(e.message)).should.equal(true);
    });
  });

  describe('watch mode', () => {
    // a stand-in for webContents.debugger: records commands, and the test sends it DevTools protocol events
    function fakeContents(id = 1) {
      const dbg = new EventEmitter();
      let attached = false;
      dbg.attach = () => { if (attached) throw new Error('Another debugger is already attached'); attached = true; };
      dbg.detach = () => { attached = false; dbg.emit('detach'); };
      dbg.isAttached = () => attached;
      dbg.commands = [];
      dbg.sendCommand = (method, params) => {
        dbg.commands.push(method);
        if (method === 'Network.getResponseBody') return Promise.resolve({ body: '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.aaaaaaaaaaaaaaaaaaaa"}', base64Encoded: false });
        return Promise.resolve({ params });
      };
      const contents = new EventEmitter();
      contents.id = id;
      contents.debugger = dbg;
      return contents;
    }
    const tick = () => new Promise(resolve => setImmediate(resolve));

    it('checks what each window sends and receives, through its DevTools protocol connection', async () => {
      const records = [];
      const traffic = createTrafficObserver({ write: (kind, data) => records.push({ kind, ...data }) });
      const contents = fakeContents();
      traffic.attach(contents);
      contents.debugger.isAttached().should.equal(true);
      await tick();
      contents.debugger.commands.should.include('Network.enable');
      const send = (method, params) => contents.debugger.emit('message', {}, method, params);
      traffic.onBeforeRequest({ id: 1, url: 'https://app.test/', resourceType: 'mainFrame', webContentsId: 1, method: 'GET' });
      // the ExtraInfo events can come first: the headers actually sent and received, cookies included
      send('Network.requestWillBeSentExtraInfo', { requestId: 'r1', headers: { Cookie: 'sid=abcdefgh12345678' } });
      send('Network.responseReceivedExtraInfo', { requestId: 'r1', headers: { 'set-cookie': 'sid=abcdefgh12345678; Path=/' } });
      send('Network.requestWillBeSent', { requestId: 'r1', type: 'XHR', request: { method: 'GET', url: 'https://app.test/api/me', headers: {} } });
      send('Network.responseReceived', { requestId: 'r1', type: 'XHR', response: { status: 200, headers: {}, mimeType: 'application/json' } });
      send('Network.loadingFinished', { requestId: 'r1', encodedDataLength: 100 });
      send('Network.webSocketCreated', { requestId: 'w1', url: 'ws://app.test/live' });
      send('Network.webSocketFrameReceived', { requestId: 'w1', response: { opcode: 1, payloadData: '<img src=x onerror=alert(1)>' } });
      await tick();
      await tick();
      traffic.flush();
      const last = records.filter(r => r.kind === 'traffic').pop();
      last.findings.map(f => f.id).should.include.members(['TRAFFIC_SECRET_IN_RESPONSE', 'TRAFFIC_INSECURE_COOKIE', 'TRAFFIC_WS_CLEARTEXT', 'TRAFFIC_WS_HTML_MESSAGE']);
      last.summary.sources.debugger.should.equal(1);
      JSON.stringify(records).should.not.include('abcdefgh12345678');
      // requests of a debugged window don't come twice through webRequest
      traffic.onBeforeRequest({ id: 2, url: 'http://app.test/x', resourceType: 'xhr', webContentsId: 1, method: 'GET' });
      traffic.onHeadersReceived({ id: 2, statusCode: 200, responseHeaders: {} });
      traffic.flush();
      records.filter(r => r.kind === 'traffic').pop().summary.sources.webRequest.should.equal(0);
    });

    it('steps aside when the app attaches its own debugger', () => {
      const records = [];
      const traffic = createTrafficObserver({ write: (kind, data) => records.push({ kind, ...data }) });
      const contents = fakeContents(2);
      traffic.attach(contents);
      (() => contents.debugger.attach('1.3')).should.not.throw();
      records.some(r => r.kind === 'traffic-note' && /own debugger/.test(r.message)).should.equal(true);
    });

    it('falls back to the session\'s webRequest events', () => {
      const records = [];
      const traffic = createTrafficObserver({ write: (kind, data) => records.push({ kind, ...data }), scope: ['app.test'] });
      traffic.onBeforeRequest({ id: 7, url: 'https://tracker.other/c?u=1', method: 'GET', resourceType: 'xhr' });
      traffic.onSendHeaders({ id: 7, requestHeaders: { 'X-Auth-Token': 'Qx7Lm2Vt9Rk4Zp8W' } });
      traffic.onHeadersReceived({ id: 7, statusCode: 200, responseHeaders: { 'Set-Cookie': ['t=1'] } });
      traffic.flush();
      records.pop().findings.map(f => f.id).should.include('TRAFFIC_AUTH_TO_THIRD_PARTY');
    });

    it('turns the session log into findings', () => {
      const { issues, summary } = analyzeWatchLog([
        { kind: 'start', electron: '38.0.0' },
        { kind: 'traffic', findings: [{ id: 'TRAFFIC_CLEARTEXT_HTTP', severity: 'MEDIUM', confidence: 'CERTAIN', description: 'Requests to a.test are sent over http', location: 'http://a.test', evidence: ['GET http://a.test/'], count: 2, properties: { host: 'a.test' } }], summary: { http: 2, ws: 0, hosts: 1, firstParty: [] } },
        { kind: 'traffic-note', message: 'debugger not attached' },
        { kind: 'console-secret', where: 'main', kinds: ['GitHub token'], evidence: ['GitHub token=ghp_…[redacted 40 chars]'] },
        { kind: 'page-exception', url: 'https://a.test/app.js', message: 'Uncaught Error: boom', line: 3 },
        { kind: 'main-exception', message: 'Error: main boom' },
        { kind: 'csp-violation', url: 'https://a.test/', directive: 'script-src', blocked: 'inline' },
      ]);
      const ids = issues.map(i => i.id);
      ids.should.include.members(['TRAFFIC_CLEARTEXT_HTTP', 'RUNTIME_SECRET_IN_CONSOLE', 'RUNTIME_UNCAUGHT_EXCEPTION', 'RUNTIME_CSP_VIOLATION']);
      ids.filter(id => id === 'RUNTIME_UNCAUGHT_EXCEPTION').length.should.equal(2);
      issues.find(i => i.id === 'TRAFFIC_CLEARTEXT_HTTP').description.should.include('seen 2 times');
      summary.traffic.notes.should.deep.equal(['debugger not attached']);
    });
  });
});
