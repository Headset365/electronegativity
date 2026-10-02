import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { analyzeProofs } from '../src/watch/proof-analysis.js';
import { proveRunAsNode } from '../src/watch/fuses.js';
import { fetchMetadata, inspectFeed, inspectServices } from '../src/watch/network-proofs.js';
import { annotateShipment } from '../src/util/shipment.js';
import { componentTable } from '../src/report/xlsx.js';
import { mergeDependencies } from '../src/report/combined.js';
import { reconcileRuntime } from '../src/watch/reconcile.js';
import { severity, confidence } from '../src/finder/attributes.js';

const require = createRequire(import.meta.url);
const { validateProfile } = require('../src/watch/proof-profile.cjs');
const { createProofs, sessionRequest } = require('../src/watch/proofs.cjs');
const { assessAcl, assessProtocol, readZone, powershell } = require('../src/watch/windows.cjs');
const { observeUpdater } = require('../src/watch/update-observer.cjs');

class Contents extends EventEmitter {
  constructor(id = 1) { super(); this.id = id; this.url = 'https://trusted.example/view'; this.session = {}; this.mainFrame = { url: this.url }; }
  getURL() { return this.url; }
  getType() { return 'window'; }
  isDestroyed() { return false; }
  executeJavaScript() { return Promise.resolve([]); }
}
function restore(p) {
  for (const [object, name, original] of [...p.originals].reverse()) object[name] = original;
  syncBuiltinESMExports();
}
describe('Windows watch proof contracts and evidence', () => {
  it('requires reviewed non-command IPC contracts, bounded args, and file canary placeholders', () => {
    assert.throws(() => validateProfile({ handlers: [{ channel: 'run-command', reviewed: true, contract: 'read-only', args: [] }] }, true));
    assert.throws(() => validateProfile({ handlers: [{ channel: 'file-read', reviewed: false, contract: 'file-read', args: ['$CANARY_PATH'] }] }, true));
    assert.throws(() => validateProfile({ handlers: [{ channel: 'file-read', reviewed: true, contract: 'file-read', args: ['C:\\customer.txt'] }] }, true));
    assert.equal(validateProfile({ handlers: [{ channel: 'file-read', reviewed: true, contract: 'file-read', args: ['$CANARY_PATH'] }] }, true).handlers.length, 1);
  });
  it('rejects ambiguous origins, credential-bearing feeds and unreviewed service routes', () => {
    assert.throws(() => validateProfile({ origins: ['https://trusted.example/path'] }));
    assert.throws(() => validateProfile({ feeds: ['https://user:password@example.com/latest.yml'] }));
    assert.throws(() => validateProfile({ services: [{ port: 80, transport: 'http', path: '/', requiresAuth: true }] }));
    assert.throws(() => validateProfile({ services: [{ reviewed: true, port: 80, transport: 'http', path: '//other.example', requiresAuth: true }] }));
  });
  it('calls app navigation/open/permission policies without navigating or requesting a camera', async () => {
    const records = [], c = new Contents();
    const p = createProofs({ shell: {} }, (kind, data) => records.push({ kind, ...data }), { enabled: true });
    try {
      p.registerContents(c); p.registerSession(c.session, 'default');
      c.on('will-navigate', (event, url) => { if (new URL(url).origin !== 'https://trusted.example') event.preventDefault(); });
      p.setOpen(c, () => ({ action: 'deny' }));
      p.setPermission(c.session, 'request', (wc, permission, cb, details) => cb(details.requestingUrl.startsWith('https://trusted.example/')));
      p.setPermission(c.session, 'check', (wc, permission, origin) => origin === 'https://trusted.example');
      await p.proveContents(c);
      assert.equal(c.url, 'https://trusted.example/view');
      for (const name of ['navigation', 'window-open', 'permission-request', 'permission-check']) assert.equal(records.find(r => r.test === name).outcome, 'blocked');
      assert.equal(records.find(r => r.test === 'permission-request').actualSender, c.url);
      assert.ok(records.every(r => r.scope === 'handler-decision'));
    } finally { c.emit('destroyed'); restore(p); }
  });
  it('records policy allowance but never upgrades synthetic inputs to foreign renderer access', async () => {
    const records = [], c = new Contents();
    const p = createProofs({ shell: {} }, (kind, data) => records.push({ kind, ...data }), { enabled: true });
    try {
      p.registerContents(c); p.registerSession(c.session, 'default');
      p.setPermission(c.session, 'request', (wc, permission, cb) => cb(true));
      await p.proveContents(c);
      const analyzed = analyzeProofs(records);
      assert.ok(analyzed.issues.every(i => i.severity === severity.INFORMATIONAL));
      assert.match(analyzed.issues.find(i => i.properties.test === 'permission-request').description, /existing renderer/);
      assert.equal(records.find(r => r.test === 'permission-check').outcome, 'not-configured');
    } finally { c.emit('destroyed'); restore(p); }
  });
  it('does not consume once listeners or claim absent handlers after a late hook', async () => {
    const records = [], c = new Contents(); let calls = 0;
    const p = createProofs({ shell: {} }, (kind, data) => records.push({ kind, ...data }), { enabled: true, late: true });
    try {
      p.registerContents(c); c.once('will-navigate', () => calls++);
      await p.proveContents(c);
      assert.equal(calls, 0); assert.equal(c.listeners('will-navigate').length, 1);
      assert.equal(records.find(r => r.test === 'handlers').outcome, 'skipped');
    } finally { c.emit('destroyed'); restore(p); }
  });
  it('blocks command execution and file writes including asynchronous descendants', async () => {
    const records = [], cp = require('node:child_process');
    const p = createProofs({ shell: {} }, (kind, data) => records.push({ kind, ...data }), { enabled: true });
    try {
      assert.throws(() => p.run('test', () => cp.execSync('echo SHOULD_NEVER_EXECUTE')), /SIDE_EFFECT_BLOCKED/);
      assert.throws(() => p.run('test', () => fs.writeFileSync(path.join(os.tmpdir(), 'eng-should-never-write'), 'x')), /SIDE_EFFECT_BLOCKED/);
      await p.run('test', () => new Promise(resolve => setTimeout(() => {
        assert.throws(() => cp.spawn(process.execPath, ['-e', 'process.exit(0)']), /SIDE_EFFECT_BLOCKED/); resolve();
      }, 10)));
      assert.equal(records.filter(r => r.test === 'side-effect').length, 3);
    } finally { restore(p); }
  });
  it('requires the unique HTTPS response, distinguishes cert failures from connection errors and aborts', async () => {
    let aborted = 0;
    const net = { request: options => {
      assert.equal(options.useSessionCookies, false); assert.equal(options.credentials, 'omit');
      const req = new EventEmitter(); req.abort = () => aborted++;
      req.end = () => queueMicrotask(() => {
        const res = new EventEmitter(); res.statusCode = 200; req.emit('response', res); res.emit('data', Buffer.from('wrong nonce')); res.emit('end');
      }); return req;
    } };
    assert.equal(await sessionRequest({ net }, {}, 'https://127.0.0.1:1/test', 'expected'), 'inconclusive');
    assert.equal(aborted, 1);
    for (const [error, expected] of [['net::ERR_CERT_AUTHORITY_INVALID', 'blocked'], ['ECONNREFUSED', 'inconclusive']]) {
      net.request = () => { const r = new EventEmitter(); r.abort = () => {}; r.end = () => queueMicrotask(() => r.emit('error', Error(error))); return r; };
      assert.equal(await sessionRequest({ net }, {}, 'https://127.0.0.1:1/test', 'expected'), expected);
    }
  });
  it('treats only exit 42 as a RunAsNode behavioral proof and clears inherited injection', async () => {
    let invocation;
    const run = (exe, args, options) => { invocation = { exe, args, options }; const child = new EventEmitter(); child.kill = () => {}; queueMicrotask(() => child.emit('exit', 42)); return child; };
    const result = await proveRunAsNode('C:\\fake.exe', { platform: 'win32', run });
    assert.equal(result.outcome, 'enabled'); assert.deepEqual(invocation.args, ['-e', 'process.exit(42)']);
    assert.equal(invocation.options.env.ELECTRON_RUN_AS_NODE, '1'); assert.equal(invocation.options.env.NODE_OPTIONS, undefined);
    const other = await proveRunAsNode('C:\\fake.exe', { platform: 'win32', run: () => { const c = new EventEmitter(); queueMicrotask(() => c.emit('exit', 1)); return c; } });
    assert.equal(other.outcome, 'inconclusive');
  });
  it('checks quoted registry placeholders and records deny ACEs without claiming effective access', () => {
    const quoted = assessProtocol({ command: '"C:\\Program Files\\App\\App.exe" -- "%1"' });
    assert.equal(quoted.argumentQuoted, true); assert.equal(quoted.executableQuoted, true); assert.equal(quoted.switchDelimiter, true);
    assert.equal(assessProtocol({ command: 'C:\\App\\App.exe %1' }).argumentQuoted, false);
    const broad = assessAcl({ entries: [
      { sid: 'S-1-5-32-545', type: 'Allow', rights: 2, propagation: 'None' },
      { sid: 'S-1-1-0', type: 'Deny', rights: 2 },
      { sid: 'S-1-5-32-545', type: 'Allow', rights: 2, propagation: 'NoPropagateInherit, InheritOnly' },
    ] });
    assert.equal(broad.length, 1); assert.equal(broad[0].denyPresent, true);
  });
  it('keeps PowerShell input out of executable code and bounds process output', async () => {
    let call;
    const run = (command, args, options) => {
      call = { command, args, options }; const c = new EventEmitter(); c.stdout = new EventEmitter(); c.stderr = new EventEmitter(); c.kill = () => {};
      queueMicrotask(() => { c.stdout.emit('data', Buffer.from('{"paths":[]}')); c.emit('exit', 0); }); return c;
    };
    const input = { paths: ["C:\\app'; Start-Process calc; '"] };
    const result = await powershell('$d | ConvertTo-Json -Compress', input, { run });
    assert.equal(result.status, 'observed'); assert.deepEqual(JSON.parse(call.options.env.ENG_WINDOWS_INPUT), input);
    assert.equal(Buffer.from(call.args.at(-1), 'base64').toString('utf16le').includes('Start-Process calc'), false);
  });
  it('reads only local observed ADS paths and separates absent stream from missing file and denial', () => {
    const stat = () => ({ isFile: () => true });
    assert.equal(readZone('C:\\saved.docx', { platform: 'win32', stat, read: () => '[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://secret.example/token' }).zone, 3);
    const fail = code => () => { throw Object.assign(Error(), { code }); };
    assert.equal(readZone('C:\\saved.docx', { platform: 'win32', stat, read: fail('ENOENT') }).status, 'absent');
    assert.equal(readZone('C:\\saved.docx', { platform: 'win32', stat: fail('ENOENT') }).status, 'file-missing');
    assert.equal(readZone('C:\\saved.docx', { platform: 'win32', stat, read: fail('EACCES') }).status, 'access-error');
    assert.equal(readZone('\\\\remote\\saved.docx', { platform: 'win32', read: () => assert.fail('UNC must not be read') }).status, 'skipped');
    assert.equal(readZone('C:\\saved.docx:evil', { platform: 'win32' }).status, 'skipped');
  });
  it('validates hash syntax, follows feed redirects, and reports every transport hop', async () => {
    const hash = Buffer.alloc(64, 1).toString('base64');
    const request = async url => url.startsWith('https:') ? { outcome: 'response', status: 302, location: 'http://feed.example/latest.yml' } :
      { outcome: 'response', status: 200, body: `version: 1.0.0\nfiles:\n  - url: app.exe\n    sha512: ${hash}\npublisherName: Example\n` };
    const result = await inspectFeed('https://feed.example/latest.yml', { request, offline: false });
    assert.equal(result.hashesPresent, true); assert.equal(result.secureTransport, false); assert.equal(result.publisherVerification, 'not verified');
    assert.deepEqual(result.transports, ['https:', 'http:']);
    const invalid = await inspectFeed('https://feed.example/latest.yml', { offline: false, request: async () => ({ outcome: 'response', status: 200, body: 'files:\n - url: app.exe\n   sha512: not-a-hash' }) });
    assert.equal(invalid.hashesPresent, false);
  });
  it('does not fetch offline feeds, unsafe redirect schemes or unobserved services', async () => {
    assert.equal((await inspectFeed('https://feed.example/latest.yml', { offline: true, request: () => assert.fail('offline') })).outcome, 'skipped');
    assert.equal((await inspectFeed('https://feed.example/latest.yml', { offline: false, request: async () => ({ outcome: 'response', status: 302, location: 'file:///C:/secret' }) })).outcome, 'blocked');
    const result = await inspectServices([{ port: 8123, transport: 'http', path: '/status', requiresAuth: true }], [], { request: () => assert.fail('unattributed port') });
    assert.equal(result[0].outcome, 'skipped');
  });
  it('checks a declared loopback route with and without Origin, without retaining response data', async () => {
    const server = http.createServer((req, res) => { res.writeHead(req.headers.origin ? 403 : 401); res.end('SENSITIVE_BODY_MUST_NOT_BE_RETAINED'); });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const port = server.address().port;
      const r = await inspectServices([{ port, transport: 'http', path: '/status', requiresAuth: true }], [{ port, address: '127.0.0.1', transport: 'tcp' }]);
      assert.deepEqual(r.map(x => x.status), [401, 403]); assert.equal(JSON.stringify(r).includes('SENSITIVE_BODY'), false);
      assert.ok(r.every(x => x.authenticated === false));
    } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  });
  it('checks a WebSocket upgrade signature and disconnects without application messages', async () => {
    const server = http.createServer(); let socket;
    server.on('upgrade', (req, client) => {
      socket = client;
      const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      client.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try { assert.equal((await fetchMetadata(`http://127.0.0.1:${server.address().port}/`, { websocket: true })).outcome, 'upgrade'); }
    finally { socket?.destroy(); await new Promise(resolve => server.close(resolve)); }
  });
  it('observes update URLs without retaining credentials or mislabelling settings as signature enforcement', () => {
    const rows = [], updater = { setFeedURL: x => x };
    observeUpdater(updater, (kind, data) => rows.push({ kind, ...data }));
    updater.setFeedURL('https://user:secret@feed.example/latest.yml?token=secret');
    assert.equal(rows[0].url, 'https://feed.example/latest.yml'); assert.equal(rows[0].exact, false);
    assert.equal(JSON.stringify(rows).includes('secret'), false);
  });
  it('keeps dev declarations out of runtime action rows but still acts on packages shipped as dev', () => {
    const rows = annotateShipment([
      { name: 'build-tool', version: '1', dev: true, kinds: ['lockfile'], advisories: [{ id: 'OSV' }] },
      { name: 'shipped-dev', version: '1', dev: true, kinds: ['lockfile', 'node_modules'], advisories: [{ id: 'OSV' }] },
    ], { packaged: true });
    const table = componentTable({ rows });
    assert.deepEqual(table.rows.map(r => r[0]), ['shipped-dev']);
    assert.equal(rows[1].dev, false); assert.equal(rows[1].shipment.status, 'present-in-package');
    assert.equal(table.catalog.find(r => r[0] === 'build-tool')[5], 'Build/supply-chain review');
    assert.match(table.catalog.find(r => r[0] === 'build-tool')[6], /not established/);
  });
  it('preserves package presence when a later scan only has development metadata', () => {
    const shipped = annotateShipment([{ name: 'x', version: '1', dev: true, kinds: ['node_modules'] }], { packaged: true });
    const dev = annotateShipment([{ name: 'x', version: '1', dev: true, kinds: ['lockfile'] }]);
    assert.equal(mergeDependencies([{ rows: shipped }, { rows: dev }]).rows[0].shipment.status, 'present-in-package');
  });
  it('flags static/runtime differences without changing static severity or asserting dead code', () => {
    const issues = [
      { id: 'NODE_INTEGRATION_JS_CHECK', file: 'main.js', severity: severity.HIGH },
      { id: 'WINDOW_SUMMARY_JS_CHECK', file: 'main.js', properties: { preload: 'bridge.js', settings: { nodeIntegration: { value: true } } } },
      { id: 'RUNTIME_WINDOW_SUMMARY', file: 'https://app.example', properties: { preload: 'bridge.js', settings: { nodeIntegration: { value: false } } } },
    ];
    reconcileRuntime(issues, {});
    assert.equal(issues[0].severity, severity.HIGH);
    assert.ok(issues.some(i => i.id === 'RUNTIME_STATIC_DISCREPANCY'));
    assert.match(issues.find(i => i.id === 'RUNTIME_STATIC_DISCREPANCY').description, /static severity is retained/);
  });
  it('does not turn TLS failures, IPC resolution or logout retention into exploitation', () => {
    const records = [
      { kind: 'proof', test: 'certificate', outcome: 'blocked' },
      { kind: 'proof', test: 'ipc', channel: 'get-version', outcome: 'resolved', scope: 'foreign-sender' },
      { kind: 'logout-snapshot', phase: 'before', t: 1, entries: [{ store: 'cookies', key: 'h', value: 'v', candidate: true }] },
      { kind: 'logout-snapshot', phase: 'after', t: 2, entries: [{ store: 'cookies', key: 'h', value: 'v', candidate: true }] },
    ];
    const result = analyzeProofs(records);
    assert.ok(result.issues.every(i => i.severity === severity.INFORMATIONAL));
    const logout = result.issues.find(i => i.id === 'RUNTIME_LOGOUT_RETENTION');
    assert.equal(logout.properties.retained.length, 1); assert.match(logout.description, /does not prove/);
  });
  it('rejects out-of-order logout evidence and excludes tool windows from app security findings', () => {
    const result = analyzeWatchLog([
      { kind: 'proof-window', id: 99 },
      { kind: 'page', id: 99, url: 'http://127.0.0.1/test', prefs: { nodeIntegration: true, sandbox: false } },
      { kind: 'logout-snapshot', phase: 'after', t: 1, entries: [] }, { kind: 'logout-snapshot', phase: 'before', t: 2, entries: [] },
    ]);
    assert.equal(result.summary.windows, 0); assert.equal(result.issues.some(i => i.id === 'RUNTIME_NODE_INTEGRATION'), false);
    assert.equal(result.issues.find(i => i.id === 'RUNTIME_LOGOUT_RETENTION').properties.complete, false);
  });
  it('links behavioral fuse evidence while keeping confirmed configuration separate from execution', () => {
    const evidence = analyzeProofs([{ kind: 'proof', test: 'run-as-node', outcome: 'enabled', scope: 'process-exit' }]).issues[0];
    const finding = { id: 'PACKAGED_FUSES', file: 'App.exe', properties: { fuse: 'RunAsNode' }, confidence: confidence.CERTAIN, severity: severity.HIGH };
    reconcileRuntime([finding, evidence], {});
    assert.equal(finding.validation.scope, 'process-exit'); assert.equal(finding.validation.status, 'confirmed');
  });
});
