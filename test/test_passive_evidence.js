import assert from 'node:assert/strict';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { reconcileRuntime } from '../src/watch/reconcile.js';
import { probeAuthRoutes, navigationTestsFromFindings } from '../src/watch/network-proofs.js';
import { analyzeProofs } from '../src/watch/proof-analysis.js';
import { severity, confidence } from '../src/finder/attributes.js';
const require = createRequire(import.meta.url);
const { createPassiveEvidence, rpcMetadata, messageHosts } = require('../src/watch/passive-evidence.cjs');
const { createProofs } = require('../src/watch/proofs.cjs');
const marker = 'ENG_HARMLESS_MARKER';
const observer = () => {
  const rows = []; const passive = createPassiveEvidence({ write: (kind, data) => rows.push({ kind, ...data }), marker });
  return { rows, passive };
};
const finding = (id, properties, file = '/app/main.js', line = 5) => ({ id, properties, file, location: { line, column: 0 },
  description: id, severity: severity.HIGH, confidence: confidence.FIRM });

describe('Passive evidence and bounded uplift proofs', () => {
  for (const driver of ['node-adodb', 'better-sqlite3', 'sqlite3']) it(`${driver}: observes statement interpolation, preserves bound values and driver results`, async () => {
    const { rows, passive } = observer(); const calls = []; const result = { row: 7 };
    class Database {
      exec(text, ...args) { calls.push([this, text, ...args]); return result; }
      run(text, ...args) { calls.push([this, text, ...args]); return this; }
      prepare(text) { return { all(...args) { calls.push([this, text, ...args]); return result; } }; }
    }
    const module = driver === 'node-adodb' ? { open() { return { query: async (...args) => { calls.push(args); return result; } }; } } :
      driver === 'sqlite3' ? { Database } : Database;
    assert.equal(passive.observeModule(driver, module), module); passive.observeModule(driver, module);
    const db = driver === 'node-adodb' ? module.open('tool-only') : new Database();
    if (driver === 'node-adodb') {
      assert.equal(await db.query('SELECT ? AS value', marker), result);
      assert.equal(rows.length, 0);
      assert.equal(await db.query(`SELECT '${marker}' AS value`), result);
    } else {
      const prepared = db.prepare(`SELECT '${marker}' AS value`);
      assert.equal(rows.length, 0, 'prepare alone is not a query execution attempt');
      assert.equal(db.prepare('SELECT ? AS value').all(marker), result);
      assert.equal(rows.length, 0, 'bound marker must not be interpolation evidence');
      assert.equal(prepared.all(), result);
    }
    assert.equal(rows.length, 1, 'module reload must not duplicate wrapping');
    assert.equal(rows[0].driver, driver); assert.equal(rows[0].markerInSql, true);
    assert.equal(JSON.stringify(rows).includes(marker), false, 'no query text or parameter values in evidence');
    assert.equal(calls.length, 2); assert.ok(rows[0].frames.length);
  });
  it('preserves sqlite3 callback this, positional arguments and synchronous failures', () => {
    const { rows, passive } = observer(); const error = new Error('driver failure');
    class Database { run(text, values, cb) { cb.call(this, null, values); return this; } exec() { throw error; } }
    passive.observeModule('sqlite3', { Database }); const db = new Database(); const values = [marker]; let called;
    assert.equal(db.run('SELECT ?', values, function (err, received) { called = this; assert.equal(err, null); assert.equal(received, values); }), db);
    assert.equal(called, db); assert.equal(rows.length, 0);
    assert.throws(() => db.exec(`SELECT '${marker}'`), e => e === error);
    assert.equal(rows[0].scope, 'database-api-call');
  });
  it('decodes only documented RPC request envelopes and distinguishes marker input from procedure metadata', () => {
    const request = { method: 'request', operation: { path: 'files.saveFile', type: 'mutation', input: { name: marker } } };
    assert.deepEqual(rpcMetadata('electron-trpc', [request], marker), { procedure: 'files.saveFile', rpcType: 'mutation', inputMarker: true });
    assert.deepEqual(rpcMetadata('other', [request], marker), {});
    assert.deepEqual(rpcMetadata('electron-trpc', [{ path: 'saveFile' }], marker), {});
    assert.deepEqual(rpcMetadata('electron-trpc', [{ method: 'subscription.stop', id: 1 }], marker), {});
    assert.equal(rpcMetadata('electron-trpc', [{ ...request, operation: { ...request.operation, input: 'safe' } }], marker).inputMarker, false);
    const rows = ['files.saveFile', 'files.deleteFile'].map(procedure => ({ kind: 'ipc', channel: 'electron-trpc', procedure, inputMarker: true, marker: true }));
    assert.equal(analyzeWatchLog(rows).issues.filter(i => i.id === 'RUNTIME_MARKER_IPC').length, 2);
  });
  it('observes endpoint host correlation without reading getters, credentials or unrelated destinations', () => {
    const value = { endpoint: 'https://user:secret@APP.example/login?token=secret', cycle: null }; value.cycle = value;
    Object.defineProperty(value, 'getter', { get() { throw Error('must not read'); } });
    assert.deepEqual(messageHosts([value]), ['app.example']);
    const { rows, passive } = observer(); passive.observeIpc('login-success', [value], 'https://local.example');
    passive.navigation('https://unrelated.example', 1); assert.equal(rows.length, 1);
    passive.navigation('https://app.example/home', 1); assert.equal(rows.at(-1).correlationOnly, true);
    assert.equal(JSON.stringify(rows).includes('secret'), false);
  });
  it('links successful sync, callback, promise and stream writes to file URLs with async IPC context', async () => {
    const { rows, passive } = observer(); const file = path.join(os.tmpdir(), 'eng-file-chain.txt');
    const value = Promise.resolve(); const fake = {
      writeFileSync() { return 17; }, writeFile(f, data, cb) { queueMicrotask(() => cb(null)); },
      appendFile(f, data, cb) { cb(Error('denied')); }, promises: { writeFile() { return value; } },
      createWriteStream() { return new EventEmitter(); }
    };
    passive.instrumentFiles(fake);
    await passive.runIpc('electron-trpc', [{ method: 'request', operation: { path: 'files.saveFile', type: 'mutation' } }], 'https://ui.example', async () => {
      assert.equal(fake.writeFileSync(file, 'data'), 17);
      passive.openFile(pathToFileURL(file).href, 'openPath');
      assert.equal(rows.at(-1).sameIpcCall, true); assert.equal(rows.at(-1).procedure, 'files.saveFile');
      await new Promise(resolve => fake.writeFile(file, 'data', resolve));
      const count = rows.length; fake.appendFile('/unwritten', 'data', () => {}); passive.openFile('/unwritten', 'openPath'); assert.equal(rows.length, count);
      assert.equal(fake.promises.writeFile(file, 'data'), value); await value;
      const stream = fake.createWriteStream(file); stream.emit('finish');
      passive.openFile(file, 'showItemInFolder'); assert.equal(rows.at(-1).writeMethod, 'createWriteStream');
    });
    assert.equal(rows.filter(r => r.kind === 'file-write').length, 4);
  });
  it('keeps relative cwd-derived candidates distinct from actual Windows process images', () => {
    const { passive } = observer(); const working = path.resolve('empty-folder');
    const candidate = passive.processPath('spawn', './helper.exe', [[], { cwd: working }]);
    assert.equal(candidate.resolvedPath, path.join(working, 'helper.exe')); assert.equal(candidate.resolution, 'cwd-derived');
    assert.deepEqual(passive.processPath('exec', './helper.exe --args', []), {});
    assert.deepEqual(passive.processPath('spawn', 'helper.exe', []), {});
    const result = analyzeWatchLog([{ kind: 'process', ...candidate, pid: 21 }, { kind: 'windows-process-image', pid: 21, image: 'C:\\App\\helper.exe' }]);
    assert.equal(result.issues.find(i => i.id === 'RUNTIME_RELATIVE_EXECUTABLE_PATH').properties.resolution, 'windows-process-image');
  });
  it('links HTML template lines and SQL calls precisely, without ambiguous RPC leaf matches', () => {
    const html = finding('HTML_TEMPLATE_JS_CHECK', {}), sql = finding('SQL_INJECTION_JS_CHECK', {});
    const sink = finding('RUNTIME_MARKER_SINK', { sink: 'innerHTML', frames: [{ url: html.file, line: 5 }] });
    const query = finding('RUNTIME_SQL_MARKER', { frames: [{ url: sql.file, line: 5 }] });
    const procedures = [finding('IPC_RPC_PROCEDURE_JS_CHECK', { procedure: 'saveFile', router: 'a' }), finding('IPC_RPC_PROCEDURE_JS_CHECK', { procedure: 'saveFile', router: 'b' })];
    const rpc = finding('RUNTIME_MARKER_IPC', { channel: 'electron-trpc', procedure: 'a.saveFile', inputMarker: true });
    reconcileRuntime([html, sql, sink, query, ...procedures, rpc], {});
    assert.equal(html.validation.status, 'observed'); assert.equal(sql.validation.status, 'observed');
    assert.ok(procedures.every(i => !i.validation));
    procedures[0].properties.procedurePath = 'a.saveFile'; reconcileRuntime([...procedures, rpc], {});
    assert.ok(procedures[0].validation); assert.equal(procedures[1].validation, undefined);
  });
  it('performs handler-only host variants and reports preload options without calling createWindow', async () => {
    const navigationTests = navigationTestsFromFindings([finding('LIMIT_NAVIGATION_JS_CHECK', { hosts: ['trusted.example', 'evil.example/path'] })]);
    assert.equal(navigationTests.length, 2); const rows = [], contents = new EventEmitter();
    Object.assign(contents, { id: 1, session: {}, getURL: () => 'https://trusted.example/', isDestroyed: () => false });
    const proofs = createProofs({ shell: {} }, (kind, data) => rows.push({ kind, ...data }), { enabled: true, profile: { navigationTests } });
    try {
      proofs.registerContents(contents); contents.on('will-navigate', (event, url) => { if (new URL(url).hostname !== 'trusted.example') event.preventDefault(); });
      proofs.setOpen(contents, () => ({ action: 'allow', overrideBrowserWindowOptions: { webPreferences: { preload: '/app/preload.cjs' } }, createWindow() { throw Error('must not create'); } }));
      await proofs.proveContents(contents);
      assert.equal(rows.find(r => r.test === 'navigation' && r.variant === 'allowed-host-http').outcome, 'allowed');
      assert.equal(rows.find(r => r.test === 'navigation' && r.variant === 'allowed-host-subdomain').outcome, 'blocked');
      assert.ok(rows.filter(r => r.test === 'window-open').every(r => r.childCreated === false && r.preloadObservation === 'handler-options-only' && r.preload === 'preload.cjs'));
    } finally { contents.emit('destroyed'); for (const [obj, name, original] of [...proofs.originals].reverse()) obj[name] = original; syncBuiltinESMExports(); }
  });
  it('requests only declared read-only local routes, sends no credentials and never confirms bypass from 200 or follows redirects', async () => {
    const requests = []; const server = http.createServer((req, res) => {
      requests.push(req); if (req.url === '/api/status') { res.writeHead(302, { Location: 'https://must-not-follow.example/' }); } else res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('public SPA');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const source = finding('AUTH_MODE_BYPASS_JS_CHECK', { readOnlyRoutes: ['/api/clipper/handshake', '/api/status', '//foreign/handshake', '/delete', '/api/handshake?write=1'] });
      const listener = { transport: 'tcp', address: '127.0.0.1', port: server.address().port };
      const results = await probeAuthRoutes(listener, [source]); assert.equal(results.length, 2);
      assert.deepEqual(results.map(r => r.status), [200, 302]); assert.ok(results.every(r => !r.authBypassConfirmed && !r.redirectsFollowed));
      assert.ok(requests.every(r => r.method === 'GET' && !r.headers.cookie && !r.headers.authorization));
      assert.ok(analyzeProofs(results.map(r => ({ kind: 'proof', ...r }))).issues.every(i => i.validation.status !== 'confirmed'));
      assert.deepEqual(await probeAuthRoutes({ ...listener, toolInspector: true }, [source]), []);
    } finally { await new Promise(resolve => server.close(resolve)); }
  });
});
