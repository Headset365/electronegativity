import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { connectDebug, localDebugURL, watchDebug } from '../src/watch/debug.js';
import { analyzeWatchLog, readWatchLog } from '../src/watch/analyze.js';
const { rendererObserver } = createRequire(import.meta.url)('../src/watch/renderer.cjs');
const { runCampaign } = createRequire(import.meta.url)('../src/watch/campaign.cjs');

class Socket extends EventTarget {
  constructor() { super(); queueMicrotask(() => this.dispatchEvent(new Event('open'))); }
  send(text) { const message = JSON.parse(text); queueMicrotask(() => this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ id: message.id, result: { method: message.method } }) }))); }
  close() { this.dispatchEvent(new Event('close')); }
}
const page = { id: 'page-1', type: 'page', url: 'https://app.test/view', webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/1' };
const fetchList = items => async () => ({ ok: true, json: async () => items });

describe('Local renderer debug connection', () => {
  it('rejects remote, credential-bearing and redirected debug endpoints', async () => {
    for (const url of ['http://example.com:9222', 'http://127.0.0.1.evil.test:9222', 'http://user:secret@127.0.0.1:9222', 'http://127.0.0.1:9222?token=a'])
      assert.throws(() => localDebugURL(url));
    let options;
    const client = await connectDebug('http://127.0.0.1:9222', { Socket, fetchImpl: async (_, opts) => { options = opts; return { ok: true, json: async () => [page] }; } });
    assert.equal(options.redirect, 'error'); client.close();
  });
  it('requires one explicit renderer and rejects a main-process target', async () => {
    await assert.rejects(connectDebug('http://127.0.0.1:9222', { Socket, fetchImpl: fetchList([page, { ...page, id: 'second' }]) }), /found 2/);
    await assert.rejects(connectDebug('http://127.0.0.1:9222', { Socket, fetchImpl: fetchList([{ ...page, type: 'node' }]) }), /found 0/);
    const client = await connectDebug('http://127.0.0.1:9222', { Socket, target: page.id, fetchImpl: fetchList([page, { ...page, id: 'second' }]) });
    assert.equal(client.target.id, page.id); client.close();
  });
  it('rejects off-host and off-port advertised WebSockets', async () => {
    for (const ws of ['ws://evil.test:9222/page', 'ws://127.0.0.1:9223/page'])
      await assert.rejects(connectDebug('http://127.0.0.1:9222', { Socket, fetchImpl: fetchList([{ ...page, webSocketDebuggerUrl: ws }]) }));
  });
  it('matches protocol responses and rejects commands after disconnect', async () => {
    const client = await connectDebug('http://127.0.0.1:9222', { Socket, fetchImpl: fetchList([page]) });
    assert.deepEqual(await Promise.all([client.send('Runtime.enable'), client.send('Network.enable')]), [{ method: 'Runtime.enable' }, { method: 'Network.enable' }]);
    client.close(); await assert.rejects(client.send('Runtime.evaluate'), /closed/);
  });
  it('bounds commands that never get a response', async () => {
    class Silent extends Socket { send() {} }
    const client = await connectDebug('http://127.0.0.1:9222', { Socket: Silent, timeout: 20, fetchImpl: fetchList([page]) });
    await assert.rejects(client.send('Runtime.evaluate'), /timed out/); client.close();
  });
  it('rejects a socket that closes before opening and surfaces protocol errors', async () => {
    class EarlyClose extends EventTarget {
      constructor() { super(); queueMicrotask(() => this.dispatchEvent(new Event('close'))); }
      close() {}
    }
    await assert.rejects(connectDebug('http://127.0.0.1:9222', { Socket: EarlyClose, fetchImpl: fetchList([page]) }), /before opening/);
    class Failure extends Socket {
      send(text) { const { id } = JSON.parse(text); queueMicrotask(() => this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ id, error: { message: 'Denied' } }) }))); }
    }
    const client = await connectDebug('http://127.0.0.1:9222', { Socket: Failure, fetchImpl: fetchList([page]) });
    await assert.rejects(client.send('Runtime.evaluate'), /Denied/); client.close();
  });
  it('removes renderer listeners and restores its own sinks without undoing page changes', () => {
    const listeners = new Set();
    const listen = { addEventListener: (name, fn) => listeners.add(fn), removeEventListener: (name, fn) => listeners.delete(fn) };
    class Element { insertAdjacentHTML() {} }
    class Document { write() {} writeln() {} }
    const original = { configurable: true, set() {}, get() { return ''; } };
    Object.defineProperty(Element.prototype, 'innerHTML', original);
    Object.defineProperty(Element.prototype, 'outerHTML', original);
    let disconnected = false;
    class MutationObserver { observe() {} disconnect() { disconnected = true; } }
    const window = { ...listen }, document = { ...listen, documentElement: {}, getElementsByTagName: () => [] };
    const code = rendererObserver('ENG_DEBUG_TEST', 'observer', true);
    assert.equal(vm.runInNewContext(code, { window, document, Element, Document, MutationObserver }), 'installed');
    assert.equal(listeners.size, 3);
    assert.notEqual(Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set, original.set);
    const replacement = () => {};
    Object.defineProperty(Element.prototype, 'outerHTML', { configurable: true, set: replacement });
    window.observer.cleanup();
    assert.equal(window.observer, undefined); assert.equal(disconnected, true); assert.equal(listeners.size, 0);
    assert.equal(Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set, original.set);
    assert.equal(Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML').set, replacement);
  });
  it('stops case writes after cancellation, attempts cleanup and does not claim verified restoration', async () => {
    const controller = new AbortController(), records = [], writes = [];
    await assert.rejects(runCampaign({ profile: { fields: ['body'], cases: ['text', 'event-handler'], request: { method: 'PUT', url: 'https://app.test/save', body: '{"body":"Hello"}' } },
      marker: 'ENG_DEBUG_TEST', signal: controller.signal, write: (kind, data) => records.push({ kind, ...data }),
      fetch: async (url, options) => { writes.push(options); return { ok: true, status: 200 }; },
      fill: () => ({ body: '{"body":"probe"}', contentType: 'application/json' }), delay: async () => controller.abort() }), /cancelled/);
    assert.equal(writes.length, 2); assert.equal(writes[1].body, '{"body":"Hello"}');
    assert.ok(!records.some(r => r.kind === 'campaign-done'));
    assert.equal(records.find(r => r.kind === 'campaign-restore').verification, 'not-configured');
  });

  it('captures a real body in memory, replays approved fields and reports partial coverage', async function () {
    this.timeout(12000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-debug-test-'));
    const log = path.join(root, 'session.jsonl'), commands = path.join(root, 'commands.jsonl');
    fs.writeFileSync(log, ''); fs.writeFileSync(commands, '');
    const events = new EventEmitter(), calls = [], sends = [], marker = 'ENG_DEBUG_TEST';
    let emitTimer;
    const client = { events, target: page, close: () => events.emit('closed'), send: async (method, params = {}) => {
      calls.push({ method, params });
      if (method === 'Page.addScriptToEvaluateOnNewDocument') return { identifier: 'script-1' };
      if (method === 'Runtime.evaluate') {
        const code = params.expression;
        if (code.startsWith('({ url:')) return { result: { value: { url: page.url, csp: null } } };
        if (code.includes('await fetch(')) {
          const value = await vm.runInNewContext(code, { fetch: async (url, options) => { sends.push({ url, options }); return { ok: true, status: 200 }; } });
          return { result: { value } };
        }
        if (code.includes('.drain()')) return { result: { value: [] } };
        return { result: { value: true } };
      }
      if (method === 'Network.enable' && !emitTimer) emitTimer = setTimeout(() => {
        for (const id of [1, 2, 3]) events.emit('protocol', 'Runtime.executionContextCreated', { context: { id, auxData: { isDefault: true } } });
        events.emit('protocol', 'Runtime.executionContextDestroyed', { executionContextId: 3 });
        events.emit('protocol', 'Network.requestWillBeSent', { requestId: 'save-1', type: 'Fetch', request: { method: 'PUT', url: 'https://app.test/notes/42?token=SECRET',
          postData: '{"id":1234567890123456789,"body":"Hello","password":"private"}', headers: { Authorization: 'Bearer PRIVATE', Cookie: 'secret-cookie' } } });
        events.emit('protocol', 'Network.responseReceived', { requestId: 'save-1', type: 'Fetch', response: { status: 200 } });
      }, 20);
      return {};
    } };
    try {
      const running = watchDebug('http://127.0.0.1:9222', { duration: 5, marker, active: true, campaign: true, traffic: false, log, commands, connect: async () => client });
      for (let attempt = 0; attempt < 100 && !readWatchLog(log).some(r => r.kind === 'api'); attempt++) await new Promise(resolve => setTimeout(resolve, 10));
      const api = readWatchLog(log).find(r => r.kind === 'api'); assert.ok(api);
      assert.equal(api.fields.find(f => f.name === 'password').candidate, false);
      fs.appendFileSync(commands, JSON.stringify({ kind: 'run-campaign', replay: api.replay, profile: { route: 'PUT https://app.test/notes/{id}', fields: ['body'], view: 'captured', cases: ['text', 'event-handler'] } }) + '\n');
      await running;
      assert.equal(sends.length, 3, 'two tests and restoration');
      assert.ok(sends[0].options.body.includes('1234567890123456789'));
      assert.ok(sends[0].options.body.includes('"password":"private"'));
      assert.equal(sends[0].options.headers.Authorization, 'Bearer PRIVATE');
      assert.equal(sends[0].options.headers.Cookie, undefined);
      assert.equal(sends[2].options.body, '{"id":1234567890123456789,"body":"Hello","password":"private"}');
      assert.ok(calls.some(c => c.method === 'Page.navigate' && c.params.url === page.url));
      assert.ok(calls.some(c => c.method === 'Page.removeScriptToEvaluateOnNewDocument'));
      assert.deepEqual(calls.filter(c => c.method === 'Runtime.evaluate' && c.params.expression.includes('.cleanup()') && c.params.contextId).map(c => c.params.contextId).sort(), [1, 2], 'every live default frame context is cleaned up');
      const text = fs.readFileSync(log, 'utf8');
      assert.ok(!text.includes('PRIVATE')); assert.ok(!text.includes('SECRET')); assert.ok(!text.includes('secret-cookie'));
      const report = analyzeWatchLog(readWatchLog(log));
      assert.ok(report.issues.some(issue => issue.id === 'RUNTIME_DEBUG_COVERAGE'));
      assert.ok(!report.issues.some(issue => issue.id === 'RUNTIME_CSP'), 'initial CSP response headers are unknown');
      assert.equal(report.issues.find(issue => issue.id === 'RUNTIME_WINDOW_SUMMARY').properties.settings.contextIsolation.source, 'unavailable');
      assert.equal(report.summary.campaign.cases.length, 2);
      assert.ok(report.summary.campaign.cases.every(c => c.execution !== 'observed'), 'acceptance never establishes execution');
    } finally { clearTimeout(emitTimer); fs.rmSync(root, { recursive: true, force: true }); }
  });
});
