import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { spawnSync } from 'node:child_process';
import { watchDebugApp } from '../src/watch/debug_launch.js';
import { observeSession } from '../src/watch/session.js';

describe('Managed renderer debug launch', () => {
  let root, target, log, child, client, kills, closes, launches;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-debug-launch-'));
    target = path.join(root, 'app.exe'); log = path.join(root, 'session.jsonl');
    fs.writeFileSync(target, '');
    kills = 0; closes = 0; launches = [];
    child = new EventEmitter();
    child.kill = () => { kills++; queueMicrotask(() => child.emit('exit', 0)); return true; };
    client = { close: () => { closes++; } };
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const options = () => ({ log, exitGraceMs: 0, selectPort: async () => 49152,
    spawnApp: (...args) => { launches.push(args); return child; }, connect: async () => client,
    observe: async () => log });

  it('allocates a port, launches once, reuses the connection and closes only the owned app', async () => {
    const notes = [];
    const result = await watchDebugApp(target, { ...options(), args: ['--label=Case Sensitive Value'], target: 'https://app.test/', duration: 60,
      marker: 'ENG_DEBUG_AUTO', active: true, campaign: true, onNote: note => notes.push(note),
      connect: async (endpoint, opts) => { assert.equal(endpoint, 'http://127.0.0.1:49152'); assert.equal(opts.target, 'https://app.test/'); return client; },
      observe: async (endpoint, opts) => {
        assert.equal(endpoint, 'http://127.0.0.1:49152'); assert.equal(await opts.connect(), client);
        assert.equal(opts.duration, 60); assert.equal(opts.marker, 'ENG_DEBUG_AUTO'); assert.equal(opts.campaign, true);
        return log;
      } });
    assert.equal(result, log); assert.equal(launches.length, 1);
    assert.equal(launches[0][0], target);
    assert.deepEqual(launches[0][1], ['--label=Case Sensitive Value', '--remote-debugging-port=49152']);
    assert.equal(kills, 1); assert.ok(closes >= 1);
    assert.equal(notes[0].mainProcess, false);
    assert.ok(fs.readFileSync(log, 'utf8').includes('"closed":true'));
  });
  it('runs a source project with its Electron binary and preserves the project argument', async () => {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"test-project"}');
    const electron = path.join(root, 'node_modules', 'electron'); fs.mkdirSync(electron, { recursive: true });
    fs.writeFileSync(path.join(electron, 'package.json'), '{"main":"index.cjs"}');
    fs.writeFileSync(path.join(electron, 'index.cjs'), `module.exports = ${JSON.stringify(process.execPath)};`);
    await watchDebugApp(root, options());
    assert.equal(launches[0][0], process.execPath); assert.equal(launches[0][1][0], root);
  });
  it('lets the app finish its quit handlers after the renderer disconnects', async () => {
    let flushed = false;
    await watchDebugApp(target, { ...options(), exitGraceMs: 100,
      observe: async () => {
        setTimeout(() => { flushed = true; child.emit('exit', 0); }, 20);
        return log;
      } });
    assert.equal(flushed, true); assert.equal(kills, 0);
    assert.ok(fs.readFileSync(log, 'utf8').includes('"closed":true'));
  });
  it('bounds the grace period and closes an app that stays open', async () => {
    await watchDebugApp(target, { ...options(), exitGraceMs: 10 });
    assert.equal(kills, 1);
  });
  it('waits for the renderer endpoint instead of requiring a manually started app', async () => {
    let attempts = 0;
    await watchDebugApp(target, { ...options(), connect: async () => {
      if (++attempts === 1) throw Object.assign(new Error('No page yet'), { code: 'ENG_DEBUG_NO_TARGET' });
      return client;
    } });
    assert.equal(attempts, 2); assert.equal(kills, 1);
  });
  it('fails clearly and cleans up when several renderers need a selector', async () => {
    let attempts = 0;
    await assert.rejects(watchDebugApp(target, { ...options(), connect: async () => {
      attempts++; throw Object.assign(new Error('Use --debug-target'), { code: 'ENG_DEBUG_AMBIGUOUS_TARGET' });
    } }), /debug-target/);
    assert.equal(attempts, 1); assert.equal(kills, 1);
  });
  it('bounds startup when the app ignores debug options', async () => {
    await assert.rejects(watchDebugApp(target, { ...options(), startupTimeout: 1, connect: async () => { throw new Error('No endpoint'); } }), /ignore debug launch options/);
    assert.equal(kills, 1);
  });
  it('bounds a stalled connection and closes it if it completes after cancellation', async () => {
    let complete;
    await assert.rejects(watchDebugApp(target, { ...options(), startupTimeout: 10, connect: () => new Promise(resolve => { complete = resolve; }) }), /timed out/);
    assert.equal(kills, 1);
    complete(client); await new Promise(resolve => setImmediate(resolve));
    assert.equal(closes, 1);
  });
  it('stops startup promptly if the app exits or cannot spawn', async () => {
    for (const error of [undefined, new Error('Permission denied')]) {
      child = new EventEmitter(); child.kill = () => { kills++; return true; };
      await assert.rejects(watchDebugApp(target, { ...options(), spawnApp: () => {
        queueMicrotask(() => error ? child.emit('error', error) : child.emit('exit', 0)); return child;
      }, connect: async () => new Promise(() => {}) }), error ? /Permission denied/ : /close other copies/);
    }
    assert.equal(kills, 0);
  });
  it('closes the connection and owned app after observation fails', async () => {
    await assert.rejects(watchDebugApp(target, { ...options(), observe: async () => { throw new Error('Observer failed'); } }), /Observer failed/);
    assert.equal(kills, 1); assert.ok(closes >= 1);
  });
  it('rejects conflicting launch flags before starting any process', async () => {
    for (const args of [['--remote-debugging-port=9222'], ['--remote-debugging-address', '0.0.0.0'], ['--remote-debugging-pipe']])
      await assert.rejects(watchDebugApp(target, { ...options(), args }), /manages its own/);
    assert.equal(launches.length, 0);
    await assert.rejects(observeSession({ watch: root, debugLaunch: true, debugUrl: 'http://127.0.0.1:9222' }), /cannot be combined/);
  });
  it('rejects invalid CLI combinations before scanning or launching', function () {
    this.timeout(20000);
    const cli = path.join(import.meta.dirname, '..', 'src', 'index.js');
    for (const args of [['--debug-launch'], ['--watch', root, '--debug-launch', '--debug-url', 'http://127.0.0.1:9222'],
      ['--watch', root, '--debug-launch', '--watch-log', log], ['--watch', root, '--debug-target', 'page-1']]) {
      const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
      assert.notEqual(result.status, 0); assert.match(result.stderr, /debug-launch|debug-url/);
    }
  });
});
