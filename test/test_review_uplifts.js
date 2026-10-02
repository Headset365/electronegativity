import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import run from '../src/runner.js';
import { Finder, GlobalChecks } from '../src/finder/index.js';
import { prepareScanFolder, MANIFEST } from '../src/remote/sources.js';
import { recoverableSources } from '../src/production/source_map_sources.js';
import { Parser } from '../src/parser/index.js';
import { combineRuns } from '../src/report/markdown.js';
import { severity } from '../src/finder/attributes.js';
import _i18n from '../src/locales/i18n.js';

await _i18n();
const CLI = path.resolve('src/index.js');
const RUNNER = pathToFileURL(path.resolve('src/runner.js')).href;
const PACKAGE = JSON.stringify({ name: 'review-uplifts', main: 'main.js', devDependencies: { electron: '38.2.0' } });
const UNSAFE_WINDOW = `const {BrowserWindow} = require('electron'); new BrowserWindow({webPreferences:{nodeIntegration:true}});`;

describe('Code review regression coverage', () => {
  let root;
  let app;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-review-uplifts-'));
    app = path.join(root, 'app');
    fs.mkdirSync(app);
    fs.writeFileSync(path.join(app, 'package.json'), PACKAGE);
    fs.writeFileSync(path.join(app, 'main.js'), UNSAFE_WINDOW);
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const scan = (input, extra = {}) => run({ input, offline: true, ...extra });

  it('applies the HIGH gate to a guided static scan and respects its baseline', () => {
    const output = path.join(root, 'guided');
    const baseline = path.join(root, 'baseline.json');
    const args = [CLI, '--app', app, '--sessions', '0', '--out', output, '-o', 'report.json',
      '--offline', '--no-report-dir', '-l', 'NodeIntegrationJSCheck', '--fail-on', 'high'];
    const failed = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 15000 });
    assert.equal(failed.status, 1, failed.stderr);
    const report = JSON.parse(fs.readFileSync(path.join(output, 'static-report.json'), 'utf8'));
    assert.equal(report.issues.filter(issue => issue.severity === 'HIGH').length, 1);
    const accepted = spawnSync(process.execPath, [...args, '--write-baseline', baseline], { encoding: 'utf8', timeout: 15000 });
    assert.equal(accepted.status, 1, accepted.stderr);
    const passed = spawnSync(process.execPath, [...args, '--baseline', baseline], { encoding: 'utf8', timeout: 15000 });
    assert.equal(passed.status, 0, passed.stderr);
  });

  it('retains a HIGH finding that appears only in a later guided session', () => {
    const low = { id: 'LOW_CHECK', file: 'main.js', severity: severity.LOW };
    const high = { id: 'RUNTIME_HIGH_CHECK', file: 'runtime', severity: severity.HIGH };
    const combined = combineRuns([{ reported: [low], suppressed: [] }, { reported: [high], suppressed: [] },
      { reported: [high], suppressed: [] }]);
    assert.deepEqual(combined.reported.filter(issue => issue.severity.value >= severity.HIGH.value), [high]);
  });

  function capture(bundles) {
    const dir = path.join(root, 'capture');
    fs.mkdirSync(dir);
    const entries = [];
    bundles.forEach(({ code = UNSAFE_WINDOW, map }, i) => {
      const url = `https://review.test/chunk-${i}.js`;
      fs.writeFileSync(path.join(dir, `${i}.js`), code);
      fs.writeFileSync(path.join(dir, `${i}.map`), JSON.stringify(map));
      entries.push({ kind: 'script', url, file: `${i}.js` }, { kind: 'map', url: `${url}.map`, of: url, file: `${i}.map` });
    });
    fs.writeFileSync(path.join(dir, MANIFEST), entries.map(entry => JSON.stringify(entry)).join('\n'));
    return prepareScanFolder(dir);
  }
  const sourceMap = (sources, sourcesContent) => ({ version: 3, mappings: '', names: [], sources, sourcesContent });

  for (const [name, map] of [
    ['partial', sourceMap(['safe.js', 'unsafe.js'], ['const safe=1;', null])],
    ['unparseable', sourceMap(['unsafe.js'], ['const broken = ;'])],
    ['duplicate', sourceMap(['same.js', 'same.js'], ['const safe=1;', UNSAFE_WINDOW])],
    ['unsupported', sourceMap(['component.vue'], ['<template/>'])],
    ['incomplete index', { version: 3, sections: [{ offset: { line: 0, column: 0 }, map: sourceMap(['safe.js'], ['const safe=1;']) },
      { offset: { line: 1, column: 0 }, url: 'missing.map' }] }],
  ]) {
    it(`retains the bundle and its finding for a ${name} source map`, async () => {
      const prepared = capture([{ map }]);
      assert.equal(prepared.counts.bundlesReplaced, 0);
      assert.equal(prepared.counts.scripts, 1);
      assert.equal(prepared.errors.length, 1);
      const result = await scan(prepared.dir, { extraInputs: [prepared], customScan: ['NodeIntegrationJSCheck'] });
      assert.equal(result.issues.filter(issue => issue.id === 'NODE_INTEGRATION_JS_CHECK').length, 1);
      assert.equal(result.errors.filter(error => /bundle retained/.test(error.message)).length, 1);
    });
  }

  it('keeps originals with the same name from different remote bundles', async () => {
    const prepared = capture([
      { code: 'const safe=1;', map: sourceMap(['src/index.js'], ['const safe=1;']) },
      { map: sourceMap(['src/index.js'], [UNSAFE_WINDOW]) },
    ]);
    assert.equal(prepared.counts.bundlesReplaced, 2);
    assert.equal(prepared.labels.size, 2);
    const result = await scan(prepared.dir, { extraInputs: [prepared], customScan: ['NodeIntegrationJSCheck'] });
    assert.equal(result.issues.filter(issue => issue.id === 'NODE_INTEGRATION_JS_CHECK').length, 1);
    assert.match(result.issues[0].file, /chunk-1\.js \(source: src\/index\.js\)/);
  });

  it('uses the shared source budget before replacing a bundle', () => {
    const parser = new Parser(false, true);
    const result = recoverableSources(JSON.stringify(sourceMap(['main.js'], ['const x=1;'])), parser, 32 * 1024 * 1024);
    assert.match(result.error, /size limit/);
  });

  it('does not mutate a frozen API configuration across sequential scans', async () => {
    const options = Object.freeze({ input: app, offline: true, severitySet: 'high', confidenceSet: 'firm',
      customScan: Object.freeze(['NodeIntegrationJSCheck']), excludeFromScan: Object.freeze([]) });
    const first = await run(options);
    const second = await run(options);
    assert.deepEqual(second.issues.map(issue => issue.id), first.issues.map(issue => issue.id));
    assert.equal(options.severitySet, 'high');
    assert.equal(options.confidenceSet, 'firm');
    assert.deepEqual(options.customScan, ['NodeIntegrationJSCheck']);
  });

  for (const extra of [{ customScan: ['NoSuchCheck'] }, { excludeFromScan: ['NoSuchCheck'] }, { electronUpgrade: 'bad' },
    { customScan: ['CSPGlobalCheck', 'NoSuchGlobalCheck'] }, { excludeFromScan: ['CSPGlobalCheck', 'NoSuchGlobalCheck'] }]) {
    it(`rejects invalid API configuration without terminating its caller: ${JSON.stringify(extra)}`, () => {
      // A child isolates the regression: process.exit() would otherwise kill the test runner.
      const program = `import run from ${JSON.stringify(RUNNER)};
try { await run(${JSON.stringify({ input: app, offline: true, ...extra })}); process.exitCode=2; }
catch(error) { console.log('caught-validation-error'); }
console.log('caller-alive');`;
      const result = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', timeout: 15000 });
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /caught-validation-error\ncaller-alive/);
    });
  }

  it('allows valid exclusions outside a custom selection', () => {
    assert.doesNotThrow(() => new Finder(['nodeintegrationjscheck'], ['sandboxjscheck']));
    assert.doesNotThrow(() => new GlobalChecks(['cspglobalcheck'], ['sandboxglobalcheck']));
  });

  it('only lowers file-access severity for controls applied before the relevant operation', async () => {
    fs.writeFileSync(path.join(app, 'main.js'), `const {ipcMain}=require('electron'); const fs=require('fs'); const path=require('path');
ipcMain.handle('none',(e,p)=>fs.readFileSync(p));
ipcMain.handle('ignored',(e,p)=>{path.basename(p); return fs.readFileSync(p);});
ipcMain.handle('late',(e,p)=>{const value=fs.readFileSync(p); if(!p.startsWith('/docs/')) return; return value;});
ipcMain.handle('nonrejecting',(e,p)=>{if(!p.startsWith('/docs/')) console.log('outside'); return fs.readFileSync(p);});
ipcMain.handle('nested',(e,p)=>{function check(){if(!p.startsWith('/docs/')) return;} return fs.readFileSync(p);});
ipcMain.handle('other',(e,p,q)=>{if(!q.startsWith('/docs/')) return; return fs.readFileSync(p);});
ipcMain.handle('applied',(e,p)=>fs.readFileSync(path.join('/docs',path.basename(p))));
ipcMain.handle('rejecting',(e,p)=>{if(!p.startsWith('/docs/')) throw new Error(); return fs.readFileSync(p);});
ipcMain.handle('copy',(e,p,q)=>fs.copyFileSync(path.join('/docs',path.basename(p)),q));
ipcMain.handle('same-copy',(e,p)=>fs.copyFileSync(path.join('/docs',path.basename(p)),p));
ipcMain.handle('late-basename',(e,p)=>{fs.readFileSync(p); p=path.basename(p);});`);
    const result = await scan(app, { customScan: ['IpcFileAccessJSCheck', 'IpcHandlerJSCheck'] });
    assert.deepEqual(result.errors, []);
    for (const channel of ['none', 'ignored', 'late', 'nonrejecting', 'nested', 'other', 'applied', 'rejecting', 'copy', 'same-copy', 'late-basename']) {
      const handler = result.issues.find(issue => issue.id === 'IPC_HANDLER_JS_CHECK' && issue.properties.channel === channel);
      const file = result.issues.find(issue => issue.id === 'IPC_FILE_ACCESS_JS_CHECK' && issue.location.line === handler.location.line);
      const protectedPath = ['applied', 'rejecting'].includes(channel);
      assert.equal(file.severity.name, protectedPath ? 'LOW' : 'HIGH', channel);
      assert.equal(file.properties.pathControl, protectedPath ? 'recognized-unverified' : 'not-recognized', channel);
      assert.equal(handler.properties.context.effects[0].pathControl, file.properties.pathControl, channel);
    }
  });

  it('detects malicious packages consistently without output and across report formats', async () => {
    fs.writeFileSync(path.join(app, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
      '': { dependencies: { 'event-stream': '3.3.6' } }, 'node_modules/event-stream': { version: '3.3.6' },
    } }));
    let expected;
    for (const format of [undefined, 'json', 'csv', 'sarif', 'html']) {
      const result = await scan(app, { customScan: ['DependencyInventoryLockCheck'],
        ...(format ? { output: path.join(root, `report.${format}`), isSarif: format === 'sarif' } : {}) });
      const ids = result.issues.map(issue => issue.id).sort();
      assert.ok(ids.includes('MALICIOUS_DEPENDENCY'), String(format));
      if (expected) assert.deepEqual(ids, expected, String(format));
      expected = ids;
    }
    const disabled = await scan(app, { customScan: ['DependencyInventoryLockCheck'], dependencies: false });
    assert.equal(disabled.dependencies, undefined);
    assert.ok(!disabled.issues.some(issue => issue.id === 'MALICIOUS_DEPENDENCY'));
  });

  it('recognizes dynamic execution inputs and preserves constant/callback exclusions in JS and TS', async () => {
    const code = `function parameter(code) { eval(code); }
function property() { eval(window.location.hash); }
function constructor(code) { return new Function(code); }
function concat(code) { eval('prefix' + code); }
function alias(code) { const execute = globalThis.eval; execute(code); }
function timer(code) { window.setTimeout(code, 10); }
function functionBody(code) { return Function('name', code); }
eval('constant'); new Function('return 1;');
function callback() {} setTimeout(callback, 10);
const callbackAlias = callback; setInterval(callbackAlias, 10);
setTimeout(() => {}, 10); request.setTimeout(delay, callback);
const constantCode = 'constant'; eval(constantCode);
globalThis.eval?.(window.location.hash);`;
    for (const extension of ['js', 'ts']) {
      fs.rmSync(path.join(app, 'main.js'), { force: true });
      const filename = path.join(app, `main.${extension}`);
      fs.writeFileSync(filename, code);
      const result = await scan(filename, { customScan: ['DangerousFunctionsJSCheck'] });
      assert.deepEqual(result.errors, []);
      assert.deepEqual(result.issues.map(issue => issue.location.line), [1, 2, 3, 4, 5, 6, 7, 13]);
    }
  });
});
