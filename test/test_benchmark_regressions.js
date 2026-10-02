import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { Parser } from '../src/parser/index.js';
import { Finder } from '../src/finder/index.js';
import i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { isNonAppFile } from '../src/util/file.js';

await i18n();
const { findSecrets } = createRequire(import.meta.url)('../src/traffic/secrets.cjs');
const parserModes = [[false, true], [true, true], [false, false], [true, false]];
async function scanCode(code, id, filename = 'main.js') {
  const results = [];
  for (const mode of parserModes) {
    const parser = new Parser(...mode), finder = new Finder(null, null, null);
    const [type, data, content] = parser.parse(filename, code);
    assert.ok(data, 'fixture must parse');
    const issues = await finder.find(filename, data, type, content, null, '38.0.0');
    assert.deepEqual(finder.checkErrors, []);
    results.push(issues.filter(i => i.id === id).map(i => i.severity.name));
  }
  for (const result of results) assert.deepEqual(result, results[0], 'parser disagreement');
  return results[0];
}
async function scanProject(files, checks, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-regression-'));
  const { inputSubdir = '', ...scanOptions } = options;
  try {
    for (const [name, source] of Object.entries({ 'package.json': JSON.stringify({ name: 'regression', version: '1.0.0', devDependencies: { electron: '38.0.0' } }), ...files })) {
      const file = path.join(dir, name); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, source);
    }
    const result = await run({ input: path.join(dir, inputSubdir), offline: true, isRelative: true, customScan: checks, ...scanOptions });
    assert.deepEqual(result.errors, []);
    return result.issues;
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

describe('Real-app benchmark regressions', () => {
  describe('HTML sanitizer provenance', () => {
    for (const mutation of ['DOMPurify.sanitize = x => x;', 'DOMPurify["sanitize"] = x => x;', 'const alias = DOMPurify; alias.sanitize = x => x;', 'Object.assign(DOMPurify, { sanitize: x => x });', 'Object.defineProperty(DOMPurify, "sanitize", { value: x => x });']) {
      for (const prefix of ['', 'import DOMPurify from "dompurify";', 'const DOMPurify = require("dompurify");']) {
        it(`reports sanitizer mutation: ${prefix || 'browser global'} ${mutation}`, async () => {
          assert.equal((await scanCode(`${prefix} ${mutation} el.innerHTML = DOMPurify.sanitize(input);`, 'XSS_SINK_JS_CHECK')).length, 1);
        });
      }
    }
    it('does not invalidate a sanitizer for unrelated metadata changes', async () => assert.deepEqual(await scanCode('DOMPurify.version = "test"; el.innerHTML = DOMPurify.sanitize(input);', 'XSS_SINK_JS_CHECK'), []));
    for (const [name, code] of [
      ['a no-op sanitizer', 'function sanitize(x) { return x; } el.innerHTML = sanitize(input);'],
      ['an unresolved sanitizer', 'el.innerHTML = sanitize(input);'],
      ['an unescaped variable', 'const unescapedHtml = input; el.innerHTML = unescapedHtml;'],
      ['a sanitized-looking property', 'el.innerHTML = input.escapedHtml;'],
      ['a replaced DOMPurify global', 'const DOMPurify = { sanitize: x => x }; el.innerHTML = DOMPurify.sanitize(input);'],
      ['a function that renders escaped text again', 'el.innerHTML = render(escapeHtml(input));'],
    ]) it(`reports ${name}`, async () => assert.equal((await scanCode(code, 'XSS_SINK_JS_CHECK')).length, 1));
    it('follows local sanitizer wrappers and aliases', async () => {
      assert.deepEqual(await scanCode('function clean(x) { return DOMPurify.sanitize(x); } const result = clean(input); el.innerHTML = result;', 'XSS_SINK_JS_CHECK'), []);
      for (const code of ['const DOMPurify = require("dompurify"); el.innerHTML = DOMPurify.sanitize(input);', 'const { sanitize: clean } = require("dompurify"); el.innerHTML = clean(input);'])
        assert.deepEqual(await scanCode(code, 'XSS_SINK_JS_CHECK'), []);
    });
    it('follows an imported sanitizer wrapper', async () => {
      const issues = await scanProject({ 'renderer.js': 'import { clean } from "./clean.js"; el.innerHTML = clean(input);', 'clean.js': 'import DOMPurify from "dompurify"; export const clean = x => DOMPurify.sanitize(x);' }, ['xsssinkjscheck']);
      assert.equal(issues.length, 0);
    });
    it('reports an unsafe caller of a shared HTML helper', async () => {
      const issues = await scanProject({ 'renderer.js': 'import { render } from "./render.js"; render(input); render(DOMPurify.sanitize(input));', 'render.js': 'export function render(html) { el.innerHTML = html; }' }, ['xsssinkjscheck']);
      assert.equal(issues.filter(i => i.file === 'renderer.js').length, 1);
    });
    it('recognizes a complete escaper by its implementation', async () => {
      const escaper = `const clean = str => str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));`;
      assert.deepEqual(await scanCode(`${escaper} el.innerHTML = clean(input);`, 'XSS_SINK_JS_CHECK'), []);
      assert.equal((await scanCode(`${escaper.replace("'<': '&lt;',", '')} el.innerHTML = clean(input);`, 'XSS_SINK_JS_CHECK')).length, 1);
    });
    it('does not trust sanitizer objects passed as parameters', async () => assert.equal((await scanCode('function clean(DOMPurify) { return DOMPurify.sanitize(input); } el.innerHTML = clean({ sanitize: x => x });', 'XSS_SINK_JS_CHECK')).length, 1));
    it('invalidates escaped parameter state after reassignment', async () => assert.equal((await scanCode('function render(x) { x = input; return x; } el.innerHTML = render(DOMPurify.sanitize(input));', 'XSS_SINK_JS_CHECK')).length, 1));
  });
  describe('URL guard and fixed-origin analysis', () => {
    const listener = body => `const { shell } = require('electron'); win.webContents.on('new-window', (event, url) => { ${body} });`;
    for (const [guard, expected] of [
      ['if (parsed.protocol === "https:") shell.openExternal(url);', 'LOW'],
      ['if (parsed.protocol !== "https:") shell.openExternal(url);', 'HIGH'],
      ['if (parsed.protocol === "https:") {} else shell.openExternal(url);', 'HIGH'],
      ['if (parsed.protocol !== "https:") {} else shell.openExternal(url);', 'LOW'],
      ['if (parsed.protocol !== "https:") return; shell.openExternal(url);', 'LOW'],
      ['if (parsed.protocol === "https:") return; shell.openExternal(url);', 'HIGH'],
      ['parsed.protocol === "https:" && shell.openExternal(url);', 'LOW'],
      ['parsed.protocol === "https:" || shell.openExternal(url);', 'HIGH'],
      ['if (parsed.protocol === "https:" || event.isTrusted) shell.openExternal(url);', 'HIGH'],
      ['if (parsed.protocol !== "https:" && event.isTrusted) return; shell.openExternal(url);', 'HIGH'],
      ['if (parsed.protocol === "https:") { url = event.raw; shell.openExternal(url); }', 'HIGH'],
    ]) for (const filename of ['main.js', 'main.ts']) it(`preserves URL branch meaning in ${filename}: ${guard}`, async () => {
      assert.deepEqual(await scanCode(listener(`const parsed = new URL(url); ${guard}`), 'OPEN_EXTERNAL_JS_CHECK', filename), [expected]);
    });
    for (const body of ['return true;', 'return false;', 'return value;', 'return !!value;']) it(`rejects an unproven URL validator: ${body}`, async () => {
      assert.deepEqual(await scanCode(listener(`function isSafeUrl(value) { ${body} } if (isSafeUrl(url)) shell.openExternal(url);`), 'OPEN_EXTERNAL_JS_CHECK'), ['HIGH']);
    });
    it('follows the implementation of a real URL validator', async () => assert.deepEqual(await scanCode(listener('function allowed(value) { const parsed = new URL(value); return parsed.protocol === "https:"; } if (allowed(url)) shell.openExternal(url);'), 'OPEN_EXTERNAL_JS_CHECK'), ['LOW']));
    for (const [name, code] of [
      ['unrelated URL checks', 'const other = new URL("https://example.org/"); if (other.protocol === "https:") shell.openExternal(url);'],
      ['URL parsing without an allowlist', 'const parsed = new URL(url); if (event) shell.openExternal(url);'],
      ['an unrelated event check', 'if (event.isTrusted) shell.openExternal(url);'],
      ['a shared parser applied to an unrelated URL', 'const parse = value => new URL(value); const other = parse("https://example.org/"); if (other.protocol === "https:") shell.openExternal(parse(url).href);'],
    ]) it(`keeps ${name} HIGH`, async () => assert.deepEqual(await scanCode(listener(code), 'OPEN_EXTERNAL_JS_CHECK'), ['HIGH']));
    it('recognizes the actual URL allowlist', async () => assert.deepEqual(await scanCode(listener('const parsed = new URL(url); if (parsed.protocol === "https:") shell.openExternal(url);'), 'OPEN_EXTERNAL_JS_CHECK'), ['LOW']));
    it('recognizes a destructured protocol rejection', async () => assert.deepEqual(await scanCode(listener('const { protocol } = new URL(url); if (protocol !== "https:") return; shell.openExternal(url);'), 'OPEN_EXTERNAL_JS_CHECK'), ['LOW']));
    it('does not flag fixed-origin query builders across helper calls', async () => {
      const issues = await scanProject({ 'main.js': 'import { open } from "./urls.js"; ipcMain.handle("issue", (e, title) => open(title));', 'urls.js': 'import { shell } from "electron"; function build(title) { const u = new URL("https://github.com/project/issues/new"); u.searchParams.set("title", title); return u.toString(); } export function open(title) { shell.openExternal(build(title)); }' }, ['openexternaljscheck']);
      assert.equal(issues.length, 0);
    });
    it('reports origin mutation on a fixed URL object', async () => assert.equal((await scanCode(listener('const u = new URL("https://example.org/"); u.hostname = url; shell.openExternal(u.href);'), 'OPEN_EXTERNAL_JS_CHECK')).length, 1));
    it('rejects replaced URL constructors and methods', async () => {
      for (const body of ['const URL = class { constructor() { this.href = url; } }; const u = new URL("https://example.org/"); shell.openExternal(u.href);', 'const u = new URL("https://example.org/"); u.replaceOrigin(url); shell.openExternal(u.href);'])
        assert.equal((await scanCode(listener(body), 'OPEN_EXTERNAL_JS_CHECK')).length, 1);
    });
    it('tracks URL object mutation through aliases', async () => assert.equal((await scanCode(listener('const u = new URL("https://example.org/"); const alias = u; alias.href = url; shell.openExternal(u.href);'), 'OPEN_EXTERNAL_JS_CHECK')).length, 1));
  });
  describe('Renderer-chosen modules', () => {
    for (const [setup, loader] of [
      ['const load = require;', 'load'], ['const load = require; const alias = load;', 'alias'],
      ['import { createRequire } from "node:module"; const load = createRequire(import.meta.url);', 'load'],
      ['const { createRequire: factory } = require("module"); const load = factory(import.meta.url);', 'load'],
      ['import * as Module from "node:module"; const load = Module.createRequire(import.meta.url);', 'load'],
      ['const load = require("node:module").createRequire(import.meta.url);', 'load'], ['', 'module.require'],
    ]) for (const filename of ['main.js', 'main.ts']) it(`recognizes ${loader} from ${setup || 'module'} in ${filename}`, async () => {
      const parameters = filename.endsWith('.ts') ? '(e: unknown, name: string)' : '(e, name)';
      assert.deepEqual(await scanCode(`${setup} ipcMain.handle("module", ${parameters} => ${loader}(name));`, 'DYNAMIC_MODULE_JS_CHECK', filename), ['HIGH']);
    });
    it('does not treat a shadowed require as Node module loading', async () => assert.deepEqual(await scanCode('function require(x) { return x; } ipcMain.handle("module", (e, name) => require(name));', 'DYNAMIC_MODULE_JS_CHECK'), []));
    for (const [name, setup, call] of [
      ['assigned property', 'const handlers = {}; handlers.runWidget = runWidget;', 'handlers[name](...args)'],
      ['computed property', 'const handlers = {}; handlers["runWidget"] = runWidget;', 'handlers[name](...args)'],
      ['Map constructor', 'const handlers = new Map([["runWidget", runWidget]]);', 'handlers.get(name)(...args)'],
      ['Map.set', 'const handlers = new Map(); handlers.set("runWidget", runWidget);', 'handlers.get(name)(...args)'],
    ]) it(`follows imported handlers through ${name}`, async () => {
      const issues = await scanProject({ 'main.js': `const { runWidget } = require("./widget"); ${setup} ipcMain.handle("async", (event, { name, args }) => ${call});`, 'widget.js': 'function runWidget(id) { return require(`./widget-${id}.js`); } module.exports = { runWidget };' }, ['dynamicmodulejscheck']);
      assert.equal(issues.length, 1); assert.equal(issues[0].file, 'widget.js'); assert.equal(issues[0].severity.name, 'HIGH');
    });
    it('reports direct require and dynamic import', async () => {
      for (const sink of ['require(name)', 'import(name)']) assert.deepEqual(await scanCode(`ipcMain.handle('module', (event, name) => ${sink});`, 'DYNAMIC_MODULE_JS_CHECK'), ['HIGH']);
    });
    it('follows imported helpers through an IPC dispatch table', async () => {
      const issues = await scanProject({ 'main.js': 'const { runWidget } = require("./widget"); const handlers = { runWidget }; ipcMain.handle("async", (event, { name, args }) => handlers[name](...args));', 'widget.js': 'const path = require("path"); function runWidget(id) { const file = `widget-${id}.js`; return require(path.join(__dirname, file)); } module.exports = { runWidget };' }, ['dynamicmodulejscheck']);
      assert.equal(issues.length, 1); assert.equal(issues[0].file, 'widget.js'); assert.equal(issues[0].severity.name, 'HIGH');
    });
    it('accepts a restrictive identifier rejection before constructing the path', async () => {
      assert.deepEqual(await scanCode('const pattern = /^[a-z0-9-]+$/; ipcMain.handle("module", (e, id) => { if (!pattern.test(id)) throw new Error("Invalid id"); return require(`./widget-${id}.js`); });', 'DYNAMIC_MODULE_JS_CHECK'), []);
    });
    it('does not accept a no-op path validator', async () => assert.deepEqual(await scanCode('function validatePath(id) { return id; } ipcMain.handle("module", (e, id) => require(validatePath(id)));', 'DYNAMIC_MODULE_JS_CHECK'), ['HIGH']));
    it('does not treat a regex permitting dots and slashes as containment', async () => assert.deepEqual(await scanCode('ipcMain.handle("module", (e, id) => { if (!/^[a-z./]+$/.test(id)) throw Error(); return require(`./widget-${id}.js`); });', 'DYNAMIC_MODULE_JS_CHECK'), ['HIGH']));
    it('follows a guarded path helper', async () => {
      assert.deepEqual(await scanCode('function pathFor(id) { if (!/^[a-z0-9-]+$/.test(id)) throw Error(); const file = `./widget-${id}.js`; return file; } ipcMain.handle("module", (e, id) => require(pathFor(id)));', 'DYNAMIC_MODULE_JS_CHECK'), []);
    });
    for (const [name, guard] of [
      ['a conditional guard', 'if (flag) { if (!/^[a-z]+$/.test(id)) throw Error(); }'],
      ['a partial rejection', 'if (!/^[a-z]+$/.test(id) && flag) throw Error();'],
      ['a multiline regex', 'if (!/^[a-z]+$/m.test(id)) throw Error();'],
      ['a reassigned identifier', 'if (!/^[a-z]+$/.test(id)) throw Error(); id = other;'],
    ]) it(`does not accept ${name}`, async () => assert.deepEqual(await scanCode(`ipcMain.handle("module", (e, id, other, flag) => { ${guard} return require(\`./widget-\${id}.js\`); });`, 'DYNAMIC_MODULE_JS_CHECK'), ['HIGH']));
  });
  describe('Source tooling and credential placeholders', () => {
    it('suppresses only explicit username/password templates', () => {
      for (const url of ['https://[username]:[password]@host', 'socks://username:password@some-socks-proxy.example']) assert.equal(findSecrets(url).length, 0);
      for (const url of ['https://username:RealSecret123@example.com', 'https://admin:password@production.example.org']) assert.equal(findSecrets(url).length, 1);
    });
    it('keeps build manifests, excludes source tooling, and includes shipped tooling', () => {
      assert.equal(isNonAppFile('build/vite/conf.js'), true);
      assert.equal(isNonAppFile('build/bin/build.js'), true);
      assert.equal(isNonAppFile('build/electron-builder.json'), false);
      assert.equal(isNonAppFile('build/vite/conf.js', { packaged: true }), false);
      assert.equal(isNonAppFile('dist/main.js'), false);
    });
    it('does not describe source build tooling as shipped development code', async () => {
      for (const allFiles of [false, true]) {
        const issues = await scanProject({ 'build/vite/conf.js': 'import { defineConfig } from "vite"; export default defineConfig({});', 'build/electron-builder.json': '{}' }, ['developmentcodejscheck'], { allFiles });
        assert.equal(issues.length, 0);
      }
    });
    it('continues to report development tooling in a packaged app folder', async () => {
      const issues = await scanProject({ 'resources/app/package.json': '{"name":"packaged"}', 'resources/app/build/vite/conf.js': 'import { defineConfig } from "vite"; export default defineConfig({});' }, ['developmentcodejscheck'], { allFiles: true, inputSubdir: 'resources/app' });
      assert.equal(issues.length, 1);
    });
  });
});
