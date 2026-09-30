// Evaluate the benchmark's evidence, including small semantic controls.
// Usage: node scripts/evaluate-known-vulnerabilities.mjs SOURCE_DIR OUTPUT_DIR [--strict]
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import run from '../src/runner.js';
import { benchmarkFailures } from './benchmark-policy.mjs';

const sources = path.resolve(process.argv[2] || '../electron-benchmark/sources');
const output = path.resolve(process.argv[3] || '../electron-benchmark/results');
const read = (name, mode = 'default') => JSON.parse(fs.readFileSync(path.join(output, `${name}-${mode}.json`), 'utf8'));
const at = (report, id, file, line) => report.issues.filter(i => i.id === id && i.file === file && (line === undefined || i.line === line));
const summary = { pairs: [], falsePositives: [], controls: [], semanticEvidence: [], limitations: [
  'Offline static scans; dependency CVEs and native runtime vulnerabilities are not evaluated.',
  'Fixed means fixed for the selected advisory; it does not mean the entire app is secure.',
  'No whole-app precision/recall estimate: unreviewed findings are not labeled.',
  'Apps were not installed or launched. Electerm function behavior uses a VM with mocked modules.',
] };
for (const mode of ['default', 'all-files']) {
  const jv = read('jitsi-vulnerable', mode), jf = read('jitsi-fixed', mode);
  const ev = read('element-vulnerable', mode), ef = read('element-fixed', mode);
  const mv = read('marktext-vulnerable', mode), mf = read('marktext-fixed', mode);
  const wv = read('electerm-vulnerable', mode), wf = read('electerm-fixed', mode);
  for (const report of [jv, jf, ev, ef, mv, mf, wv, wf]) assert.equal(report.errors.length, 0, 'scan coverage errors');
  summary.pairs.push({ app: 'Jitsi', advisory: 'CVE-2020-25019', mode,
    result: at(jv, 'OPEN_EXTERNAL_JS_CHECK', 'main.js', 165).some(i => i.severity === 'HIGH') &&
      at(jf, 'OPEN_EXTERNAL_JS_CHECK', 'app/features/utils/openExternalLink.js', 23).every(i => i.severity === 'LOW') &&
      at(jf, 'OPEN_EXTERNAL_JS_CHECK', 'app/features/utils/openExternalLink.js', 23).length > 0 ? 'pass' : 'gap',
    scope: 'Unsafe navigation-to-openExternal flow; other issues in the bundled advisory are not scored.' });
  summary.pairs.push({ app: 'Element', advisory: 'CVE-2022-23597', mode,
    result: at(ev, 'UNTRUSTED_LOAD_URL_JS_CHECK', 'src/protocol.ts', 32).some(i => i.severity === 'HIGH') &&
      !at(ef, 'UNTRUSTED_LOAD_URL_JS_CHECK', 'src/protocol.ts').some(i => i.severity === 'HIGH') ? 'partial' : 'gap',
    scope: 'Detects deep-link mitigation and Electron 13.5.1 -> 13.5.2; does not detect the V8 use-after-free offline.' });
  const vulnerableLanguageCaller = at(mv, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/renderBlock/renderLeafBlock.js', 251);
  const fixedLanguageCaller = at(mf, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/renderBlock/renderLeafBlock.js', 252);
  const vulnerableSharedSink = at(mv, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/snabbdom.js', 17);
  const fixedSharedSink = at(mf, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/snabbdom.js', 28);
  summary.pairs.push({ app: 'MarkText', advisory: 'CVE-2021-29996', mode,
    result: vulnerableLanguageCaller.length && !fixedLanguageCaller.length ? 'pass' :
      vulnerableSharedSink.length && fixedSharedSink.length ? 'partial' : 'gap',
    vulnerableCallerFindings: at(mv, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/renderBlock/renderLeafBlock.js', 251).length,
    vulnerableSharedSink: at(mv, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/snabbdom.js', 17).length,
    fixedSharedSink: at(mf, 'XSS_SINK_JS_CHECK', 'src/muya/lib/parser/render/snabbdom.js', 28).length,
    scope: 'Scores the languageInput caller of htmlToVNode; shared helper findings alone are only partial evidence.' });
  summary.pairs.push({ app: 'Electerm', advisory: 'CVE-2026-43940', mode,
    result: at(wv, 'DYNAMIC_MODULE_JS_CHECK', 'src/app/widgets/load-widget.js', 68).some(i => i.severity === 'HIGH') &&
      !at(wf, 'DYNAMIC_MODULE_JS_CHECK', 'src/app/widgets/load-widget.js').length ? 'pass' : 'gap',
    vulnerableRootFindings: at(wv, 'DYNAMIC_MODULE_JS_CHECK', 'src/app/widgets/load-widget.js').length,
    fixedRootFindings: at(wf, 'DYNAMIC_MODULE_JS_CHECK', 'src/app/widgets/load-widget.js').length,
    scope: 'IPC dispatch into runWidget, dynamic require path traversal, and the patched identifier rejection.' });
  summary.falsePositives.push({ app: 'Electerm', mode, kind: 'Credentials are UI examples',
    findings: wf.issues.filter(i => i.id === 'HARDCODED_SECRET' && ((i.file === 'src/client/components/tabs/quick-connect.jsx' && i.line === 77) ||
      (i.file === 'src/client/components/setting-panel/setting-common.jsx' && [325, 326, 327].includes(i.line)))) });
  summary.falsePositives.push({ app: 'Electerm', mode, kind: 'Source build tooling described as shipped runtime code',
    findings: wf.issues.filter(i => i.id === 'DEVELOPMENT_CODE_JS_CHECK' && ['build/vite/conf.js', 'build/vite/dev-server.js'].includes(i.file)) });
  summary.falsePositives.push({ app: 'MarkText', mode, kind: 'Fixed GitHub origin with encoded query parameters rated HIGH',
    findings: at(mf, 'OPEN_EXTERNAL_JS_CHECK', 'src/main/utils/createGitHubIssue.js', 16) });
}

// Actual Electerm code with mocked modules, for POSIX and Windows path semantics.
for (const platform of [{ name: 'posix', paths: path.posix, dir: '/benchmark/widgets' }, { name: 'windows', paths: path.win32, dir: 'C:\\benchmark\\widgets' }]) {
  for (const name of ['electerm-vulnerable', 'electerm-fixed']) {
    const requested = [];
    const context = vm.createContext({ module: { exports: {} }, __dirname: platform.dir, console: { log() {}, error() {} },
      process: { on() {} }, require(id) {
        if (id === 'fs') return {};
        if (id === 'path') return platform.paths;
        requested.push(id);
        return { widgetInfo: { type: 'function' }, widgetRun: () => 'mocked' };
      } });
    vm.runInContext(fs.readFileSync(path.join(sources, name, 'src/app/widgets/load-widget.js'), 'utf8'), context, { timeout: 1000 });
    const ids = ['a/../../probe', '../probe', 'a\\..\\..\\probe', '/tmp/probe', '\\\\server\\share', '%2e%2e%2fprobe', 'widget.js', 'valid-id-123'];
    for (const id of ids) {
      requested.length = 0;
      let error;
      try { vm.runInContext(`module.exports.runWidget(${JSON.stringify(id)}, {})`, context, { timeout: 1000 }); } catch (e) { error = e.message; }
      if (name.endsWith('vulnerable')) {
        assert.equal(requested.length, 1);
        if (id === 'a/../../probe') assert.deepEqual(requested, [platform.paths.join(platform.dir, '..', 'probe.js')]);
      } else if (id === 'valid-id-123') assert.deepEqual(requested, [platform.paths.join(platform.dir, 'widget-valid-id-123.js')]);
      else { assert.equal(requested.length, 0); assert.match(error, /Invalid widget ID/); }
      summary.semanticEvidence.push({ app: name, platform: platform.name, id, requested: [...requested], error });
    }
  }
}

// Execute only MarkText's small URL builder with shell.openExternal replaced by a recorder.
const opened = [];
const urlContext = vm.createContext({ URL, GITHUB_REPO_URL: 'https://github.com/marktext/marktext', shell: { openExternal(url) { opened.push(url); } } });
const urlBuilder = fs.readFileSync(path.join(sources, 'marktext-fixed/src/main/utils/createGitHubIssue.js'), 'utf8')
  .replace(/^import .*$/gm, '').replace(/export const /g, 'const ');
vm.runInContext(urlBuilder, urlContext, { timeout: 1000 });
vm.runInContext('createAndOpenGitHubIssueUrl("file:///benchmark/probe", "https://other.example/")', urlContext, { timeout: 1000 });
assert.equal(opened.length, 1);
assert.equal(new URL(opened[0]).origin, 'https://github.com');
assert.equal(new URL(opened[0]).pathname, '/marktext/marktext/issues/new');
summary.semanticEvidence.push({ app: 'marktext-fixed', purpose: 'Fixed-origin URL builder', opened });

const fixtures = [
  { name: 'raw-html', check: 'xsssinkjscheck', expected: 'finding', code: 'window.addEventListener("message", event => { document.body.innerHTML = event.data; });' },
  { name: 'noop-sanitize', check: 'xsssinkjscheck', expected: 'finding', code: 'function sanitize(x) { return x; } window.addEventListener("message", event => { document.body.innerHTML = sanitize(event.data); });' },
  { name: 'unescaped-name', check: 'xsssinkjscheck', expected: 'finding', code: 'window.addEventListener("message", event => { const unescapedHtml = event.data; document.body.innerHTML = unescapedHtml; });' },
  { name: 'dompurify-control', check: 'xsssinkjscheck', expected: 'none', code: 'import DOMPurify from "dompurify"; window.addEventListener("message", event => { document.body.innerHTML = DOMPurify.sanitize(event.data); });' },
  { name: 'raw-openexternal', check: 'openexternaljscheck', expected: 'HIGH', code: 'import { shell } from "electron"; win.webContents.on("new-window", (event, url) => { shell.openExternal(url); });' },
  { name: 'unrelated-validation', check: 'openexternaljscheck', expected: 'HIGH', code: 'import { shell } from "electron"; win.webContents.on("new-window", (event, url) => { const unrelated = new URL("https://example.org/"); if (unrelated.protocol === "https:") shell.openExternal(url); });' },
  { name: 'require-alias', check: 'dynamicmodulejscheck', expected: 'HIGH', code: 'const load = require; ipcMain.handle("module", (e, name) => load(name));' },
  { name: 'create-require', check: 'dynamicmodulejscheck', expected: 'HIGH', code: 'import { createRequire } from "node:module"; const load = createRequire(import.meta.url); ipcMain.handle("module", (e, name) => load(name));' },
  { name: 'overridden-sanitizer', check: 'xsssinkjscheck', expected: 'finding', code: 'import DOMPurify from "dompurify"; DOMPurify.sanitize = x => x; el.innerHTML = DOMPurify.sanitize(input);' },
  { name: 'noop-url-validator', check: 'openexternaljscheck', expected: 'HIGH', code: 'import { shell } from "electron"; function isSafeUrl() { return true; } win.webContents.on("new-window", (event, url) => { if (isSafeUrl(url)) shell.openExternal(url); });' },
  { name: 'rejected-url-branch', check: 'openexternaljscheck', expected: 'HIGH', code: 'import { shell } from "electron"; win.webContents.on("new-window", (event, url) => { if (new URL(url).protocol !== "https:") shell.openExternal(url); });' },
];
for (const fixture of fixtures) {
  const dir = path.join(output, 'controls', fixture.name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'main.js'), fixture.code + '\n');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: fixture.name, version: '1.0.0', devDependencies: { electron: '38.0.0' } }));
  const scan = await run({ input: dir, customScan: [fixture.check], offline: true, isRelative: true });
  assert.equal(scan.errors.length, 0);
  const findings = scan.issues.map(i => ({ id: i.id, severity: i.severity.name, confidence: i.confidence.name, description: i.description }));
  const pass = fixture.expected === 'finding' ? findings.length > 0 : fixture.expected === 'none' ? findings.length === 0 : findings.some(i => i.severity === fixture.expected);
  summary.controls.push({ name: fixture.name, expected: fixture.expected, result: pass ? 'pass' : 'gap', findings });
}
const failures = benchmarkFailures(summary, { fullCoverage: process.argv.includes('--strict') });
summary.gate = { passed: failures.length === 0, failures, fullCoverage: process.argv.includes('--strict') };
fs.writeFileSync(path.join(output, 'evaluation.json'), JSON.stringify(summary, null, 2));
console.log(JSON.stringify({ pairs: summary.pairs, controls: summary.controls, semanticEvidence: summary.semanticEvidence, gate: summary.gate }, null, 2));
if ((process.argv.includes('--ci') || process.argv.includes('--strict')) && failures.length) process.exitCode = 1;
