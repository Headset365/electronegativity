// Regressions from the review of the client reports written for Notesnook, SiYuan, Trilium and DivorceMate: what a
// finding shows (inserted SQL values, second-order sources, code limited to one platform, library code), how it is
// rated (likelihood of certain findings, outdated components), and how it reads (key instances, lists of facts,
// references, examples, Windows paths).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { severity, confidence } from '../src/finder/attributes.js';
import { groupClientFindings, ratingOf, renderClientFindings, renderTesterNotes, outdatedRating } from '../src/report/markdown.js';
import { referenceTitle } from '../src/report/markdown_style.js';
import { libraryOfFile } from '../src/util/libraries.js';
import { platformGuard } from '../src/finder/checks/analysis.js';
import { visit } from '../src/finder/checks/helpers.js';
import { Parser } from '../src/parser/index.js';
import { ProjectIndex } from '../src/finder/project_index.js';
import run from '../src/runner.js';
import _i18n from '../src/locales/i18n.js';

await _i18n();

const ROOT = path.join(os.tmpdir(), 'client', 'resources', 'app.asar');
const issue = (id, extra = {}) => ({ id, severity: severity.MEDIUM, confidence: confidence.FIRM, file: path.join(ROOT, 'out/main.js'), location: { line: 10, column: 2 },
  sample: 'x();', description: `Observed ${id}`, shortenedURL: 'https://www.electronjs.org/docs/latest/tutorial/security', ...extra });
const render = (issues, meta = {}) => renderClientFindings(issues, { root: ROOT, app: { name: 'Client' }, ...meta });
const finding = (issues, title, meta) => render(issues, meta).find(f => f.title === title)?.content || '';

describe('Client report feedback', () => {
  let root;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-feedback-')); });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const app = (files) => {
    for (const [name, content] of Object.entries({ 'package.json': JSON.stringify({ name: 'c', main: 'out/app.js', devDependencies: { electron: '38.0.0' } }), ...files })) {
      fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      fs.writeFileSync(path.join(root, name), content);
    }
    return root;
  };
  const scan = async (files, checks) => (await run({ input: app(files), offline: true, customScan: checks })).issues;

  describe('SQL injection evidence', () => {
    const files = { 'out/db-import.js': `const electron_1 = require("electron");
let ADODB; ADODB = require('node-adodb');
const connection = ADODB.open('x');
function dbQuery(sql) { return connection.query(sql); }
electron_1.ipcMain.handle('desktop-matter-import-model', async (event, fileID) => {
  let parties = await dbQuery(\`SELECT * FROM tblParties WHERE FileID = \${fileID};\`);
  let party = parties[0];
  let infos = await dbQuery(\`SELECT * FROM tblSepAgrInfo WHERE PartyID = \${party.PartyID};\`);
  return infos;
});` };

    it('shows each inserted value as written, and tells a value read back from the database from one the page sent', async () => {
      const found = (await scan(files, ['sqlinjectionjscheck'])).filter(i => i.id === 'SQL_INJECTION_JS_CHECK').sort((a, b) => a.location.line - b.location.line);
      assert.equal(found.length, 2);
      assert.equal(found[0].properties.statement, 'SELECT * FROM tblParties WHERE FileID = ${fileID};');
      assert.equal(found[0].severity.name, 'HIGH');
      assert.equal(found[0].properties.source, 'an IPC message from a renderer');
      assert.equal(found[1].properties.statement, 'SELECT * FROM tblSepAgrInfo WHERE PartyID = ${party.PartyID};');
      assert.equal(found[1].properties.secondOrder, true);
      assert.equal(found[1].properties.chosenBy, 'an IPC message from a renderer');
      assert.equal(found[1].severity.name, 'MEDIUM');
      assert.ok(found.every(i => i.properties.driver === 'node-adodb'));
    });

    it('gives advice for a driver without parameters in place of the general advice it contradicts', async () => {
      const issues = (await scan(files, ['sqlinjectionjscheck'])).filter(i => i.id === 'SQL_INJECTION_JS_CHECK');
      const content = renderClientFindings(issues, { root, app: { name: 'Client' } }).find(f => f.title === 'SQL Injection in Local Database Queries').content;
      assert.match(content, /inserting `fileID` into its text \(`SELECT \* FROM tblParties WHERE FileID = \$\{fileID\};`\)/);
      assert.match(content, /read by an earlier query whose rows were chosen by an IPC message from a renderer \(second-order\)/);
      assert.match(content, /node-adodb library used by the application does not support query parameters/);
      assert.doesNotMatch(content, /- Pass the value as a query parameter/);
      assert.match(content, /Number\.parseInt\(fileID, 10\)/);
      assert.doesNotMatch(content, /FileID = \? ;/);
    });
  });

  describe('code limited to one operating system', () => {
    it('reads platform branches, early returns and platform-named functions', () => {
      const cases = {
        "function openInMac(f) { exec('lsof ' + f); }": 'darwin',
        "if (process.platform === 'darwin') { exec('x' + f); }": 'darwin',
        "if (process.platform === 'win32') { a(); } else { exec('x' + f); }": 'non-windows',
        "function g() { if (os.platform() !== 'linux') return; exec('x' + f); }": 'linux',
        "function getMacAddress() { exec('x' + f); }": undefined,
        "function closeAllWindows() { exec('x' + f); }": undefined,
      };
      for (const [source, expected] of Object.entries(cases)) {
        const [, ast] = new Parser(false, true).parse('x.js', source);
        let got = 'not reached';
        visit(ast.program || ast, (n, ancestors) => { if (n.type === 'CallExpression' && n.callee.name === 'exec') got = platformGuard(ancestors, n); return true; });
        assert.equal(got, expected, source);
      }
    });

    it('labels a finding in macOS-only code and asks the tester whether that build is in scope', async () => {
      const issues = await scan({ 'out/check.js': `const cp = require("node:child_process");
function byPath(p) { return process.platform === 'win32' ? openInWindows(p) : openInMac(p); }
function openInMac(filePath) { cp.exec('lsof "' + filePath + '"', () => {}); }
module.exports = { byPath };` }, ['commandinjectionjscheck']);
      const command = issues.find(i => i.id === 'COMMAND_INJECTION_JS_CHECK');
      assert.equal(command.properties.platform, 'darwin');
      const content = renderClientFindings(issues, { root, app: { name: 'Client' } }).find(f => f.title === 'Command or Code Execution from Variable Input').content;
      assert.match(content, /`out\/check\.js:3` \(macOS only\)/);
      assert.match(content, /This code runs only on macOS\./);
      const notes = renderTesterNotes(issues, { root, app: { name: 'Client' } }).find(n => n.title === 'Command or Code Execution from Variable Input').content;
      assert.match(notes, /runs only on macOS .*Confirm whether that build is in scope/);
    });
  });

  describe('third-party library code', () => {
    it('names the library a node_modules copy or bundler chunk belongs to', () => {
      const names = ['tabulator-tables', 'mermaid', 'jquery', 'leaflet', 'maplibre-gl', 'ckeditor5'];
      assert.equal(libraryOfFile('public\\src\\tabulator-CmBzg3cD.js', names), 'tabulator-tables');
      assert.equal(libraryOfFile('public/src/mermaid.core-C91UIso6.js', names), 'mermaid');
      assert.equal(libraryOfFile('public/src/jquery.module-R5Nq7kwZ.js', names), 'jquery');
      assert.equal(libraryOfFile('public/src/leaflet-maplibre-gl-DDa73Qhf.js', names), 'leaflet');
      assert.equal(libraryOfFile('node_modules/@scope/pkg/dist/x.js', names), '@scope/pkg');
      assert.equal(libraryOfFile('public/src/note_tree-BeKzNc7A.js', names), undefined);
      assert.equal(libraryOfFile('public/src/index-DFtQ-Uyx.js', names), undefined);
    });

    it('lists library instances apart from the application’s own, and rates the finding from the application’s code', () => {
      const issues = [
        issue('XSS_SINK_JS_CHECK', { severity: severity.HIGH, file: path.join(ROOT, 'public/src/mermaid.core-C91UIso6.js') }),
        issue('XSS_SINK_JS_CHECK', { file: path.join(ROOT, 'public/src/note_tree-BeKzNc7A.js') }),
      ];
      const [group] = groupClientFindings(issues, ['mermaid']);
      assert.equal(group.basis.file, issues[1].file);
      const content = finding(issues, 'Cross-Site Scripting in Content Rendering', { dependencies: { rows: [{ name: 'mermaid' }] } });
      const affected = content.slice(content.indexOf('## Affected'), content.indexOf('## Implication'));
      assert.ok(affected.indexOf('note_tree') < affected.indexOf('within bundled third-party components (`mermaid`)'));
      assert.ok(affected.indexOf('within bundled third-party components') < affected.indexOf('mermaid.core'));
    });
  });

  describe('the instances that rate a finding', () => {
    it('sorts instances by rating, then file and line, and leads with the few that carry the most risk', () => {
      const sender = (file, line) => issue('IPC_SENDER_VALIDATION_JS_CHECK', { severity: severity.LOW, file: path.join(ROOT, file), location: { line, column: 0 }, properties: { channel: `c${line}` } });
      const issues = [sender('out/z.js', 5), sender('out/a.js', 9), sender('out/a.js', 3), sender('out/m.js', 1),
        issue('IPC_HANDLER_JS_CHECK', { severity: severity.HIGH, file: path.join(ROOT, 'out/k.js'), location: { line: 4, column: 0 }, properties: { channel: 'run', issue: 'unvalidated' } })];
      const content = finding(issues, 'Insufficient Validation of Inter-Process Messages');
      const affected = content.slice(content.indexOf('## Affected'), content.indexOf('## Implication'));
      assert.match(affected, /The instance that carries the most risk in Client is:\n\n- `out\/k\.js:4`/);
      const order = ['out/k.js:4', 'out/a.js:3', 'out/a.js:9', 'out/m.js:1', 'out/z.js:5'].map(where => affected.lastIndexOf(where));
      assert.deepEqual([...order].sort((a, b) => a - b), order);
    });

    it('reports state a page sets for window loads and credentials as its own finding, and a write-then-open handler with the operating system hand-offs', () => {
      const issues = [
        issue('IPC_STATE_DESTINATION_JS_CHECK', { severity: severity.HIGH, properties: { channel: 'login-success', setter: 'setLoginModel', loads: ['out/main.window.js'], credentialed: ['out/api.js'] } }),
        issue('IPC_HANDLER_JS_CHECK', { severity: severity.HIGH, properties: { channel: 'file-open-docx', issue: 'write-then-open' } }),
        issue('IPC_SENDER_VALIDATION_JS_CHECK', { properties: { channel: 'login-success' } }),
      ];
      const titles = groupClientFindings(issues).map(g => g.definition[0]);
      assert.ok(titles.includes('Application Destinations Controlled by Web Content'));
      const destination = finding(issues, 'Application Destinations Controlled by Web Content');
      assert.match(destination, /Page decides the address application windows load/);
      assert.match(destination, /Page decides where the access token is sent/);
      assert.match(destination, /windows load that address in `out\/main\.window\.js`, and requests carrying the user’s access token are sent to it from `out\/api\.js`/);
      assert.match(finding(issues, 'Unvalidated URLs and Files Passed to the Operating System'), /File written from page input and opened by the operating system/);
    });
  });

  describe('ratings', () => {
    it('rates a certain but unconfirmed finding at most Possible, except what anyone with the package can read', () => {
      assert.equal(ratingOf(issue('NODE_INTEGRATION_JS_CHECK', { severity: severity.HIGH, confidence: confidence.CERTAIN }), 'Insufficient Renderer Process Isolation').likelihood, 'Possible');
      assert.equal(ratingOf(issue('FILE_PROTOCOL_JS_CHECK', { severity: severity.LOW, confidence: confidence.CERTAIN }), 'Insecure Handling of Deep Links and File Associations').likelihood, 'Possible');
      assert.equal(ratingOf(issue('RUNTIME_ACTIVE_SCRIPT', { properties: { execution: 'observed' } }), 'Cross-Site Scripting in Content Rendering').likelihood, 'Very Likely');
    });

    it('rates outdated components from the support status of the Electron runtime and the renderer isolation', () => {
      const eol = issue('UNSUPPORTED_VERSION_GLOBAL_CHECK', { severity: severity.HIGH, description: 'Electron version is end of life: Electron 34' });
      assert.deepEqual(outdatedRating([eol]).rating, { consequence: 'Medium', likelihood: 'Possible' });
      assert.deepEqual(outdatedRating([eol], [eol, issue('NODE_INTEGRATION_JS_CHECK', { severity: severity.HIGH })]).rating, { consequence: 'High', likelihood: 'Possible' });
      assert.deepEqual(outdatedRating([issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK')]).rating, { consequence: 'Low', likelihood: 'Possible' });
      assert.deepEqual(outdatedRating([issue('UNSUPPORTED_VERSION_GLOBAL_CHECK', { severity: severity.LOW, description: 'A newer patch is available' })]).rating, { consequence: 'N/A', likelihood: 'N/A' });
      const content = finding([eol], 'Outdated Software Components');
      assert.match(content, /Consequence: Medium\nLikelihood: Possible/);
      assert.doesNotMatch(content, /rated as Informational/);
    });
  });

  describe('wording', () => {
    it('lists three or more facts about one line instead of running them together', () => {
      const issues = ['IPC_SENDER_VALIDATION_JS_CHECK', 'IPC_HANDLER_JS_CHECK', 'IPC_CHANNEL_MAP_JS_CHECK'].map(id =>
        issue(id, { severity: severity.LOW, context: { start: 9, lines: ['a', 'ipcMain.on("run", (e, x) => run(x));', 'b'] }, location: { line: 10, column: 0 }, properties: { channel: 'run', issue: 'unvalidated' } }));
      const content = finding(issues, 'Insufficient Validation of Inter-Process Messages');
      assert.match(content, /This shows the following:\n\n {2}- The handler for the `run` channel does not validate the sender/);
      assert.match(content, /- No reviewed user interface code sends the `run` channel that the main process handles\./);
      assert.match(content, /Message handler with no identified caller/);
      assert.doesNotMatch(content, /Unused message handler exposed/);
    });

    it('names what a finding without a file covers, and the CWE a check links to', () => {
      assert.match(finding([issue('CSP_GLOBAL_CHECK', { file: 'N/A', sample: '' })], 'Missing or Insufficient Content Security Policy'), /- All application windows \(no policy in any page or response\) \(Client\) — /);
      assert.equal(referenceTitle('https://cwe.mitre.org/data/definitions/427.html'), 'CWE-427: Uncontrolled Search Path Element');
    });

    it('shows every setting that isolates a renderer in the example, and forward slashes in the steps', () => {
      const content = finding([issue('SANDBOX_JS_CHECK'), issue('NODE_INTEGRATION_JS_CHECK', { severity: severity.HIGH })], 'Insufficient Renderer Process Isolation');
      assert.match(content, /nodeIntegration: false,[\s\S]*contextIsolation: true,[\s\S]*sandbox: true,/);
      assert.match(content, /`resources\/app\.asar`/);
    });

    it('describes the application’s own loopback server apart from content loaded over the network', async () => {
      const issues = await scan({ 'out/app.js': `const { BrowserWindow } = require('electron');
const w = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });
w.loadURL('http://127.0.0.1:37840/');` }, ['httpresourcesjavascriptcheck', 'nodeintegrationjscheck', 'httpresourcesandnodeintegrationglobalcheck']);
      const http = issues.find(i => i.id === 'HTTP_RESOURCES_JS_CHECK');
      assert.equal(http.severity.name, 'LOW');
      assert.equal(http.properties.loopback, true);
      const combined = issues.find(i => i.id === 'HTTP_RESOURCES_WITH_NODE_INTEGRATION_GLOBAL_CHECK');
      assert.equal(combined.properties.loopbackOnly, true);
      assert.equal(combined.severity.name, 'LOW');
    });

    it('states which install folders other accounts can write to, relative to the installation folder, once', () => {
      const install = 'D:\\a\\_temp\\run\\extracted\\app';
      const acl = (folder) => issue('WINDOWS_INSTALL_PERMISSIONS', { severity: severity.LOW, file: 'runtime', sample: '', description: `${folder}: observed. The ACL contains write grants to broad user groups.`,
        properties: { path: folder, status: 'observed', broadWrite: [{ sid: 'S-1-5-32-545', identity: 'S-1-5-32-545' }] }, validation: { status: 'confirmed', scope: 'acl-configuration', text: `${folder}: observed.` } });
      const issues = [acl(install), acl(`${install}\\resources`)];
      const content = renderClientFindings(issues, { root: `${install}\\resources\\app.asar`, app: { name: 'Client' } })
        .find(f => f.title === 'Application Code Not Protected Against Tampering or Disclosure').content;
      assert.match(content, /Installation folder writable by other accounts/);
      assert.match(content, /During testing, the access control lists of `app` and `resources` grant write access to the Users group/);
      assert.doesNotMatch(content, /_temp|D:/);
      assert.equal(content.match(/During testing/g).length, 1);
    });
  });

  describe('minified bundles', () => {
    it('resolves a function name to the function in scope, not one of the same name in another module', () => {
      const file = path.join(root, 'main.cjs');
      // two modules of a bundle each declare their own o(); a handler's value reaches only the first
      fs.writeFileSync(file, `function a(){function o(d){return d}function s(l){return o(l)}require('electron').ipcMain.on('x',(e,v)=>s(v));}
function b(){function o(c){return require('fs').readdirSync(c)}return o('/fixed')}`);
      const index = new ProjectIndex({ list_files: [file], load_buffer: f => fs.readFileSync(f) }, new Parser(false, true), root);
      index.text = f => fs.readFileSync(f, 'utf8');
      index.summarize(file);
      const reached = new Set(index.seeds.keys());
      let frontier = [...reached];
      while (frontier.length) frontier = frontier.flatMap(k => [...(index.edges.get(k) || [])].filter(t => !reached.has(t) && reached.add(t)));
      const lines = [...reached].map(k => k.split(':').slice(-2).join(':'));
      assert.ok(lines.includes('1:13'), `the o() of the first module is reached: ${lines}`);
      assert.ok(!lines.some(k => k.startsWith('2:')), 'nothing in the second module is reached');
    });
  });
});
