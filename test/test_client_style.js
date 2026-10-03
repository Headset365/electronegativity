import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import YAML from 'yaml';
import { severity, confidence } from '../src/finder/attributes.js';
import { renderClientFindings, renderTesterNotes, groupClientFindings } from '../src/report/markdown.js';
import { VARIATIONS } from '../src/report/markdown_variations.js';
import { CLIENT_LABELS } from '../src/report/markdown_client_copy.js';
import { TITLES, LEADS, NOTES } from '../src/report/markdown_style.js';
import { secretsNote, RELEASE_GUIDE_FILE } from '../src/report/markdown_release.js';
import { getContext } from '../src/util/file.js';
import { redactCodeLine } from '../src/secrets/scan.js';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';

chaiShould();
await _i18n();

// the app lives in the temporary folder, as a downloaded server script does, so a leaked path would show
const ROOT = path.join(os.tmpdir(), 'client', 'resources', 'app.asar');
const INSTALL = path.dirname(path.dirname(ROOT));
const at = (file) => path.join(ROOT, file);
let line = 0;
const issue = (id, extra = {}) => ({ id, severity: severity.MEDIUM, confidence: confidence.FIRM, file: at('src/main.js'), location: { line: 12, column: 3 },
  sample: `win.setting${++line}(value);`, description: `An issue was observed in step ${line}`, shortenedURL: 'https://www.electronjs.org/docs/latest/tutorial/security', ...extra });

// at least one finding of every check the client findings name, with the descriptions the checks write
const ISSUES = [
  issue('NODE_INTEGRATION_JS_CHECK', { severity: severity.HIGH }),
  issue('HTTP_RESOURCES_WITH_NODE_INTEGRATION_GLOBAL_CHECK', { file: 'N/A', sample: '' }),
  issue('CONTEXT_ISOLATION_JS_CHECK'), issue('SANDBOX_JS_CHECK'), issue('PRELOAD_JS_CHECK'), issue('REMOTE_MODULE_JS_CHECK'), issue('AFFINITY_JS_CHECK'),
  issue('RUNTIME_NODE_INTEGRATION', { file: 'https://app.test/', sample: '', description: 'A page ran with Node.js integration: https://app.test/ (nodeIntegration on, not sandboxed)' }),
  issue('RUNTIME_CAMPAIGN_FS_READ', { file: 'https://app.test/view', sample: '', description: 'Injected script read a tool-owned file canary. Access to other files or accounts was not tested.',
    properties: { screenshot: path.join(INSTALL, 'shots', 'read.png') } }),
  issue('WEB_SECURITY_JS_CHECK'), issue('INSECURE_CONTENT_JS_CHECK'), issue('EXPERIMENTAL_FEATURES_JS_CHECK'), issue('BLINK_FEATURES_JS_CHECK'),
  issue('CUSTOM_ARGUMENTS_JS_CHECK', { description: 'Security-relevant command-line switch (--disable-site-isolation-trials)' }),
  issue('CUSTOM_ARGUMENTS_JS_CHECK', { location: { line: 6 }, description: 'Security-relevant command-line switch (--ignore-certificate-errors)' }),
  issue('SECURITY_WARNINGS_DISABLED_JS_CHECK'), issue('SECUREKEYBOARDENTRY_JS_CHECK'),
  issue('CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', { description: 'contextBridge exposure: exposes ipcRenderer' }), issue('WINDOW_SESSION_JS_CHECK'),
  issue('IPC_SENDER_VALIDATION_JS_CHECK', { properties: { channel: 'run' } }),
  issue('IPC_HANDLER_JS_CHECK', { description: "IPC handler: 'run' uses processes with arguments from the page (command)", properties: { channel: 'run' } }),
  issue('IPC_RPC_PROCEDURE_JS_CHECK', { description: "Sensitive IPC procedure exposed to the renderer: the query 'osRouter.deleteFile' deletes files (rm) with input from the page; any page that reaches the IPC bridge can call it",
    properties: { procedure: 'deleteFile', router: 'osRouter', kind: 'query', capabilities: ['deletes files'], calls: ['rm'], takesInput: true } }),
  issue('AUTH_MODE_BYPASS_JS_CHECK', { description: 'Authentication is turned off in one mode of the application: auth.checkEtapiToken is skipped in one mode, for /api/clipper/notes',
    properties: { auth: 'auth.checkEtapiToken', routes: ['/api/clipper/notes'] } }),
  issue('RUNTIME_LOCAL_SERVICE', { severity: severity.HIGH, file: 'runtime', sample: '', description: 'An app process serves HTTP on port 6806 (127.0.0.1), answering an unauthenticated GET / with HTTP 200. It allows cross-origin reads from https://… origins (Access-Control-Allow-Origin: *).',
    properties: { port: 6806, address: '127.0.0.1', origins: [{ origin: 'https://eng-proof.invalid', allowOrigin: '*' }] } }),
  issue('NODE_TLS_REJECT_UNAUTHORIZED_SCRIPT', { file: path.join(INSTALL, 'app-no-cert-check.bat'), description: 'The launcher script app-no-cert-check.bat sets NODE_TLS_REJECT_UNAUTHORIZED=0', properties: { script: 'app-no-cert-check.bat' } }),
  issue('SQL_INJECTION_JS_CHECK', { description: 'SQL statement built from values instead of parameters: SELECT * FROM tblRecords WHERE RecordID = ? ; (values come from an IPC message from a renderer)',
    properties: { statement: 'SELECT * FROM tblRecords WHERE RecordID = ?', source: 'an IPC message from a renderer' } }),
  issue('RELATIVE_EXECUTABLE_PATH_JS_CHECK', { description: "A program or script is named by a path relative to the working directory: PATH is set to './resources/adodb.js'", properties: { path: './resources/adodb.js', property: 'PATH' } }),
  issue('IPC_STATE_DESTINATION_JS_CHECK', { severity: severity.HIGH, description: "A page decides where the application loads windows or sends its credentials: the 'session-ready' handler stores what the page sends",
    properties: { channel: 'session-ready', credentialed: ['backend/api.js'], loads: ['main/main.window.js'] } }),
  issue('IPC_FILE_ACCESS_JS_CHECK'), issue('IPC_CHANNEL_MAP_JS_CHECK', { properties: { channel: 'legacy' } }),
  issue('RUNTIME_MARKER_IPC', { file: 'runtime', sample: '', description: "Seen at runtime: marker data reached 'run' (sent from https://app.test/). The handler's sender and value checks remain unverified.", properties: { channel: 'run' } }),
  issue('OPEN_EXTERNAL_JS_CHECK', { description: 'shell.openExternal: the value comes from an IPC message from a renderer and is not validated' }),
  issue('OPEN_PATH_JS_CHECK'), issue('SHOWITEMINFOLDER_JS_CHECK'), issue('WRITE_SHORTCUT_JS_CHECK'), issue('DOWNLOAD_JS_CHECK'),
  issue('RUNTIME_OPEN_EXTERNAL', { file: `file:///${INSTALL.replace(/\\/g, '/').replace(/^\//, '')}/x.exe`, sample: '',
    description: `shell.openExternal was called with a non-web URL: file:///${INSTALL.replace(/\\/g, '/').replace(/^\//, '')}/x.exe; only http(s) and mailto links should reach it` }),
  issue('COMMAND_INJECTION_JS_CHECK', { description: 'Command injection: exec receives data from an IPC message' }), issue('DANGEROUS_FUNCTIONS_JS_CHECK'), issue('DYNAMIC_MODULE_JS_CHECK'),
  issue('RUNTIME_MARKER_COMMAND', { file: 'runtime', sample: '', description: 'Marker data reached a command invocation (cmd.exe, via spawn). Command injection and argument control remain unverified' }),
  issue('WORD_LAUNCH_JS_CHECK', { severity: severity.INFORMATIONAL }),
  issue('FILE_HANDLER_JS_CHECK'), issue('PROTOCOL_HANDLER_JS_CHECK'), issue('PROTOCOL_PRIVILEGES_JS_CHECK'), issue('INSTALLER_FILE_HANDLER'), issue('FILE_PROTOCOL_JS_CHECK'),
  issue('LIMIT_NAVIGATION_GLOBAL_CHECK', { file: 'N/A', sample: '', description: 'Missing will-navigate handler' }), issue('UNTRUSTED_LOAD_URL_JS_CHECK'),
  issue('WINDOW_OPEN_HANDLER_JS_CHECK', { description: 'setWindowOpenHandler: every URL is allowed' }), issue('AUXCLICK_JS_CHECK'), issue('ALLOWPOPUPS_HTML_CHECK', { file: at('index.html') }),
  issue('WEBVIEW_TAG_JS_CHECK'), issue('IFRAME_SANDBOX_HTML_CHECK', { file: at('index.html') }),
  issue('RUNTIME_MARKER_NAVIGATION', { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, file: 'https://example.invalid/ENG', sample: '',
    description: 'A link from content (carrying the planted marker) tried to navigate an app window, and the app blocked it', properties: { blocked: true } }),
  issue('PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK', { file: 'N/A', sample: '', description: 'Missing permission request handler' }),
  issue('RUNTIME_PERMISSION_CHECK', { file: 'https://app.test/', sample: '', description: 'A permission check for media was granted to https://app.test/' }),
  issue('XSS_SINK_JS_CHECK', { description: 'HTML sink: innerHTML with a variable', validation: { status: 'observed', scope: 'data-flow', text: 'Observed at runtime: marker markup reached innerHTML from this line (https://app.test/app.js:12:3). Script execution and exploitability remain untested.' } }),
  issue('XSS_SINK_JS_CHECK', { file: at('src/other.js'), description: 'HTML sink: innerHTML with a variable' }),
  issue('HTML_TEMPLATE_JS_CHECK', { description: 'HTML built from a template literal with unescaped values (values inserted without escaping: data.title (element text))', properties: { values: ['data.title (element text)'] } }),
  issue('RUNTIME_IFRAME', { severity: severity.HIGH, file: 'https://app.test/', sample: '', description: "A frame in the page's own origin (srcdoc) was shown without a sandbox at https://app.test/. The window has Node.js integration without context isolation, so script in the frame can reach Node.js through parent.require()",
    properties: { content: 'srcdoc', sameOrigin: true, sandbox: null, scripts: [], nodeIntegration: true } }),
  issue('RENDERER_INPUT_JS_CHECK', { description: 'External paste input: input reaches html; bounded analysis complete. Recognized guards require validation.', properties: { event: 'paste' } }),
  issue('RICH_TEXT_EDITOR_JS_CHECK'), issue('SANITIZER_CONFIG_JS_CHECK'), issue('ANGULAR_SCE_DISABLED_JS_CHECK'),
  issue('RUNTIME_MARKER', { file: 'https://app.test/view', sample: '', description: 'Planted marker appeared as HTML at https://app.test/view. This establishes rendering of markup, not script execution or access across accounts', properties: { live: true } }),
  issue('RUNTIME_CAMPAIGN_SCRIPT', { file: 'https://app.test/view', sample: '', description: 'Injected script executed in https://app.test/view', properties: { execution: 'observed' },
    validation: { status: 'confirmed', scope: 'execution', text: 'The payload ran' } }),
  issue('CSP_GLOBAL_CHECK', { file: 'N/A', sample: '', description: 'No CSP has been detected in the target application' }),
  issue('CSP_DIRECTIVES_HTML_CHECK', { file: at('index.html'), description: "One or more CSP directives detected are vulnerable (script-src 'unsafe-inline')" }),
  issue('RUNTIME_CAMPAIGN_EVAL', { file: 'https://app.test/view', sample: '', description: 'Injected script could call eval' }),
  issue('DOCUMENT_PIPELINE_JS_CHECK', { description: 'Document pipeline: mammoth converts .docx to HTML' }),
  issue('FUSES_GLOBAL_CHECK', { file: at('package.json'), sample: '', description: 'No Electron Fuses configuration found' }),
  issue('PACKAGED_FUSES', { file: path.join(INSTALL, 'Client.exe'), sample: '', properties: { fuse: 'RunAsNode', value: true } }),
  issue('ASAR_INTEGRITY', { file: path.join(INSTALL, 'Client.exe'), sample: '' }), issue('SOURCE_MAP_SHIPPED', { severity: severity.INFORMATIONAL, file: at('app.js.map'), sample: '' }),
  issue('CODE_SIGNING', { severity: severity.LOW, file: path.join(INSTALL, 'Client.exe'), sample: '', properties: { status: 'NotSigned' } }),
  issue('BINARY_HARDENING', { severity: severity.LOW, file: path.join(INSTALL, 'Client.exe'), sample: '', description: 'Exploit mitigations missing (CFG)' }),
  issue('UPDATE_SECURITY_JS_CHECK', { description: 'Update feed over http' }), issue('UPDATE_SECURITY_JS_CHECK', { location: { line: 40 }, description: 'Update signature verification disabled' }),
  issue('DEVTOOLS_JS_CHECK', { description: 'DevTools always opened' }), issue('DEVELOPMENT_CODE_JS_CHECK'), issue('DEBUG_LOGGING_JS_CHECK'),
  issue('RUNTIME_SECRET_IN_CONSOLE', { file: 'https://app.test/', sample: '', description: 'A bearer token was written to the console' }),
  issue('HARDCODED_SECRET_JS_CHECK', { properties: { kind: 'Stripe secret key' } }), issue('HARDCODED_SECRET_JS_CHECK', { location: { line: 30 }, properties: { kind: 'Google API key' } }),
  issue('STORAGE_SECRET_AT_REST', { file: path.join(os.homedir(), 'AppData', 'Roaming', 'Client', 'Local Storage') }),
  issue('STORAGE_CACHED_RESPONSES', { severity: severity.INFORMATIONAL, file: path.join(os.homedir(), 'AppData', 'Roaming', 'Client', 'Cache'), sample: '' }),
  issue('ELECTRON_STORE_ENCRYPTION_JS_CHECK'), issue('SECRET_FILE_WRITE_JS_CHECK'),
  issue('CERTIFICATE_PINNING_GLOBAL_CHECK', { severity: severity.INFORMATIONAL, file: 'N/A', sample: '' }),
  issue('HTTP_RESOURCES_JS_CHECK', { description: 'HTTP resource (http://cdn.test/app.js)' }), issue('CERTIFICATE_VERIFY_PROC_JS_CHECK', { description: 'setCertificateVerifyProc: every certificate is accepted' }),
  issue('CERTIFICATE_ERROR_EVENT_JS_CHECK'), issue('COOKIE_FLAGS_JS_CHECK'),
  issue('NODE_TLS_REJECT_UNAUTHORIZED_JSON_CHECK', { file: at('package.json'), description: 'NODE_TLS_REJECT_UNAUTHORIZED=0 in npm script "start"' }),
  issue('TRAFFIC_CLEARTEXT_HTTP', { file: 'http://api.test/login', sample: '', description: 'A request was sent over unencrypted HTTP to api.test', properties: { host: 'api.test' } }),
  issue('TRAFFIC_SECRET_IN_URL', { file: 'https://api.test/x?token=a', sample: '', description: 'A secret-like value was sent in a URL to api.test' }),
  issue('TRAFFIC_WS_SECRET', { file: 'wss://ws.test/', sample: '' }), issue('TRAFFIC_AUTH_TO_THIRD_PARTY', { file: 'https://other.test/', sample: '' }),
  issue('UNSUPPORTED_VERSION_GLOBAL_CHECK', { file: at('package.json') }), issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', { file: at('package.json') }),
  issue('MALICIOUS_DEPENDENCY', { severity: severity.HIGH, file: at('package-lock.json'), properties: { package: 'evil', version: '1.0.0' } }),
  issue('EXOTIC_NEW_CHECK', { severity: severity.LOW }),
  { ...issue('DEVTOOLS_JS_CHECK', { location: { line: 99 } }), suppression: { reason: 'Only in the internal build', owner: 'Client security' } },
];

const META = { root: ROOT, app: { name: 'Client' }, dir: path.join(INSTALL, 'reports'), reportRoot: INSTALL };
// the client's reading text: no code, no code spans and no reference titles (a CWE's own title keeps its spelling)
const prose = content => content.split('## References')[0].replace(/^---[\s\S]*?\n---\n/, '').replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '');

describe('Client findings in house style', () => {
  const findings = renderClientFindings(ISSUES, META);

  it('writes every named finding, each with a lead, a note and a new-style title', () => {
    const titles = findings.map(f => f.title);
    for (const title of Object.values(TITLES)) titles.should.include(title, title);
    for (const { title, content } of findings) {
      if (title === 'Outdated Software Components') continue;
      LEADS.should.have.property(title);
      NOTES.should.have.property(title);
      content.should.include(LEADS[title].replace('{app}', 'Client'));
      content.should.include(`*Note:* `);
    }
    // every scenario has a client label
    for (const entries of Object.values(VARIATIONS)) for (const [label] of entries) CLIENT_LABELS.should.have.property(label);
  });

  for (const check of [
    ['names no check of the tool', /_CHECK\b|\bRUNTIME_[A-Z]|\bTRAFFIC_[A-Z]|\bEXOTIC_NEW_CHECK\b/],
    ['never speaks of the scan or the scanner', /\bthe scan\b|\bscanner\b|\bthe tool\b/i],
    ['shows no placeholder location', /`runtime`|Application-wide|\bN\/A\b(?!\n)/],
  ]) it(check[0], () => {
    for (const { title, content } of findings) {
      const body = content.replace(/^---[\s\S]*?\n---\n/, '');
      body.should.not.match(check[1], title);
    }
  });

  it('shows no absolute path: the app, the install, home and temporary folders', () => {
    const forms = folder => [folder, folder.replace(/\\/g, '/')];
    for (const { title, content } of findings) {
      for (const folder of [...forms(INSTALL), ...forms(os.homedir()), ...forms(os.tmpdir())]) content.should.not.include(folder, title);
      content.should.not.match(/file:\/\/\//, title);
    }
  });

  it('shows each code block once, and one note per finding', () => {
    for (const { title, content } of findings) {
      const blocks = [...content.matchAll(/```\w*\n([\s\S]*?)```/g)].map(m => m[1].replace(/^\s+/gm, '').trim());
      new Set(blocks).size.should.equal(blocks.length, title);
      if (title !== 'Outdated Software Components') (content.match(/\*Note:\*/g) || []).length.should.equal(1, title);
    }
  });

  it('is written in Australian English, the tester notes too', () => {
    const american = /\b\w*(sanitiz|organiz|behavior|authoriz|analyz|randomiz|recogniz|minimiz|prioritiz|utiliz|customiz|centraliz|characteriz|color|honor|favor|center|defense|catalog\b)\w*/i;
    for (const { title, content } of findings) prose(content).should.not.match(american, title);
    // the checks' own descriptions (\"no rejecting input guard was recognized\") are respelt; code and constants are not
    const notes = renderTesterNotes([issue('IPC_HANDLER_JS_CHECK', { description: "IPC handler: 'run' uses processes; no rejecting input guard was recognized; NODE_TLS_REJECT_UNAUTHORIZED, ngSanitize" })], META)[0].content;
    notes.should.include('was recognised;').and.include('NODE_TLS_REJECT_UNAUTHORIZED, ngSanitize');
    for (const { title, content } of renderTesterNotes(ISSUES, META)) content.replace(/`[^`]*`/g, '').replace(/\b[A-Z0-9]+(?:_[A-Z0-9]+)+\b/g, '').should.not.match(american, title);
  });

  it('names a shared subject once, nests several scenarios under one location, and says where the files are', () => {
    const [ipc] = renderClientFindings([issue('IPC_SENDER_VALIDATION_JS_CHECK', { file: '/client/src/main.js', properties: { channel: 'run' } }),
      issue('IPC_HANDLER_JS_CHECK', { file: '/client/src/main.js', description: "IPC handler: 'run' uses processes with arguments from the page (command)", properties: { channel: 'run' } })],
    { root: '/client/src', app: { name: 'Client' } });
    ipc.content.should.include('This shows that the handler for the `run` channel does not validate the sender of the message before acting on it, and passes values');
    ipc.content.should.match(/^- `main\.js:12` — channel `run`\n {2}- Message sender not validated\n {2}- Message arguments not validated$/m);
    ipc.content.should.include('- Obtain the source code of Client. The file paths below are relative to its root folder.');
    const unpacked = renderClientFindings([issue('NODE_INTEGRATION_JS_CHECK', { file: '/opt/Client/resources/app/main.js' })], { root: '/opt/Client/resources/app', app: { name: 'Client' } })[0].content;
    unpacked.should.include('- Open the application folder `resources/app` in the installation folder of Client.');
    // facts without a common subject keep their own
    const isolation = renderClientFindings([issue('NODE_INTEGRATION_JS_CHECK'), issue('CONTEXT_ISOLATION_JS_CHECK')], META)[0].content;
    isolation.should.include('that Node.js integration is enabled for the window, and that context isolation is disabled for the window');
  });

  it('keeps the parts of a finding in order, with steps and recommendations as bullets, never numbered', () => {
    for (const { title, content } of findings) {
      const headings = [...content.matchAll(/^## (.+)$/gm)].map(m => m[1]);
      headings.should.deep.equal(['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References'], title);
      const front = YAML.parse(content.split(/^---$/m)[1]);
      Object.keys(front).filter(key => key !== 'Notes').should.deep.equal(['Title', 'GeneratedBy', 'Consequence', 'Likelihood'], title);
      if (title === 'Outdated Software Components') continue;
      content.split('## Recommendations\n')[1].should.match(/^\s*- /, title);
      content.should.not.match(/^ *\d+\. /m, title);
    }
  });

  it('records the secrets reminder and accepted risks in Notes only, and limits shown by the application in the note', () => {
    const debugging = findings.find(f => f.title === 'Debugging Features Enabled in Production').content;
    // (a secret written to the console is evidence that can show it)
    YAML.parse(debugging.split(/^---$/m)[1]).Notes.should.deep.equal([secretsNote('testerNotes'),
      'Accepted risk: Developer tools or test functions available at src/main.js:99. Only in the internal build Owner: Client security.']);
    const withSecrets = ['Hard-coded Secrets in the Application Package', 'Sensitive Data Stored Without Adequate Protection', 'Sensitive Data Exposed in Network Traffic',
      'Insecure Network Transport and Certificate Validation', 'Debugging Features Enabled in Production'];
    for (const title of withSecrets) YAML.parse(findings.find(f => f.title === title).content.split(/^---$/m)[1]).Notes[0].should.include('mask them as needed', title);
    const navigation = findings.find(f => f.title === 'Insufficient Navigation and New Window Restrictions').content;
    navigation.should.include('and the application blocked it.');
    navigation.split('## Reproduction and Evidence')[1].should.not.include('blocked it');
    for (const { content } of findings.filter(f => !withSecrets.includes(f.title))) YAML.parse(content.split(/^---$/m)[1]).should.not.have.property('Notes');
  });

  it('describes the certificate bypass switch with the certificate findings, and npm scripts as development only', () => {
    const transport = findings.find(f => f.title === 'Insecure Network Transport and Certificate Validation').content;
    transport.should.include('`--ignore-certificate-errors`').and.include('typically during development');
    findings.find(f => f.title === 'Browser Security Controls Disabled').content.should.not.include('ignore-certificate-errors');
  });

  it('starts the reproduction of a packaged app by extracting its archive, and shows validated runtime results', () => {
    const isolation = findings.find(f => f.title === 'Insufficient Renderer Process Isolation').content.split('## Reproduction and Evidence')[1];
    isolation.should.match(/as follows:\n\n- Extract the application archive `resources\/app\.asar`/);
    isolation.should.include('During testing, a page ran with Node.js integration');
    isolation.should.include('![read.png](../shots/read.png)');
    const xss = findings.find(f => f.title === 'Cross-Site Scripting in Content Rendering').content.split('## Reproduction and Evidence')[1];
    xss.should.include('During testing, test markup reached innerHTML from this line').and.not.include('other.js');
    xss.should.not.match(/remain untested|establishes/);
  });

  it('keeps every instance and caveat in the tester notes', () => {
    const notes = renderTesterNotes(ISSUES, META);
    const all = notes.map(n => n.content).join('\n');
    for (const value of ['**EXOTIC_NEW_CHECK**', 'src/other.js', 'This establishes rendering of markup', 'and the app blocked it', 'Script execution and exploitability remain untested'])
      all.should.include(value);
    // one per finding, the coverage of the sessions when there is one, and the guide to preparing them for release
    notes.length.should.equal(groupClientFindings(ISSUES).length + 1);
    notes.at(-1).file.should.equal(RELEASE_GUIDE_FILE);
    for (const { content } of notes) content.should.match(/^<!-- Electronegativity tester notes/);
  });

  it('names the app after its executable, without .exe', async function () {
    this.timeout(60000);
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-appname-'));
    try {
      fs.mkdirSync(path.join(folder, 'resources', 'app'), { recursive: true });
      fs.writeFileSync(path.join(folder, 'MyApp.exe'), Buffer.concat([Buffer.from('MZ'), Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), Buffer.from([1, 2]), Buffer.from('01')]));
      fs.writeFileSync(path.join(folder, 'resources', 'app', 'package.json'), JSON.stringify({ name: 'my-app-package', productName: 'My Product', version: '1.0.0', main: 'main.js' }));
      fs.writeFileSync(path.join(folder, 'resources', 'app', 'main.js'), "const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n");
      const out = path.join(folder, 'out');
      fs.mkdirSync(out);
      await run({ input: path.join(folder, 'resources', 'app'), offline: true, output: [path.join(out, 'report.html')], suppress: undefined }, false);
      JSON.parse(fs.readFileSync(path.join(out, 'report.json'), 'utf8')).app.name.should.equal('MyApp');
      fs.readFileSync(path.join(out, 'reports', 'Insufficient Renderer Process Isolation.md'), 'utf8').should.include('windows in MyApp run web content');
    } finally { fs.rmSync(folder, { recursive: true, force: true }); }
  });

  it('shows the code around each location with line numbers, one block for nearby lines', () => {
    const source = ['function setup() {', '  const win = new BrowserWindow();', '', '  ipcMain.handle(\'run\', (e, c) => exec(c));', '  ipcMain.on(\'open\', (e, f) => shell.openPath(f));', '});', '', ''];
    const at = (line, id, channel) => issue(id, { file: '/client/src/main.js', location: { line, column: 2 }, sample: source[line - 1].trim(), context: getContext(source, line - 1, 2), properties: { channel } });
    const [ipc] = renderClientFindings([at(4, 'IPC_SENDER_VALIDATION_JS_CHECK', 'run'), at(5, 'IPC_SENDER_VALIDATION_JS_CHECK', 'open')], { root: '/client/src', app: { name: 'Client' } });
    const evidence = ipc.content.split('## Reproduction and Evidence')[1].split('## Recommendations')[0];
    evidence.should.include('- Open `main.js` and review lines 4 and 5:');
    evidence.should.include(['  ```javascript', '  2 |   const win = new BrowserWindow();', '  3 |', "  4 |   ipcMain.handle('run', (e, c) => exec(c));",
      "  5 |   ipcMain.on('open', (e, f) => shell.openPath(f));", '  6 | });', '  ```'].join('\n'));
    evidence.should.include('Line 4 shows that the handler for the `run` channel').and.include('Line 5 shows that the handler for the `open` channel');
    // a minified line: an excerpt around the column
    const minified = getContext([`${'a'.repeat(1000)}el.innerHTML=x;${'b'.repeat(1000)}`], 0, 1000);
    minified.should.include({ start: 1, excerpt: true });
    minified.lines[0].should.match(/^…a+el\.innerHTML=x;b+…$/).and.have.length.below(310);
    // secrets in the lines around a finding are redacted as everywhere else; ordinary code is not
    redactCodeLine("const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';").should.not.include('A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8');
    redactCodeLine("const password = 'Hunter2-Secret-Value!';").should.not.include('Hunter2-Secret-Value!');
    redactCodeLine("  ipcMain.on('open', (event, file) => shell.openPath(file));").should.equal("  ipcMain.on('open', (event, file) => shell.openPath(file));");
    // a report written before the context was recorded: the line alone, numbered
    const [old] = renderClientFindings([issue('NODE_INTEGRATION_JS_CHECK', { file: '/client/src/main.js', sample: 'nodeIntegration: true' })], { root: '/client/src', app: { name: 'Client' } });
    old.content.should.include('  12 | nodeIntegration: true');
  });

  it('lists a file with many locations as one row under Affected', () => {
    const bundle = Array.from({ length: 14 }, (_, n) => issue('XSS_SINK_JS_CHECK', { file: '/client/src/bundle.js', location: { line: n * 10 + 1, column: 0 },
      validation: { status: 'observed' } }));
    const [xss] = renderClientFindings([...bundle, issue('XSS_SINK_JS_CHECK', { file: '/client/src/view.js' })], { root: '/client/src', app: { name: 'Client' } });
    const affected = xss.content.split('## Affected\n')[1].split('## ')[0];
    affected.should.include('- `bundle.js` — 14 locations (lines 1, 11, 21, 31, 41, 51, 61, 71, 81, 91 and 4 more, listed in the tester notes) — Dynamic content inserted as HTML');
    affected.should.include('- `view.js:12` — Dynamic content inserted as HTML');
    renderTesterNotes(bundle, { root: '/client/src', app: { name: 'Client' } })[0].content.should.include('`bundle.js:131`');
  });

  it('ends each tester notes file with a checklist whose links reach the sections of the release guide', () => {
    const notes = renderTesterNotes(ISSUES, META);
    const guide = notes.find(n => n.file === RELEASE_GUIDE_FILE).content;
    const anchors = new Set([...guide.matchAll(/^## (.+)$/gm)].map(m => m[1].toLowerCase().replace(/[^a-z0-9 -]/g, '').replace(/ /g, '-')));
    const secrets = notes.find(n => n.title === 'Hard-coded Secrets in the Application Package').content.split('## Before release')[1];
    secrets.should.include('- [ ] Find every secret in the finding and mask it.').and.include('- [ ] Find out, with the client, whether the embedded credential still works.');
    notes.find(n => n.title === 'Outdated Software Components').content.should.include('Links to validate manually');
    notes.find(n => n.title === 'Sensitive Data Exposed in Network Traffic').content.should.include('which of the hosts named in the finding are theirs');
    notes.find(n => n.title === 'Debugging Features Enabled in Production').content.should.include('Check that the 1 accepted risk is still accepted');
    for (const { title, content } of notes.filter(n => n.file !== RELEASE_GUIDE_FILE && n.title !== 'Validation Coverage and Test Outcomes')) {
      const checklist = content.split('## Before release')[1];
      checklist.should.be.a('string', title);
      for (const [, target] of checklist.matchAll(/\]\(([^)]+)\)/g)) {
        const [file, hash] = target.split('#');
        decodeURIComponent(file).should.equal(RELEASE_GUIDE_FILE);
        anchors.has(hash).should.equal(true, `${title}: #${hash}`);
      }
    }
    guide.should.include('## Mask secrets').and.include('Ctrl+F');
  });

  it('labels example code as illustrative', () => {
    const isolation = findings.find(f => f.title === 'Insufficient Renderer Process Isolation').content;
    isolation.should.match(/The following illustrative examples? shows? the recommended approach\. (It|They) should be adapted to the application’s own code:/);
  });
});
