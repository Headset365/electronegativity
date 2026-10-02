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

  it('is written in Australian English', () => {
    const american = /\b\w*(sanitiz|organiz|behavior|authoriz|analyz|randomiz|recogniz|minimiz|prioritiz|utiliz|customiz|centraliz|characteriz|color|honor|favor|center|defense|catalog\b)\w*/i;
    for (const { title, content } of findings) prose(content).should.not.match(american, title);
  });

  it('keeps the parts of a finding in order, with numbered steps and recommendations', () => {
    for (const { title, content } of findings) {
      const headings = [...content.matchAll(/^## (.+)$/gm)].map(m => m[1]);
      headings.should.deep.equal(['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References'], title);
      const front = YAML.parse(content.split(/^---$/m)[1]);
      Object.keys(front).filter(key => key !== 'Notes').should.deep.equal(['Title', 'GeneratedBy', 'Consequence', 'Likelihood'], title);
      if (title === 'Outdated Software Components') continue;
      content.split('## Recommendations\n')[1].should.match(/^\s*1\. /, title);
    }
  });

  it('records accepted risks in Notes only, and limits shown by the application in the note', () => {
    const debugging = findings.find(f => f.title === 'Debugging Features Enabled in Production').content;
    YAML.parse(debugging.split(/^---$/m)[1]).Notes.should.deep.equal(['Accepted risk: Developer tools or test functions available at src/main.js:99. Only in the internal build Owner: Client security.']);
    const navigation = findings.find(f => f.title === 'Insufficient Navigation and New Window Restrictions').content;
    navigation.should.include('and the application blocked it.');
    navigation.split('## Reproduction and Evidence')[1].should.not.include('blocked it');
    for (const { content } of findings.filter(f => f.title !== 'Debugging Features Enabled in Production')) YAML.parse(content.split(/^---$/m)[1]).should.not.have.property('Notes');
  });

  it('describes the certificate bypass switch with the certificate findings, and npm scripts as development only', () => {
    const transport = findings.find(f => f.title === 'Insecure Network Transport and Certificate Validation').content;
    transport.should.include('`--ignore-certificate-errors`').and.include('typically during development');
    findings.find(f => f.title === 'Browser Security Controls Disabled').content.should.not.include('ignore-certificate-errors');
  });

  it('starts the reproduction of a packaged app by extracting its archive, and shows validated runtime results', () => {
    const isolation = findings.find(f => f.title === 'Insufficient Renderer Process Isolation').content.split('## Reproduction and Evidence')[1];
    isolation.should.match(/1\. Extract the application archive `resources\\app\.asar`/);
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
    notes.length.should.equal(groupClientFindings(ISSUES).length);
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
});
