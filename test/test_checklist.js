// Coverage of the Electron security checklist (https://www.electronjs.org/docs/latest/tutorial/security) and other
// well-known Electron security practices. Each practice has insecure code that must be reported, with the expected
// severity and at least the expected confidence, and secure code that must not be reported.
// Scans run end-to-end through run(), offline, so results don't depend on the network.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import run from '../src/runner.js';

chaiShould();

const NETWORK_CHECKS = ['availablesecurityfixesglobalcheck', 'unsupportedversionglobalcheck', 'dependencyvulnerabilitiesglobalcheck'];
const CONFIDENCE = { TENTATIVE: 0, FIRM: 1, CERTAIN: 2 };

const MODERN = { 'package.json': JSON.stringify({ name: 'app', devDependencies: { electron: '38.2.0' } }) };

export async function scan(files, { electronVersion } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-checklist-'));
  try {
    for (const [name, content] of Object.entries({ ...MODERN, ...files })) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), content);
    }
    const result = await run({ input: dir, excludeFromScan: NETWORK_CHECKS, offline: true, electronVersionOverride: electronVersion, isRelative: true });
    result.errors.filter(e => !e.tolerable).should.deep.equal([], 'files must parse');
    return result.issues;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const describeIssues = (issues) => issues.map(i => `${i.id} ${i.severity.name}/${i.confidence.name} ${i.file}:${i.location.line} ${i.description}`).join('\n    ');

// asserts that a finding with the id exists, with the given severity and at least the given confidence
function expectFinding(issues, { id, severity, confidence = 'FIRM', match }) {
  const candidates = issues.filter(i => i.id === id && (!match || match.test(i.description)));
  const found = candidates.find(i => (!severity || i.severity.name === severity) && i.confidence.value >= CONFIDENCE[confidence]);
  if (!found)
    throw new Error(`expected ${id}${severity ? ' ' + severity : ''} with confidence >= ${confidence}${match ? ' matching ' + match : ''}, got:\n    ${describeIssues(issues) || '(no findings)'}`);
}

// asserts that nothing is reported for the id above INFORMATIONAL
function expectNoFinding(issues, id) {
  const found = issues.filter(i => i.id === id && i.severity.name !== 'INFORMATIONAL');
  if (found.length > 0) throw new Error(`expected no ${id} findings, got:\n    ${describeIssues(found)}`);
}

// window boilerplate that satisfies the application-wide checks, so each case only exercises what it's about
const HARDENING = `
const { app, session } = require('electron');
session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => callback(false));
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});
`;

const CASES = [
  // 1. Only load secure content
  { practice: '#1 only load secure content', insecure: { 'main.js': `win.loadURL('http://example.com');` }, expect: [{ id: 'HTTP_RESOURCES_JS_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': `win.loadURL('https://example.com');` }, absent: ['HTTP_RESOURCES_JS_CHECK'] },
  { practice: '#1 only load secure content (HTML)', insecure: { 'index.html': `<script src="http://cdn.example.com/lib.js"></script>` }, expect: [{ id: 'HTTP_RESOURCES_HTML_CHECK', confidence: 'CERTAIN' }],
    secure: { 'index.html': `<script src="https://cdn.example.com/lib.js"></script>` }, absent: ['HTTP_RESOURCES_HTML_CHECK'] },

  // 2. Do not enable Node.js integration for remote content
  { practice: '#2 nodeIntegration', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { nodeIntegration: true, sandbox: false } });` }, expect: [{ id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { preload: 'preload.js' } });` }, absent: ['NODE_INTEGRATION_JS_CHECK'] },
  { practice: '#2 nodeIntegration for unknown versions (default on)', insecure: { 'main.js': `const w = new BrowserWindow();`, 'package.json': '{"name":"x"}' },
    expect: [{ id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH' }] },
  { practice: '#2 nodeIntegrationInWorker', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { nodeIntegrationInWorker: true } });` }, expect: [{ id: 'NODE_INTEGRATION_JS_CHECK' }] },
  { practice: '#2 <webview nodeintegration>', insecure: { 'index.html': `<webview src="https://example.com" nodeintegration></webview>` }, expect: [{ id: 'NODE_INTEGRATION_HTML_CHECK' }],
    secure: { 'index.html': `<webview src="https://example.com"></webview>` }, absent: ['NODE_INTEGRATION_HTML_CHECK'] },

  // 3. Enable context isolation
  { practice: '#3 contextIsolation: false', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { contextIsolation: false } });` }, expect: [{ id: 'CONTEXT_ISOLATION_JS_CHECK', severity: 'HIGH' }],
    secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { preload: 'preload.js' } });` }, absent: ['CONTEXT_ISOLATION_JS_CHECK'] },
  { practice: '#3 contextIsolation missing on Electron < 12', insecure: { 'main.js': `const w = new BrowserWindow();` }, version: '11.0.0', expect: [{ id: 'CONTEXT_ISOLATION_JS_CHECK', severity: 'HIGH' }] },

  // 4. Enable process sandboxing
  { practice: '#4 sandbox: false', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { sandbox: false } });` }, expect: [{ id: 'SANDBOX_JS_CHECK', severity: 'MEDIUM' }],
    secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { preload: 'p.js' } });` }, absent: ['SANDBOX_JS_CHECK'] },
  { practice: '#4 nodeIntegration disables the default sandbox', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { nodeIntegration: true } });` }, expect: [{ id: 'SANDBOX_JS_CHECK' }] },
  { practice: '#4 app.enableSandbox() overrides per-window settings', secure: { 'main.js': `app.enableSandbox();\nconst w = new BrowserWindow({ webPreferences: { sandbox: false } });` }, absent: ['SANDBOX_JS_CHECK'] },

  // 5. Handle session permission requests from remote content
  { practice: '#5 no permission request handler', insecure: { 'main.js': `const w = new BrowserWindow();` }, expect: [{ id: 'PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': HARDENING }, absent: ['PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK', 'PERMISSION_REQUEST_HANDLER_JS_CHECK'] },
  { practice: '#5 handler granting everything', insecure: { 'main.js': `session.defaultSession.setPermissionRequestHandler((wc, permission, callback) => callback(true));` },
    expect: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: '#5 handler granting without checking the origin', insecure: { 'main.js': `ses.setPermissionRequestHandler((wc, permission, callback) => { callback(permission === 'notifications'); });` },
    expect: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }] },
  { practice: '#5 handler checking the origin', secure: { 'main.js': `ses.setPermissionRequestHandler((wc, permission, callback) => {\n  if (new URL(wc.getURL()).origin === 'https://app.example.com' && permission === 'notifications') return callback(true);\n  callback(false);\n});` },
    absent: [], expectSecure: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'LOW' }] },
  { practice: '#5 permission check handler returning true', insecure: { 'main.js': `session.defaultSession.setPermissionCheckHandler(() => true);` },
    expect: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: '#5 device permission handler returning true', insecure: { 'main.js': `session.defaultSession.setDevicePermissionHandler((details) => { return true; });` },
    expect: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },

  // 6. Do not disable webSecurity
  { practice: '#6 webSecurity: false', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { webSecurity: false } });` }, expect: [{ id: 'WEB_SECURITY_JS_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { webSecurity: true } });` }, absent: ['WEB_SECURITY_JS_CHECK'] },
  { practice: '#6 <webview disablewebsecurity>', insecure: { 'index.html': `<webview src="https://example.com" disablewebsecurity></webview>` }, expect: [{ id: 'WEB_SECURITY_HTML_CHECK', confidence: 'CERTAIN' }] },

  // 7. Define a Content Security Policy
  { practice: '#7 no CSP', insecure: { 'index.html': `<html><body></body></html>` }, expect: [{ id: 'CSP_GLOBAL_CHECK', confidence: 'CERTAIN', match: /No CSP/ }],
    secure: { 'index.html': `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'">` },
    absent: ['CSP_GLOBAL_CHECK'] },
  { practice: '#7 weak CSP', insecure: { 'index.html': `<meta http-equiv="Content-Security-Policy" content="default-src *; script-src * 'unsafe-inline' 'unsafe-eval'">` },
    expect: [{ id: 'CSP_GLOBAL_CHECK', confidence: 'CERTAIN', match: /vulnerable/ }] },

  // 8-10. Insecure content, experimental features, Blink features
  { practice: '#8 allowRunningInsecureContent', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { allowRunningInsecureContent: true } });` }, expect: [{ id: 'INSECURE_CONTENT_JS_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': `const w = new BrowserWindow();` }, absent: ['INSECURE_CONTENT_JS_CHECK'] },
  { practice: '#9 experimentalFeatures', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { experimentalFeatures: true } });` }, expect: [{ id: 'EXPERIMENTAL_FEATURES_JS_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': `const w = new BrowserWindow();` }, absent: ['EXPERIMENTAL_FEATURES_JS_CHECK'] },
  { practice: '#10 enableBlinkFeatures', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { enableBlinkFeatures: 'ExecCommandInJavaScript' } });` }, expect: [{ id: 'BLINK_FEATURES_JS_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': `const w = new BrowserWindow();` }, absent: ['BLINK_FEATURES_JS_CHECK'] },

  // 11-12. WebViews
  { practice: '#11 <webview allowpopups>', insecure: { 'index.html': `<webview src="https://example.com" allowpopups></webview>` }, expect: [{ id: 'ALLOWPOPUPS_HTML_CHECK', confidence: 'CERTAIN' }],
    secure: { 'index.html': `<webview src="https://example.com"></webview>` }, absent: ['ALLOWPOPUPS_HTML_CHECK'] },
  { practice: '#12 webviewTag without will-attach-webview', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { webviewTag: true } });` }, expect: [{ id: 'WEBVIEW_GLOBAL_CHECK', severity: 'HIGH' }],
    secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { webviewTag: true } });\ncontents.on('will-attach-webview', (e, prefs) => { delete prefs.preload; });` }, absent: ['WEBVIEW_GLOBAL_CHECK'] },

  // 13. Disable or limit navigation
  { practice: '#13 no navigation limits', insecure: { 'main.js': `const w = new BrowserWindow();` }, expect: [{ id: 'LIMIT_NAVIGATION_GLOBAL_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': HARDENING }, absent: ['LIMIT_NAVIGATION_GLOBAL_CHECK', 'LIMIT_NAVIGATION_JS_CHECK'] },
  { practice: '#13 will-navigate handler that blocks nothing', insecure: { 'main.js': `contents.on('will-navigate', (event, url) => { console.log(url); });\ncontents.setWindowOpenHandler(() => ({ action: 'deny' }));` },
    expect: [{ id: 'LIMIT_NAVIGATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }, { id: 'LIMIT_NAVIGATION_GLOBAL_CHECK', match: /will-navigate/ }] },
  { practice: '#13 will-navigate allowlist', secure: { 'main.js': `${HARDENING}\ncontents.on('will-navigate', (event, url) => { if (new URL(url).origin !== 'https://app.example.com') event.preventDefault(); });` },
    absent: ['LIMIT_NAVIGATION_GLOBAL_CHECK'], expectSecure: [{ id: 'LIMIT_NAVIGATION_JS_CHECK', severity: 'LOW' }] },

  // 14. Disable or limit creation of new windows
  { practice: '#14 no window open handler', insecure: { 'main.js': `contents.on('will-navigate', (e) => e.preventDefault());` }, expect: [{ id: 'LIMIT_NAVIGATION_GLOBAL_CHECK', match: /new window/i }] },
  { practice: '#14 window open handler allowing everything', insecure: { 'main.js': `contents.setWindowOpenHandler(() => ({ action: 'allow' }));` },
    expect: [{ id: 'WINDOW_OPEN_HANDLER_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `contents.setWindowOpenHandler(() => ({ action: 'deny' }));` }, absent: ['WINDOW_OPEN_HANDLER_JS_CHECK'] },
  { practice: '#14 new windows with Node.js enabled', insecure: { 'main.js': `contents.setWindowOpenHandler(({ url }) => { if (url.startsWith('https://a.com/')) return { action: 'allow', overrideBrowserWindowOptions: { webPreferences: { nodeIntegration: true } } }; return { action: 'deny' }; });` },
    expect: [{ id: 'WINDOW_OPEN_HANDLER_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },

  // 15. Do not use shell.openExternal with untrusted content
  { practice: '#15 openExternal with URLs from web content', insecure: { 'main.js': `contents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });` },
    expect: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },
  { practice: '#15 openExternal with URLs from IPC', insecure: { 'main.js': `ipcMain.handle('open', (event, link) => shell.openExternal(link));` },
    expect: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },
  { practice: '#15 openExternal with a dangerous constant', insecure: { 'main.js': `shell.openExternal('file:///Applications/Calculator.app');` },
    expect: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'LOW', confidence: 'CERTAIN' }] },
  { practice: '#15 openExternal with validated URLs', secure: { 'main.js': `contents.setWindowOpenHandler(({ url }) => { if (new URL(url).protocol === 'https:') shell.openExternal(url); return { action: 'deny' }; });` },
    absent: [], expectSecure: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'LOW' }] },
  { practice: '#15 openExternal with fixed URLs', secure: { 'main.js': `shell.openExternal('https://example.com/help');\nshell.openExternal(\`https://example.com/docs/\${page}\`);` }, absent: ['OPEN_EXTERNAL_JS_CHECK'] },

  // 16. Use a current version of Electron (the advisory/support lookups need the network, see test_modern.js)
  { practice: '#16 Electron version detection', insecure: { 'main.js': '' }, expect: [{ id: 'ELECTRON_VERSION_JSON_CHECK', severity: 'INFORMATIONAL', confidence: 'CERTAIN' }] },

  // 17. Validate the sender of all IPC messages
  { practice: '#17 IPC without sender validation', insecure: { 'main.js': `ipcMain.handle('get-secrets', () => getSecrets());` }, expect: [{ id: 'IPC_SENDER_VALIDATION_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }],
    secure: { 'main.js': `ipcMain.handle('get-secrets', (event) => { if (new URL(event.senderFrame.url).host !== 'app.local') return null; return getSecrets(); });` }, absent: ['IPC_SENDER_VALIDATION_JS_CHECK'] },

  // 18. Avoid file://, prefer custom protocols
  { practice: '#18 file:// content', insecure: { 'main.js': `win.loadFile('index.html');` }, expect: [{ id: 'FILE_PROTOCOL_JS_CHECK', confidence: 'CERTAIN' }],
    secure: { 'main.js': `win.loadURL('app://bundle/index.html');` }, absent: ['FILE_PROTOCOL_JS_CHECK'] },
  { practice: '#18 custom protocol with path traversal', insecure: { 'main.js': `protocol.handle('app', (req) => net.fetch('file://' + path.join(__dirname, new URL(req.url).pathname)));` },
    expect: [{ id: 'PROTOCOL_HANDLER_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }],
    secure: { 'main.js': `protocol.handle('app', (req) => {\n  const p = path.resolve(root, new URL(req.url).pathname.slice(1));\n  if (!p.startsWith(root + path.sep)) return new Response('', { status: 403 });\n  return net.fetch(pathToFileURL(p).toString());\n});` },
    expectSecure: [{ id: 'PROTOCOL_HANDLER_JS_CHECK', severity: 'LOW' }] },
  { practice: '#18 privileged scheme bypassing CSP', insecure: { 'main.js': `protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, bypassCSP: true } }]);` },
    expect: [{ id: 'PROTOCOL_PRIVILEGES_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true } }]);` }, absent: ['PROTOCOL_PRIVILEGES_JS_CHECK'] },

  // 19. Check which fuses you can change
  { practice: '#19 insecure fuse', insecure: { 'forge.config.js': `module.exports = { plugins: [new FusesPlugin({ version: FuseVersion.V1, [FuseV1Options.RunAsNode]: true })] };` },
    expect: [{ id: 'FUSES_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: '#19 packager without fuses', insecure: { 'package.json': JSON.stringify({ name: 'a', devDependencies: { electron: '38.2.0' }, build: { appId: 'com.example' } }) },
    expect: [{ id: 'FUSES_GLOBAL_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }] },
  { practice: '#19 hardened fuses', secure: { 'forge.config.js': `module.exports = { plugins: [new FusesPlugin({ version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false, [FuseV1Options.EnableCookieEncryption]: true, [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false, [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true, [FuseV1Options.GrantFileProtocolExtraPrivileges]: false })] };` },
  absent: ['FUSES_JS_CHECK', 'FUSES_GLOBAL_CHECK'] },

  // 20. Do not expose Electron APIs to untrusted web content
  { practice: '#20 exposing ipcRenderer', insecure: { 'preload.js': `contextBridge.exposeInMainWorld('electronAPI', { on: ipcRenderer.on });` },
    expect: [{ id: 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },
  { practice: '#20 passing the IPC event to the page', insecure: { 'preload.js': `contextBridge.exposeInMainWorld('electronAPI', { onUpdate: (callback) => ipcRenderer.on('update', callback) });` }, version: '28.3.0',
    expect: [{ id: 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }],
    secure: { 'preload.js': `contextBridge.exposeInMainWorld('electronAPI', { onUpdate: (callback) => ipcRenderer.on('update', (_event, value) => callback(value)) });` },
    absent: ['CONTEXT_BRIDGE_EXPOSURE_JS_CHECK'] },
  { practice: '#20 generic IPC passthrough', insecure: { 'preload.js': `contextBridge.exposeInMainWorld('api', { invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args) });` },
    expect: [{ id: 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },

  // Beyond the checklist
  { practice: 'remote module', insecure: { 'main.js': `require('@electron/remote/main').initialize();` }, expect: [{ id: 'REMOTE_MODULE_JS_CHECK', confidence: 'FIRM' }] },
  { practice: 'certificate-error accepting everything', insecure: { 'main.js': `app.on('certificate-error', (event, wc, url, error, cert, callback) => { event.preventDefault(); callback(true); });` },
    expect: [{ id: 'CERTIFICATE_ERROR_EVENT_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `app.on('certificate-error', (event, wc, url, error, cert, callback) => { callback(false); });` }, absent: ['CERTIFICATE_ERROR_EVENT_JS_CHECK'] },
  { practice: 'certificate verification disabled', insecure: { 'main.js': `ses.setCertificateVerifyProc((request, callback) => callback(0));` },
    expect: [{ id: 'CERTIFICATE_VERIFY_PROC_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: 'certificate pinning', secure: { 'main.js': `ses.setCertificateVerifyProc((request, callback) => callback(PINS.includes(request.certificate.fingerprint) ? -3 : -2));` },
    absent: ['CERTIFICATE_VERIFY_PROC_JS_CHECK', 'CERTIFICATE_PINNING_GLOBAL_CHECK'] },
  { practice: 'Node.js TLS validation disabled', insecure: { 'main.js': `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';` }, expect: [{ id: 'NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';` }, absent: ['NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK'] },
  { practice: 'dangerous Chromium switches', insecure: { 'main.js': `app.commandLine.appendSwitch('ignore-certificate-errors');` }, expect: [{ id: 'CUSTOM_ARGUMENTS_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `app.commandLine.appendSwitch('lang', 'en-US');` }, absent: ['CUSTOM_ARGUMENTS_JS_CHECK'] },
  { practice: 'security warnings disabled', insecure: { 'main.js': `process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = true;` }, expect: [{ id: 'SECURITY_WARNINGS_DISABLED_JS_CHECK', confidence: 'CERTAIN' }] },
  { practice: 'eval-like functions', insecure: { 'main.js': `win.webContents.executeJavaScript(code);` }, expect: [{ id: 'DANGEROUS_FUNCTIONS_JS_CHECK' }] },
  { practice: 'XSS sinks in renderers', insecure: { 'renderer.js': `el.innerHTML = message.body;` }, expect: [{ id: 'XSS_SINK_JS_CHECK', confidence: 'FIRM' }],
    secure: { 'renderer.js': `el.textContent = message.body;\nel.innerHTML = DOMPurify.sanitize(message.body);` }, absent: ['XSS_SINK_JS_CHECK'] },
  { practice: 'command injection from IPC', insecure: { 'main.js': `const { exec } = require('child_process');\nipcMain.handle('ping', (event, host) => exec('ping -c 1 ' + host));` },
    expect: [{ id: 'COMMAND_INJECTION_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }],
    secure: { 'main.js': `const { execFile } = require('node:child_process');\nipcMain.handle('ping', (event, host) => execFile('ping', ['-c', '1', host]));\nconst m = /x/.exec(host);\nconst { exec } = require('./my-git-wrapper');\nexec(repo, args);` }, absent: ['COMMAND_INJECTION_JS_CHECK'] },
  { practice: 'shell.openPath from IPC', insecure: { 'main.js': `ipcMain.on('open', (event, file) => shell.openPath(file));` }, expect: [{ id: 'OPEN_PATH_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },
  { practice: 'loading URLs from IPC', insecure: { 'main.js': `ipcMain.on('go', (event, url) => win.loadURL(url));` }, expect: [{ id: 'UNTRUSTED_LOAD_URL_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },
  { practice: 'DevTools in production', insecure: { 'main.js': `win.webContents.openDevTools();` }, expect: [{ id: 'DEVTOOLS_JS_CHECK', severity: 'MEDIUM', confidence: 'CERTAIN' }],
    secure: { 'main.js': `if (!app.isPackaged) win.webContents.openDevTools();` }, absent: ['DEVTOOLS_JS_CHECK'] },
  { practice: 'deep links and file associations', insecure: { 'main.js': `app.on('open-url', (event, url) => route(url));` }, expect: [{ id: 'FILE_HANDLER_JS_CHECK', confidence: 'FIRM' }] },
  { practice: 'risky webPreferences', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { plugins: true, navigateOnDragDrop: true, webgl: true } });` },
    expect: [{ id: 'PLUGINS_JS_CHECK', confidence: 'CERTAIN' }, { id: 'NAVIGATE_ON_DRAG_DROP_JS_CHECK', confidence: 'CERTAIN' }, { id: 'WEBGL_JS_CHECK', confidence: 'CERTAIN' }] },
  { practice: 'middle-click handled by setWindowOpenHandler', secure: { 'main.js': `const w = new BrowserWindow();\nw.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));` }, absent: ['AUXCLICK_JS_CHECK'] },
  { practice: 'Secure Keyboard Entry for password fields', insecure: { 'login.html': `<input type="password">` }, expect: [{ id: 'SECUREKEYBOARDENTRY_GLOBAL_CHECK', confidence: 'FIRM' }],
    secure: { 'login.html': `<input type="password">`, 'main.js': `app.setSecureKeyboardEntryEnabled(true);` }, absent: ['SECUREKEYBOARDENTRY_GLOBAL_CHECK'] },

  { practice: 'downloads opened automatically', insecure: { 'main.js': `session.defaultSession.on('will-download', (event, item) => {\n  item.once('done', (e, state) => { if (state === 'completed') shell.openPath(item.getSavePath()); });\n});` },
    expect: [{ id: 'DOWNLOAD_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }],
    secure: { 'main.js': `session.defaultSession.on('will-download', (event, item) => {\n  item.setSavePath(path.join(downloads, path.basename(item.getFilename())));\n  item.once('done', () => shell.showItemInFolder(item.getSavePath()));\n});` }, absent: ['DOWNLOAD_JS_CHECK'] },
  { practice: 'downloads saved under the server-provided name', insecure: { 'main.js': `ses.on('will-download', (event, item) => { item.setSavePath(downloads + '/' + item.getFilename()); });` },
    expect: [{ id: 'DOWNLOAD_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }] },
  { practice: 'updates over plain HTTP', insecure: { 'main.js': `autoUpdater.setFeedURL({ url: 'http://updates.example.com/app' });` }, expect: [{ id: 'UPDATE_SECURITY_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'main.js': `autoUpdater.setFeedURL({ url: 'https://updates.example.com/app' });` }, absent: ['UPDATE_SECURITY_JS_CHECK'] },
  { practice: 'update signatures not verified', insecure: { 'package.json': JSON.stringify({ name: 'a', devDependencies: { electron: '38.2.0' }, build: { appId: 'x', win: { verifyUpdateCodeSignature: false }, publish: { provider: 'generic', url: 'http://updates.example.com' } } }) },
    expect: [{ id: 'UPDATE_SECURITY_JSON_CHECK', severity: 'HIGH', confidence: 'CERTAIN', match: /signature/ }, { id: 'UPDATE_SECURITY_JSON_CHECK', severity: 'HIGH', match: /HTTP/ }] },
  { practice: 'update downgrades allowed', insecure: { 'main.js': `autoUpdater.allowDowngrade = true;` }, expect: [{ id: 'UPDATE_SECURITY_JS_CHECK', severity: 'MEDIUM', confidence: 'CERTAIN' }],
    secure: { 'main.js': `autoUpdater.allowDowngrade = false;` }, absent: ['UPDATE_SECURITY_JS_CHECK'] },
  { practice: 'secrets stored in plaintext', insecure: { 'main.js': `store.set('accessToken', token);\nlocalStorage.setItem('password', pw);` }, expect: [{ id: 'PLAINTEXT_SECRETS_JS_CHECK', severity: 'LOW', confidence: 'FIRM' }],
    secure: { 'main.js': `store.set('accessToken', safeStorage.encryptString(token).toString('base64'));\nstore.set('theme', 'dark');\nmap.set('token', t);` }, absent: ['PLAINTEXT_SECRETS_JS_CHECK'] },
  { practice: 'screen capture without asking', insecure: { 'main.js': `session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {\n  desktopCapturer.getSources({ types: ['screen'] }).then((sources) => callback({ video: sources[0] }));\n});` },
    expect: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM', match: /screen/ }] },
  { practice: 'screen capture through a picker', secure: { 'main.js': `${HARDENING}\nsession.defaultSession.setDisplayMediaRequestHandler((request, callback) => {\n  showSourcePicker().then((source) => { if (source) callback({ video: source }); else callback({}); });\n});` },
    expectSecure: [{ id: 'PERMISSION_REQUEST_HANDLER_JS_CHECK', severity: 'LOW' }] },

  // Regressions found by scanning open-source apps (Signal, Element, VS Code, Mattermost, GitHub Desktop, Hyper, Fiddle)
  { practice: 'regression: TypeScript generics in .ts files parse', secure: { 'util.ts': `export const pick = <T,>(x: T): T => x;\nexport const cast = <T>(x: unknown) => x as T;\nconst f = async <K extends string>(k: K): Promise<Map<K, number>> => new Map();` }, absent: [] },
  { practice: 'regression: RegExp.exec and app helpers named exec are not child_process', secure: { 'main.js': `const m = /a(b)/.exec(input);\nimport { exec } from './git';\nexec(repoPath, ['status']);` }, absent: ['COMMAND_INJECTION_JS_CHECK'] },
  { practice: 'regression: child_process through a namespace and promisify', insecure: { 'main.js': `import * as cp from 'node:child_process';\nimport { promisify } from 'util';\nconst run = promisify(cp.exec);\nipcMain.handle('run', (e, cmd) => run(cmd));` },
    expect: [{ id: 'COMMAND_INJECTION_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }] },
  { practice: 'regression: class method IPC handlers are analyzed', insecure: { 'main.js': `class Downloads {\n  init() { ipcMain.handle('location', this.select); }\n  select = (event, dir) => dialog.showOpenDialog({ defaultPath: dir });\n}` },
    expect: [{ id: 'IPC_SENDER_VALIDATION_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }] },
  { practice: 'regression: bound class method handlers validating the sender', secure: { 'main.js': `class Downloads {\n  init() { ipcMain.handle('location', this.select.bind(this)); }\n  select(event, dir) { if (!isTrusted(event.senderFrame)) return; return dir; }\n}` },
    absent: ['IPC_SENDER_VALIDATION_JS_CHECK'] },
  { practice: 'regression: NODE_TLS_REJECT_UNAUTHORIZED reset to empty', secure: { 'main.js': `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '';` }, absent: ['NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK'] },
  { practice: 'regression: DevTools from a menu item are on-demand', secure: { 'main.js': `const menu = Menu.buildFromTemplate([{ label: 'Toggle DevTools', click: () => win.webContents.toggleDevTools() }]);` },
    expectSecure: [{ id: 'DEVTOOLS_JS_CHECK', severity: 'LOW' }] },
  { practice: 'regression: exposing process.platform is harmless', secure: { 'preload.js': `contextBridge.exposeInMainWorld('env', { platform: process.platform, arch: process.arch });` }, absent: ['CONTEXT_BRIDGE_EXPOSURE_JS_CHECK'] },
  { practice: 'regression: allowlisted IPC channels', secure: { 'preload.js': `contextBridge.exposeInMainWorld('electron', {\n  send(channel, ...args) {\n    if (!CHANNELS.includes(channel)) return;\n    ipcRenderer.send(channel, ...args);\n  }\n});` },
    expectSecure: [{ id: 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', severity: 'LOW' }] },
  { practice: 'regression: lookups keyed by IPC data are not attacker values', secure: { 'main.js': `ipcMain.on('open-download', (ev, { id }) => { const p = downloads.get(id); if (p) shell.openPath(p); });` },
    absent: [], expectSecure: [{ id: 'OPEN_PATH_JS_CHECK', confidence: 'TENTATIVE' }] },
  { practice: 'regression: will-navigate delegating to a helper', secure: { 'main.js': `${HARDENING}\nfunction onNavigate(ev, url) { if (!url.startsWith('https://app/')) ev.preventDefault(); }\ncontents.on('will-navigate', (ev, url) => onNavigate(ev, url));` },
    absent: ['LIMIT_NAVIGATION_GLOBAL_CHECK'], expectSecure: [{ id: 'LIMIT_NAVIGATION_JS_CHECK', severity: 'LOW' }] },
  { practice: 'regression: showItemInFolder only reveals files', insecure: { 'main.js': `ipcMain.handle('reveal', (_, path) => shell.showItemInFolder(path));` },
    expect: [{ id: 'SHOWITEMINFOLDER_JS_CHECK', severity: 'LOW', confidence: 'FIRM' }] },
  { practice: 'regression: validation helpers guard openExternal', secure: { 'main.js': `contents.setWindowOpenHandler(({ url }) => { if (isTeamUrl(url)) openTab(url); else if (!isCustomProtocol(url)) shell.openExternal(url); return { action: 'deny' }; });` },
    expectSecure: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'LOW' }] },
  { practice: 'regression: containment helpers in protocol handlers', secure: { 'main.js': `protocol.handle('bundles', (req) => {\n  const p = join(DIR, new URL(req.url).pathname);\n  if (!isPathInside(p, DIR)) throw new Error('invalid');\n  return net.fetch(pathToFileURL(p).toString());\n});` },
    expectSecure: [{ id: 'PROTOCOL_HANDLER_JS_CHECK', severity: 'LOW' }] },
  { practice: 'regression: Electron version from .npmrc', secure: { 'package.json': '{"name":"code"}', '.npmrc': 'disturl="https://electronjs.org/headers"\ntarget="43.7.3"\nruntime="electron"\n', 'main.js': `const w = new BrowserWindow(options);` },
    absent: ['NODE_INTEGRATION_JS_CHECK', 'CONTEXT_ISOLATION_JS_CHECK', 'SANDBOX_JS_CHECK'] },
  { practice: 'regression: constant template literals are not dynamic code', secure: { 'main.js': `win.webContents.insertCSS(\`.titlebar { margin: 0 }\`);\nwin.webContents.executeJavaScript(\`window.prompt = () => ''\`);` }, absent: ['DANGEROUS_FUNCTIONS_JS_CHECK'] },
  { practice: 'regression: constant non-web URLs are low severity', secure: { 'main.js': `shell.openExternal('x-apple.systempreferences:com.apple.preference.notifications');` },
    expectSecure: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'LOW', confidence: 'CERTAIN' }] },
  { practice: 'regression: methods named like eval-like globals', secure: { 'main.js': `self.req.setTimeout(timeout, function () { abort(); });\nrequest.setTimeout(ms);` }, absent: ['DANGEROUS_FUNCTIONS_JS_CHECK'] },
  { practice: 'regression: vendored package manager releases are skipped', secure: { 'bin/yarn-standalone.js': `win.webContents.openDevTools();` }, absent: ['DEVTOOLS_JS_CHECK'] },
  { practice: 'regression: tooling in dot-directories is skipped', secure: { '.yarn/releases/yarn.cjs': `win.webContents.openDevTools();` }, absent: ['DEVTOOLS_JS_CHECK'] },
  { practice: 'regression: tests and vendored code are skipped', secure: { 'test/main.test.js': `win.webContents.openDevTools();`, 'vendor/lib.js': `win.webContents.openDevTools();`, 'src/app.min.js': `win.webContents.openDevTools();`, 'src/assets/libs/snap.svg-min.js': `win.webContents.openDevTools();` }, absent: ['DEVTOOLS_JS_CHECK'] },

  { practice: 'minified bundles: namespaced BrowserWindow', insecure: { 'dist/main.js': `const o=require("electron");new o.BrowserWindow({webPreferences:{contextIsolation:!1,nodeIntegration:!0,webSecurity:!1}});` },
    expect: [{ id: 'CONTEXT_ISOLATION_JS_CHECK', severity: 'HIGH' }, { id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }, { id: 'WEB_SECURITY_JS_CHECK' }] },

  { practice: 'regression: non-literal disableBlinkFeatures does not break the scan', secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { disableBlinkFeatures: features } });\nw.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));` }, absent: ['AUXCLICK_JS_CHECK'] },

  { practice: 'regression: protocol handlers proxying to http are not file servers', secure: { 'main.js': `protocol.handle('remote', (request) => net.fetch(request.url.replace('remote:', 'http:'), { bypassCustomProtocolHandlers: true }));` },
    expectSecure: [{ id: 'PROTOCOL_HANDLER_JS_CHECK', severity: 'LOW' }] },

  // Found scanning old releases with disclosed vulnerabilities (Joplin 2.8.8, MarkText 0.16.3)
  { practice: 'regression: TypeScript window options held in a typed variable', insecure: { 'src/app.ts': `class App {\n  createWindow() {\n    const windowOptions: any = { webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false } };\n    this.win_ = new BrowserWindow(windowOptions);\n  }\n}` },
    expect: [{ id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }, { id: 'CONTEXT_ISOLATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }, { id: 'WEB_SECURITY_JS_CHECK' }],
    secure: { 'src/app.ts': `const windowOptions: BrowserWindowConstructorOptions = { webPreferences: { contextIsolation: true, sandbox: true } };\nconst win = new BrowserWindow(windowOptions);` }, absent: ['NODE_INTEGRATION_JS_CHECK', 'CONTEXT_ISOLATION_JS_CHECK', 'SANDBOX_JS_CHECK'] },
  { practice: 'regression: contextIsolation from an unresolvable value is tentative', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { contextIsolation: config.isolate } });` },
    expect: [{ id: 'CONTEXT_ISOLATION_JS_CHECK', severity: 'HIGH', confidence: 'TENTATIVE' }] },
  { practice: 'regression: export-default-from syntax parses', insecure: { 'src/menu/index.js': `export edit from './edit';\nexport default function build() { return new BrowserWindow({ webPreferences: { nodeIntegration: true } }); }` },
    expect: [{ id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },

  { practice: 'regression: window options merged from shared defaults in another file (MarkText 0.16.3)', insecure: {
    'src/main/config.js': `export const editorWinOptions = Object.freeze({ minWidth: 550, webPreferences: { enableRemoteModule: true, contextIsolation: false, nodeIntegration: true, webSecurity: false } });`,
    'src/main/windows/editor.js': `import { BrowserWindow } from 'electron';\nimport { editorWinOptions } from '../config';\nexport function create(options) {\n  const winOptions = Object.assign({ width: 800 }, editorWinOptions, options);\n  return new BrowserWindow(winOptions);\n}` },
  version: '11.1.1',
  expect: [{ id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }, { id: 'CONTEXT_ISOLATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' },
    { id: 'WEB_SECURITY_JS_CHECK' }, { id: 'REMOTE_MODULE_JS_CHECK', confidence: 'CERTAIN' }] },
  { practice: 'regression: later spread and Object.assign sources override earlier ones', secure: {
    'main.js': `const base = { webPreferences: { nodeIntegration: true, contextIsolation: false } };\nconst a = new BrowserWindow({ ...base, webPreferences: { sandbox: true } });\nconst b = new BrowserWindow(Object.assign({}, base, { webPreferences: { ...base.webPreferences, nodeIntegration: false, contextIsolation: true } }));` },
  absent: ['NODE_INTEGRATION_JS_CHECK', 'CONTEXT_ISOLATION_JS_CHECK'] },
  { practice: 'regression: webPreferences spread from a constant', insecure: { 'main.js': `const unsafe = { nodeIntegration: true };\nconst w = new BrowserWindow({ webPreferences: { ...unsafe, preload: 'p.js' } });` },
    expect: [{ id: 'NODE_INTEGRATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: 'regression: remote module on by default before Electron 10', insecure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { nodeIntegration: false, preload: 'p.js' } });` }, version: '8.2.1',
    expect: [{ id: 'REMOTE_MODULE_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }],
    secure: { 'main.js': `const w = new BrowserWindow({ webPreferences: { enableRemoteModule: false, preload: 'p.js' } });` }, absent: ['REMOTE_MODULE_JS_CHECK'] },
  { practice: 'regression: deep link passed to a helper that loads it (Element 1.9.6, CVE-2022-23597)', insecure: { 'src/protocol.ts': `const PROTOCOL = 'element://';\nfunction processUrl(url: string): void {\n  global.mainWindow.loadURL(url.replace(PROTOCOL, 'vector://'));\n}\nexport function protocolInit(): void {\n  app.on('open-url', function(ev, url) { ev.preventDefault(); processUrl(url); });\n  app.on('second-instance', (ev, commandLine) => { const url = commandLine[commandLine.length - 1]; if (!url.startsWith(PROTOCOL)) return; processUrl(url); });\n}` },
    expect: [{ id: 'UNTRUSTED_LOAD_URL_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }],
    secure: { 'src/protocol.ts': `function processUrl(url: string): void {\n  const parsed = new URL(url);\n  if (parsed.protocol !== 'element:') return;\n  const urlToLoad = new URL('vector://vector/webapp/');\n  urlToLoad.hash = parsed.hash;\n  global.mainWindow.loadURL(urlToLoad.href);\n}\napp.on('open-url', (ev, url) => processUrl(url));` },
    absent: ['UNTRUSTED_LOAD_URL_JS_CHECK'] },
  { practice: 'regression: jQuery .html() sink and escaping undone by a renderer (Signal 1.10.0, CVE-2018-10994)', insecure: { 'js/views/message_view.js': `const escapedBody = _.escape(body);\nthis.$('.body').html(Signal.HTML.render(escapedBody));` },
    expect: [{ id: 'XSS_SINK_JS_CHECK', severity: 'MEDIUM', match: /\.html\(\)/ }],
    secure: { 'js/views/message_view.js': `this.$('.body').html(_.escape(body));\nthis.$('.title').html('<b>' + escapeHtml(title) + '</b>');\nlist.append(item);` }, absent: ['XSS_SINK_JS_CHECK'] },
  { practice: 'regression: HTML built into jQuery append', insecure: { 'renderer.js': `$('#list').append('<li>' + message.text + '</li>');` }, expect: [{ id: 'XSS_SINK_JS_CHECK', match: /\.append\(\)/ }] },
  { practice: 'regression: inline scripts in HTML files are analyzed (Joplin 2.8.8 note viewer)', insecure: { 'gui/note-viewer/index.html': `<html>\n<body>\n<div id="content"></div>\n<script>\n  ipcProxySendToHost('ready');\n  window.addEventListener('message', (event) => {\n    document.getElementById('content').innerHTML = event.data.html;\n  });\n</script>\n</body>\n</html>` },
    expect: [{ id: 'XSS_SINK_JS_CHECK', severity: 'MEDIUM' }],
    secure: { 'index.html': `<script type="text/x-template"><div>{{ html }}</div></script>\n<script type="application/json">{"a": 1}</script>\n<script>document.getElementById('x').textContent = name;</script>` }, absent: ['XSS_SINK_JS_CHECK'] },
  { practice: 'iframe without sandbox (HTML)', insecure: { 'index.html': `<iframe src="viewer.html"></iframe>` }, expect: [{ id: 'IFRAME_SANDBOX_HTML_CHECK', severity: 'LOW', confidence: 'CERTAIN' }],
    secure: { 'index.html': `<iframe src="viewer.html" sandbox="allow-scripts"></iframe>` }, absent: ['IFRAME_SANDBOX_HTML_CHECK'] },
  { practice: 'iframe sandbox with allow-scripts and allow-same-origin', insecure: { 'index.html': `<iframe src="viewer.html" sandbox="allow-scripts allow-same-origin"></iframe>` }, expect: [{ id: 'IFRAME_SANDBOX_HTML_CHECK', match: /allow-same-origin/ }] },
  { practice: 'iframe without sandbox (JSX, Joplin 2.8.8 NoteTextViewer)', insecure: { 'gui/NoteTextViewer.tsx': `export default function Viewer() { return <iframe className="noteTextViewer" src="gui/note-viewer/index.html"></iframe>; }` },
    expect: [{ id: 'IFRAME_SANDBOX_JS_CHECK', severity: 'LOW', confidence: 'CERTAIN' }],
    secure: { 'gui/Viewer.tsx': `export default function Viewer() { return <iframe sandbox="allow-scripts" src="viewer.html" />; }\nexport function Frame(props) { return <iframe {...props} />; }` }, absent: ['IFRAME_SANDBOX_JS_CHECK'] },

  { practice: 'regression: passing the IPC event is low severity once Electron 29 strips ipcRenderer from contextBridge', secure: { 'preload.js': `contextBridge.exposeInMainWorld('electronAPI', { onUpdate: (callback) => ipcRenderer.on('update', callback) });` },
    expectSecure: [{ id: 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', severity: 'LOW', match: /Electron 29/ }] },
  { practice: 'regression: channels checked by a validation helper (VS Code preload)', secure: { 'preload.ts': `function validateIPC(channel: string): true | never {\n  if (!channel?.startsWith('vscode:')) throw new Error('Unsupported channel');\n  return true;\n}\nconst globals = { ipcRenderer: {\n  invoke(channel: string, ...args: unknown[]) { validateIPC(channel); return ipcRenderer.invoke(channel, ...args); },\n  send(channel: string, ...args: unknown[]) { if (validateIPC(channel)) { ipcRenderer.send(channel, ...args); } }\n} };\ncontextBridge.exposeInMainWorld('vscode', globals);` },
    absent: [], expectSecure: [{ id: 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', severity: 'LOW' }] },

  { practice: 'regression: navigation helper checking a destructured protocol (Signal Desktop handleUrl)', secure: { 'main.ts': `async function handleUrl(rawTarget: string) {\n  const parsedUrl = maybeParseUrl(rawTarget);\n  if (!parsedUrl) return;\n  const { protocol } = parsedUrl;\n  if (protocol === 'http:' || protocol === 'https:') await shell.openExternal(rawTarget);\n}\nfunction setup(window) {\n  window.webContents.on('will-navigate', (event, rawTarget) => { event.preventDefault(); drop(handleUrl(rawTarget)); });\n}` },
    absent: [], expectSecure: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'LOW' }] },

  { practice: 'regression: bower packages and copied libraries are skipped (Signal 1.10.0)', secure: {
    '.bowerrc': '{ "directory": "components/" }', 'components/mocha/mocha.js': `div.innerHTML = html;`, 'lib/other/.bower.json': '{}', 'lib/other/index.js': `div.innerHTML = html;`,
    'js/jquery.js': `/*!\n * jQuery JavaScript Library v2.1.1-pre\n * Copyright 2005, 2014 jQuery Foundation, Inc. and other contributors\n * Released under the MIT license\n */\nelem.innerHTML = value;` },
  absent: ['XSS_SINK_JS_CHECK'] },
  { practice: 'regression: app files with their own banner are still scanned', insecure: { 'dist/main.js': `/*! MyApp v1.2.3 | (c) 2024 Me | MIT license */\nelem.innerHTML = value;` },
    expect: [{ id: 'XSS_SINK_JS_CHECK' }] },

  { practice: 'cross-file: deep link passed to a helper in another file', insecure: {
    'src/main.ts': `import { openLink } from './links';\napp.on('open-url', (event, url) => { event.preventDefault(); openLink(url); });`,
    'src/links.ts': `export function openLink(target: string) {\n  shell.openExternal(target);\n}` },
  expect: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'HIGH', confidence: 'FIRM', match: /deep link/ }] },
  { practice: 'cross-file: IPC data passed through two helpers before reaching exec', insecure: {
    'src/main.js': `const { runTool } = require('./tools');\nipcMain.handle('run', (event, name) => runTool(name));`,
    'src/tools.js': `const { exec } = require('child_process');\nfunction buildCommand(tool) { return launch('tool ' + tool); }\nfunction launch(command) { exec(command); }\nfunction runTool(name) { return buildCommand(name); }\nmodule.exports = { runTool };` },
  expect: [{ id: 'COMMAND_INJECTION_JS_CHECK', severity: 'HIGH', match: /IPC message/ }] },
  { practice: 'cross-file: helpers called only with trusted data stay unflagged', secure: {
    'src/main.ts': `import { openLink } from './links';\nipcMain.handle('help', () => openLink('https://example.com/help'));`,
    'src/links.ts': `export function openLink(target: string) {\n  shell.openExternal(target);\n}` },
  absent: [], expectSecure: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'LOW', confidence: 'FIRM', match: /every caller/ }] },
  { practice: 'cross-file: helpers passed around as callbacks are not assumed trusted', secure: {
    'src/main.ts': `import { openLink } from './links';\nopenLink('https://example.com/help');\nlinks.forEach(openLink);`,
    'src/links.ts': `export function openLink(target: string) {\n  shell.openExternal(target);\n}` },
  absent: [], expectSecure: [{ id: 'OPEN_EXTERNAL_JS_CHECK', severity: 'MEDIUM', confidence: 'TENTATIVE' }] },

  { practice: 'unsandboxed iframe in an app with nodeIntegration is raised (Joplin 2.8.8)', insecure: {
    'main.js': `const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });`,
    'gui/NoteTextViewer.jsx': `export default function Viewer() { return <iframe className="noteTextViewer" src="gui/note-viewer/index.html"></iframe>; }` },
  expect: [{ id: 'IFRAME_SANDBOX_JS_CHECK', severity: 'MEDIUM', confidence: 'CERTAIN', match: /parent\.require/ }] },

  // AngularJS configuration
  { practice: 'AngularJS $sce disabled', insecure: { 'app.js': `angular.module('app', []).config(function ($sceProvider) { $sceProvider.enabled(false); });` },
    expect: [{ id: 'ANGULAR_SCE_DISABLED_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }],
    secure: { 'app.js': `angular.module('app', []).config(function ($sceProvider) { $sceProvider.enabled(true); });` }, absent: ['ANGULAR_SCE_DISABLED_JS_CHECK'] },
  { practice: 'AngularJS resource URL allowlist with wildcards', insecure: { 'app.js': `app.config(function ($sceDelegateProvider) { $sceDelegateProvider.resourceUrlWhitelist(['self', '**']); });` },
    expect: [{ id: 'ANGULAR_RESOURCE_URL_LIST_JS_CHECK', severity: 'MEDIUM', confidence: 'CERTAIN' }],
    secure: { 'app.js': `app.config(function ($sceDelegateProvider) { $sceDelegateProvider.trustedResourceUrlList(['self', 'https://cdn.example.com/templates/**']); });` }, absent: ['ANGULAR_RESOURCE_URL_LIST_JS_CHECK'] },

  // End-of-life frontend libraries
  { practice: 'end-of-life libraries in the lockfile', insecure: {
    'package.json': JSON.stringify({ name: 'app', dependencies: { angular: '1.8.3', jquery: '2.2.4' }, devDependencies: { electron: '38.2.0', bootstrap: '4.6.2' } }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/angular': { version: '1.8.3' }, 'node_modules/jquery': { version: '2.2.4' }, 'node_modules/bootstrap': { version: '4.6.2', dev: true } } }) },
  expect: [{ id: 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity: 'MEDIUM', confidence: 'CERTAIN', match: /angular@1\.8\.3.*AngularJS/ }, { id: 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity: 'MEDIUM', match: /jquery@2\.2\.4/ },
    { id: 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity: 'LOW', match: /bootstrap@4\.6\.2 \(dev\).*2023-01-01/ }],
  secure: {
    'package.json': JSON.stringify({ name: 'app', dependencies: { jquery: '3.7.1', bootstrap: '5.3.3' }, devDependencies: { electron: '38.2.0' } }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/jquery': { version: '3.7.1' }, 'node_modules/bootstrap': { version: '5.3.3' } } }) },
  absent: ['END_OF_LIFE_LIBRARY_GLOBAL_CHECK'] },
  { practice: 'copies of libraries bundled with the app are inventoried', insecure: {
    'app/lib/angular.js': `/**\n * @license AngularJS v1.5.8\n * (c) 2010-2016 Google, Inc. http://angularjs.org\n * License: MIT\n */\nelement.innerHTML = value;` },
  expect: [{ id: 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity: 'MEDIUM', match: /angular@1\.5\.8 \(copy bundled with the app\)/ }] },
  { practice: 'bower packages are inventoried', insecure: { 'components/jquery/.bower.json': JSON.stringify({ name: 'jquery', version: '2.1.1' }), 'components/jquery/dist/jquery.js': `x.innerHTML = y;` },
    expect: [{ id: 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity: 'MEDIUM', match: /jquery@2\.1\.1/ }] },

  // Renderer attack surface inventory
  { practice: 'window settings summary uses the version defaults', secure: { 'main.js': `const a = new BrowserWindow({ width: 800 });\nconst b = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, preload: 'preload.js' } });\nfunction make(options) { return new BrowserWindow(options); }` },
    absent: [], expectSecure: [
      { id: 'WINDOW_SUMMARY_JS_CHECK', severity: 'INFORMATIONAL', confidence: 'CERTAIN', match: /BrowserWindow \(nodeIntegration off \(default\), contextIsolation on \(default\), sandbox on \(default\), webSecurity on \(default\)\)/ },
      { id: 'WINDOW_SUMMARY_JS_CHECK', match: /nodeIntegration on, contextIsolation off, sandbox off \(default\), webSecurity on \(default\), preload preload\.js/ },
      { id: 'WINDOW_SUMMARY_JS_CHECK', match: /nodeIntegration unknown/ }] },
  { practice: 'APIs exposed through contextBridge are listed', secure: { 'preload.js': `const api = { openFile: (id) => ipcRenderer.invoke('open-file', id), settings: { get: () => ipcRenderer.invoke('settings:get') } };\ncontextBridge.exposeInMainWorld('app', api);` },
    absent: [], expectSecure: [{ id: 'EXPOSED_API_JS_CHECK', severity: 'INFORMATIONAL', confidence: 'CERTAIN', match: /window\.app \(openFile, settings\.get\)/ }] },

  // Cross-file analysis
  { practice: 'cross-file: imported IPC handler without sender validation', insecure: { 'src/main.ts': `import { getSecrets } from './handlers';\nipcMain.handle('get-secrets', getSecrets);`,
    'src/handlers.ts': `export function getSecrets(event: IpcMainInvokeEvent) { return store.secrets; }` },
  expect: [{ id: 'IPC_SENDER_VALIDATION_JS_CHECK', severity: 'MEDIUM', confidence: 'FIRM' }] },
  { practice: 'cross-file: imported IPC handler validating the sender', secure: { 'src/main.ts': `import { getSecrets } from './handlers/index.js';\nipcMain.handle('get-secrets', getSecrets);`,
    'src/handlers/index.ts': `export * from './secrets';`,
    'src/handlers/secrets.ts': `export const getSecrets = (event) => { if (!isTrusted(event.senderFrame)) return null; return store.secrets; };` },
  absent: ['IPC_SENDER_VALIDATION_JS_CHECK'] },
  { practice: 'cross-file: CommonJS handler modules', insecure: { 'main.js': `const handlers = require('./handlers');\nconst { onOpen } = require('./handlers');\nipcMain.on('open', onOpen);`,
    'handlers.js': `function onOpen(event, url) { shell.openExternal(url); }\nmodule.exports = { onOpen };` },
  expect: [{ id: 'IPC_SENDER_VALIDATION_JS_CHECK', confidence: 'FIRM' }] },
  { practice: 'cross-file: imported URL constants', secure: { 'main.ts': `import { RELEASE_NOTES } from './constants';\nimport * as urls from './urls';\nshell.openExternal(RELEASE_NOTES);\nshell.openExternal(urls.HELP);`,
    'constants.ts': `const HOST = 'https://example.com';\nexport const RELEASE_NOTES = \`\${HOST}/releases\`;`,
    'urls.ts': `export const HELP = 'https://example.com/help';` },
  absent: ['OPEN_EXTERNAL_JS_CHECK'] },
  { practice: 'cross-file: imported navigation helper that blocks', secure: { 'main.js': `${HARDENING}\nimport { onNavigate } from './navigation.js';\ncontents.on('will-navigate', (ev, url) => onNavigate(ev, url));`,
    'navigation.js': `export function onNavigate(ev, url) { if (!url.startsWith('app://')) ev.preventDefault(); }` },
  absent: ['LIMIT_NAVIGATION_GLOBAL_CHECK'], expectSecure: [{ id: 'LIMIT_NAVIGATION_JS_CHECK', severity: 'LOW' }] },
  { practice: 'cross-file: constants chosen by a ternary', secure: { 'main.ts': `import { ReleaseNotesUri } from './releases';\nshell.openExternal(ReleaseNotesUri);`,
    'releases.ts': `export const ReleaseNotesUri = __CHANNEL__ === 'beta' ? 'https://example.com/notes/?env=beta' : 'https://example.com/notes/';` },
  absent: ['OPEN_EXTERNAL_JS_CHECK'] },
  { practice: 'cross-file: handler factories', insecure: { 'main.ts': `import { makeNavigate } from './events';\ncontents.setWindowOpenHandler(() => ({ action: 'deny' }));\ncontents.on('will-navigate', makeNavigate(log));`,
    'events.ts': `export const makeNavigate = (log) => (event, url) => { log.info(url); };` },
  expect: [{ id: 'LIMIT_NAVIGATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: 'cross-file: tsconfig baseUrl and paths aliases', secure: { 'tsconfig.json': `{\n  // comments are allowed\n  "compilerOptions": { "baseUrl": "./src", "paths": { "@lib/*": ["lib/*"] }, },\n}`,
    'src/main/index.ts': `import { getVersion } from 'main/handlers';\nimport { HELP } from '@lib/urls';\nipcMain.handle('version', getVersion);\nshell.openExternal(HELP);`,
    'src/main/handlers.ts': `export function getVersion(event) { if (!trusted(event.senderFrame)) return; return '1.0'; }`,
    'src/lib/urls.ts': `export const HELP = 'https://example.com/help';` },
  absent: ['IPC_SENDER_VALIDATION_JS_CHECK', 'OPEN_EXTERNAL_JS_CHECK'] },
  { practice: 'TypeScript: local handler variables and factories', insecure: { 'main.ts': `class Popups {\n  attach(contents: WebContents) {\n    const willNavigate = this.makeNavigate(contents.id);\n    contents.setWindowOpenHandler(() => ({ action: 'deny' }));\n    contents.on('will-navigate', willNavigate);\n  }\n  private makeNavigate = (id: number) => (event: Event, url: string) => { log(id, url); };\n}` },
    expect: [{ id: 'LIMIT_NAVIGATION_JS_CHECK', severity: 'HIGH', confidence: 'CERTAIN' }] },
  { practice: 'cross-file: imported shell commands', secure: { 'main.js': `const { exec } = require('child_process');\nconst { READ_DND } = require('./commands');\nexec(READ_DND);`,
    'commands.js': `exports.READ_DND = 'gsettings get org.gnome.desktop.notifications show-banners';` },
  absent: ['COMMAND_INJECTION_JS_CHECK'] },
];

describe('Electron security checklist coverage', () => {
  for (const c of CASES) {
    describe(c.practice, () => {
      if (c.insecure) {
        it('reports the insecure pattern', async () => {
          const issues = await scan(c.insecure, { electronVersion: c.version });
          for (const expectation of c.expect) expectFinding(issues, expectation);
        });
      }
      if (c.secure) {
        it('does not report the secure pattern', async () => {
          const issues = await scan(c.secure, { electronVersion: c.version });
          for (const id of c.absent || []) expectNoFinding(issues, id);
          for (const expectation of c.expectSecure || []) expectFinding(issues, expectation);
        });
      }
    });
  }
});
