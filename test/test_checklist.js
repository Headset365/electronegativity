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
    expect: [{ id: 'OPEN_EXTERNAL_JS_CHECK', confidence: 'CERTAIN' }] },
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
  { practice: '#20 passing the IPC event to the page', insecure: { 'preload.js': `contextBridge.exposeInMainWorld('electronAPI', { onUpdate: (callback) => ipcRenderer.on('update', callback) });` },
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
  { practice: 'command injection from IPC', insecure: { 'main.js': `ipcMain.handle('ping', (event, host) => exec('ping -c 1 ' + host));` },
    expect: [{ id: 'COMMAND_INJECTION_JS_CHECK', severity: 'HIGH', confidence: 'FIRM' }],
    secure: { 'main.js': `ipcMain.handle('ping', (event, host) => execFile('ping', ['-c', '1', host]));` }, absent: ['COMMAND_INJECTION_JS_CHECK'] },
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
