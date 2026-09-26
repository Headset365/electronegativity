// Turns the log written by hook.cjs during a watch session into findings, in the same shape as the static ones.
import fs from 'node:fs';
import { severity, confidence } from '../finder/attributes.js';

const DOCS = 'https://www.electronjs.org/docs/latest/tutorial/security';
const LOCAL_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/;
const EXECUTABLE = /\.(exe|bat|cmd|com|scr|msi|ps1|vbs|js|jse|wsf|hta|lnk|jar|app|command|sh|desktop|appimage|dmg|pkg)$/i;
const SAFE_EXTERNAL = /^(https?|mailto):/i;
const INTERNAL_PAGES = /^(about:|devtools:|chrome:|chrome-extension:)/i;

export function readWatchLog(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => {
    try {
      return JSON.parse(line);
    } catch {
      return undefined;
    }
  }).filter(Boolean);
}

const origin = (url) => {
  if (/^data:/i.test(url || '')) return url; // recorded as data:<type>,…
  try {
    const parsed = new URL(url);
    return parsed.origin !== 'null' ? parsed.origin : `${parsed.protocol}//${parsed.pathname.split('/').slice(0, -1).join('/')}`;
  } catch {
    return url;
  }
};
const hostOf = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
};

/**
 * @returns {{ issues: Array, summary: { started, windows, channels, unusedChannels, pages } }}
 */
export function analyzeWatchLog(records) {
  const issues = [];
  const add = (id, url, sev, conf, description, properties, reference = DOCS) => issues.push({
    file: url || 'runtime', sample: '', location: { line: 0, column: 0 }, id, description, properties, shortenedURL: reference,
    severity: sev, confidence: conf, manualReview: sev !== severity.INFORMATIONAL && conf !== confidence.CERTAIN,
    visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime'
  });
  const once = new Set();
  const first = (key) => !once.has(key) && once.add(key);

  const started = records.some(r => r.kind === 'start');
  const pages = records.filter(r => r.kind === 'page' && !INTERNAL_PAGES.test(r.url));
  const prefsById = new Map(pages.map(p => [p.id, p.prefs || {}]));
  // preload scripts captured where each window was constructed (getLastWebPreferences() omits them)
  const preloadByContents = new Map();
  for (const r of records.filter(r => r.kind === 'window')) if (r.id !== undefined && r.preload) preloadByContents.set(r.id, r.preload);

  // what each window really ran with
  for (const page of pages) {
    const prefs = page.prefs || {};
    const where = origin(page.url);
    const settings = Object.fromEntries(['nodeIntegration', 'contextIsolation', 'sandbox', 'webSecurity'].map(name => [name, { value: prefs[name], source: 'observed' }]));
    const preload = prefs.preload || preloadByContents.get(page.id);
    if (first(`window:${page.id}:${where}`))
      add('RUNTIME_WINDOW_SUMMARY', page.url, severity.INFORMATIONAL, confidence.CERTAIN, `Window observed at runtime: ${page.type} showing ${page.url}`,
        { window: page.type, settings, preload, url: page.url, webContents: page.id });
    if (prefs.nodeIntegration === true && prefs.sandbox !== true && first(`node:${where}`))
      add('RUNTIME_NODE_INTEGRATION', page.url, severity.HIGH, confidence.CERTAIN, `A page ran with Node.js integration: ${page.url} (nodeIntegration on, not sandboxed)`, undefined, `${DOCS}#2-do-not-enable-nodejs-integration-for-remote-content`);
    if (prefs.contextIsolation === false && first(`isolation:${where}`))
      add('RUNTIME_CONTEXT_ISOLATION', page.url, severity.HIGH, confidence.CERTAIN, `A page ran without context isolation: ${page.url}`, undefined, `${DOCS}#3-enable-context-isolation`);
    if (prefs.webSecurity === false && first(`websecurity:${where}`))
      add('RUNTIME_WEB_SECURITY', page.url, severity.MEDIUM, confidence.CERTAIN, `A page ran with webSecurity disabled: ${page.url}`, undefined, `${DOCS}#6-do-not-disable-websecurity`);
    if (prefs.allowRunningInsecureContent === true && first(`insecure:${where}`))
      add('RUNTIME_WEB_SECURITY', page.url, severity.MEDIUM, confidence.CERTAIN, `A page ran with allowRunningInsecureContent: ${page.url}`, undefined, `${DOCS}#8-do-not-enable-allowrunninginsecurecontent`);
    if (prefs.sandbox === false && prefs.nodeIntegration !== true && first(`sandbox:${where}`))
      add('RUNTIME_SANDBOX', page.url, severity.MEDIUM, confidence.CERTAIN, `A page ran without the renderer sandbox: ${page.url}`, undefined, `${DOCS}#4-enable-process-sandboxing`);
  }

  // Content Security Policy each document actually got, from its response header or a <meta> tag
  const headerCsp = new Map();
  for (const r of records) if (r.kind === 'response' && r.resourceType === 'mainFrame') headerCsp.set(`${r.webContents}:${r.url}`, r.csp);
  for (const meta of records.filter(r => r.kind === 'page-meta-csp' && !INTERNAL_PAGES.test(r.url))) {
    const policy = meta.csp || headerCsp.get(`${meta.id}:${meta.url}`);
    if (!policy) {
      if (first(`csp:${origin(meta.url)}`))
        add('RUNTIME_CSP', meta.url, severity.MEDIUM, confidence.CERTAIN, `A page was shown without a Content Security Policy: ${meta.url}`, undefined, `${DOCS}#7-define-a-content-security-policy`);
    } else if (/'unsafe-(inline|eval)'/.test(scriptPolicy(policy)) && first(`csp-weak:${origin(meta.url)}`)) {
      add('RUNTIME_CSP', meta.url, severity.LOW, confidence.CERTAIN, `The Content Security Policy of ${meta.url} allows inline scripts or eval: ${scriptPolicy(policy)}`, { policy }, `${DOCS}#7-define-a-content-security-policy`);
    }
  }

  // anything fetched over plain http, except the local machine
  for (const r of records.filter(r => r.kind === 'response' && /^http:/i.test(r.url) && !LOCAL_HOSTS.test(hostOf(r.url)))) {
    if (!first(`http:${origin(r.url)}:${r.resourceType}`)) continue;
    const nodeWindow = (prefsById.get(r.webContents) || {}).nodeIntegration === true;
    add('RUNTIME_INSECURE_LOAD', r.url, nodeWindow ? severity.HIGH : severity.MEDIUM, confidence.CERTAIN,
      `Content was loaded over unencrypted http (${r.resourceType})${nodeWindow ? ' into a window with Node.js integration' : ''}: ${r.url}`, undefined, `${DOCS}#1-only-load-secure-content`);
  }

  // navigation away from the origin a window started on, and new windows showing web content
  const startOrigin = new Map();
  for (const r of records.filter(r => r.kind === 'did-navigate' && !INTERNAL_PAGES.test(r.url))) {
    if (!startOrigin.has(r.id)) {
      startOrigin.set(r.id, origin(r.url));
      continue;
    }
    if (origin(r.url) !== startOrigin.get(r.id) && /^https?:/i.test(r.url) && first(`nav:${r.id}:${origin(r.url)}`))
      add('RUNTIME_NAVIGATION', r.url, severity.MEDIUM, confidence.FIRM, `A window navigated from ${startOrigin.get(r.id)} to another origin: ${r.url}; check that will-navigate limits navigation`, undefined, `${DOCS}#13-disable-or-limit-navigation`);
  }
  for (const r of records.filter(r => r.kind === 'child-window' && /^https?:/i.test(r.url || '') && !LOCAL_HOSTS.test(hostOf(r.url)))) {
    if (first(`child:${origin(r.url)}`))
      add('RUNTIME_NEW_WINDOW', r.url, severity.MEDIUM, confidence.FIRM, `A new app window was opened for web content: ${r.url}; check what setWindowOpenHandler allows`, undefined, `${DOCS}#14-disable-or-limit-creation-of-new-windows`);
  }
  for (const r of records.filter(r => r.kind === 'webview' && !r.prevented)) {
    const prefs = r.prefs || {};
    const sev = prefs.nodeIntegration === true ? severity.HIGH : prefs.preload ? severity.MEDIUM : severity.LOW;
    if (first(`webview:${origin(r.src)}:${sev.name}`))
      add('RUNTIME_WEBVIEW', r.src, sev, confidence.CERTAIN, `A <webview> was attached for ${r.src}${prefs.nodeIntegration === true ? ' with Node.js integration' : prefs.preload ? ` with the preload script ${prefs.preload}` : ''}`, undefined, `${DOCS}#12-verify-webview-options-before-creation`);
  }

  // what the app opened outside itself
  for (const r of records.filter(r => r.kind === 'shell')) {
    if (!first(`shell:${r.method}:${r.target}`)) continue;
    if (r.method === 'openExternal') {
      if (SAFE_EXTERNAL.test(r.target)) add('RUNTIME_OPEN_EXTERNAL', r.target, severity.INFORMATIONAL, confidence.CERTAIN, `shell.openExternal opened ${r.target}`);
      else add('RUNTIME_OPEN_EXTERNAL', r.target, severity.HIGH, confidence.CERTAIN, `shell.openExternal was called with a non-web URL: ${r.target}; only http(s) and mailto links should reach it`, undefined, `${DOCS}#15-do-not-use-shellopenexternal-with-untrusted-content`);
    } else {
      const risky = EXECUTABLE.test(r.target);
      add('RUNTIME_OPEN_PATH', r.target, risky ? severity.HIGH : severity.INFORMATIONAL, confidence.CERTAIN,
        `shell.${r.method} was called with ${risky ? 'an executable file type' : 'a file'}: ${r.target}`, undefined, 'https://www.electronjs.org/docs/latest/api/shell');
    }
  }

  // permission requests: without a handler of the app's own, Electron grants them all
  for (const r of records.filter(r => r.kind === 'permission' && r.granted)) {
    if (!first(`perm:${r.permission}:${origin(r.origin)}`)) continue;
    if (r.default) add('RUNTIME_PERMISSION', r.origin, severity.MEDIUM, confidence.CERTAIN, `The '${r.permission}' permission was granted to ${r.origin} automatically, as the app has no permission request handler`, undefined, `${DOCS}#5-handle-session-permission-requests-from-remote-content`);
    else add('RUNTIME_PERMISSION', r.origin, severity.INFORMATIONAL, confidence.CERTAIN, `The app's permission handler granted '${r.permission}' to ${r.origin}`);
  }
  // synchronous permission checks (setPermissionCheckHandler): without a handler of the app's own, Electron allows them
  for (const r of records.filter(r => r.kind === 'permission-check' && r.granted)) {
    if (!first(`permcheck:${r.permission}:${origin(r.origin)}`)) continue;
    if (r.default) add('RUNTIME_PERMISSION_CHECK', r.origin, severity.MEDIUM, confidence.CERTAIN, `The '${r.permission}' permission check was allowed for ${r.origin} automatically, as the app has no setPermissionCheckHandler`, undefined, `${DOCS}#5-handle-session-permission-requests-from-remote-content`);
    else add('RUNTIME_PERMISSION_CHECK', r.origin, severity.INFORMATIONAL, confidence.CERTAIN, `The app's permission check handler allowed '${r.permission}' for ${r.origin}`);
  }
  // what the renderer-side observer saw inside pages: script-bearing DOM changes, and planted-marker reflections
  for (const r of records.filter(r => r.kind === 'dom-observed')) {
    if (r.event === 'marker') {
      if (!first(`marker:${origin(r.url)}:${r.live}`)) continue;
      if (r.live) add('RUNTIME_MARKER', r.url, severity.HIGH, confidence.FIRM, `Planted marker content came back rendered as live HTML at ${r.url}: stored input reaches another view without being neutralized (the stored-content threat)`, { marker: r.detail, live: true }, `${DOCS}#7-define-a-content-security-policy`);
      else add('RUNTIME_MARKER', r.url, severity.INFORMATIONAL, confidence.CERTAIN, `Planted marker appeared as text (escaped) at ${r.url}`, { marker: r.detail, live: false });
      continue;
    }
    // script-bearing insertions: on* handlers and javascript: URLs are strong injection signals; plain <script> tags
    // are too common in normal apps (code splitting) to report on their own
    if ((r.event === 'event-handler' || r.event === 'javascript-url') && first(`dom:${origin(r.url)}:${r.event}:${r.detail}`))
      add('RUNTIME_DOM_INJECTION', r.url, severity.LOW, confidence.FIRM, `Script was inserted into the page at runtime (${r.event}${r.detail ? ' ' + r.detail : ''}) at ${r.url}; check that untrusted input cannot reach this sink`, { event: r.event, detail: r.detail }, `${DOCS}#7-define-a-content-security-policy`);
  }
  for (const r of records.filter(r => r.kind === 'certificate-error')) {
    if (first(`cert:${origin(r.url)}`))
      add('RUNTIME_CERTIFICATE_ERROR', r.url, severity.LOW, confidence.FIRM, `A certificate error occurred for ${r.url} (${r.error}); check that the app rejected the connection`, undefined, 'https://www.electronjs.org/docs/latest/api/app#event-certificate-error');
  }

  // IPC: which channels pages used, from which origins, and which were never exercised
  const registered = new Map();
  for (const r of records.filter(r => r.kind === 'ipc-register')) registered.set(r.channel, r.mode);
  const used = new Map();
  for (const r of records.filter(r => r.kind === 'ipc')) {
    if (!used.has(r.channel)) used.set(r.channel, new Set());
    if (r.sender) used.get(r.channel).add(origin(r.sender));
  }
  for (const [channel, senders] of used) {
    add('RUNTIME_IPC', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN, `IPC channel '${channel}' was used by ${[...senders].join(', ') || 'a renderer'}`, { channel, senders: [...senders] });
  }
  const unusedChannels = [...registered.keys()].filter(channel => !used.has(channel));
  if (unusedChannels.length > 0)
    add('RUNTIME_COVERAGE', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      `${unusedChannels.length} of ${registered.size} IPC channels registered by the app were not used during the session: ${unusedChannels.join(', ')}`, { unusedChannels });

  return { issues, summary: { started, windows: new Set(pages.map(p => p.id)).size, pages: pages.length, channels: registered.size, usedChannels: used.size, unusedChannels } };
}

// script-src, or default-src when there is none
function scriptPolicy(policy) {
  const directives = policy.split(';').map(d => d.trim());
  return directives.find(d => /^script-src\s/i.test(d)) || directives.find(d => /^default-src\s/i.test(d)) || '';
}
