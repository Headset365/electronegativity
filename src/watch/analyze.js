// Turns the log written by hook.cjs during a watch session into findings, in the same shape as the static ones.
import fs from 'node:fs';
import { severity, confidence } from '../finder/attributes.js';
import { trafficIssues } from '../traffic/ingest.js';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { EXECUTION } = require('./campaign.cjs');

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
  const activeSent = records.filter(r => r.kind === 'active-payload-sent');
  const executed = records.filter(r => r.kind === 'active-payload-executed');
  for (const r of executed) if (first(`active:${r.id}:${r.url}`))
    add('RUNTIME_ACTIVE_SCRIPT', r.url, severity.MEDIUM, confidence.FIRM,
      `A benign event-handler probe executed script in this renderer. The log does not establish which save route supplied it or whether a second account can reach it`,
      { webContents: r.id, execution: 'observed' }, `${DOCS}#7-define-a-content-security-policy`);
  if (activeSent.length && !executed.length)
    add('RUNTIME_ACTIVE_COVERAGE', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      `${activeSent.length} benign execution probe(s) were accepted by save requests, but no execution signal appeared in the watched pages. The content may not have been viewed; this is not a safe verdict`,
      { sent: activeSent.length, execution: 'not observed' });
  const campaignCases = [];
  for (const sent of records.filter(r => r.kind === 'campaign-send')) {
    const ambiguous = !sent.campaignId && records.filter(r => r.kind === 'campaign-send' && r.case === sent.case && r.slot === sent.slot && !r.campaignId).length > 1;
    const same = r => !ambiguous && r.case === sent.case && r.slot === sent.slot && r.campaignId === sent.campaignId;
    const views = records.filter(r => r.kind === 'campaign-view' && same(r));
    const signals = records.filter(r => r.kind === 'campaign-result' && same(r));
    const resources = records.filter(r => r.kind === 'campaign-resource' && same(r));
    const action = records.find(r => r.kind === 'campaign-action' && same(r));
    const execution = signals.some(r => r.signal === 'executed');
    const delivery = sent.ok ? 'accepted' : sent.status ? 'rejected' : 'failed';
    const view = views.some(r => r.opened) ? 'opened' : 'not observed';
    const verification = records.find(r => r.kind === 'campaign-verification' && same(r));
    const caseState = { campaignId: sent.campaignId, correlation: ambiguous ? 'ambiguous' : 'matched-case', savedValue: verification?.verification || 'not verified', case: sent.case, field: sent.field, slot: sent.slot, delivery, view,
      action: action ? { clicked: action.clicked, navigated: action.navigated, url: action.url } : undefined,
      execution: EXECUTION.has(sent.case) ? (execution ? 'observed' : 'not observed') : 'not applicable',
      resources: resources.map(r => r.resource),
      signals: [...new Set(signals.map(r => r.signal))] };
    campaignCases.push(caseState);
    add('RUNTIME_CAMPAIGN_CASE', sent.route || 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      `Campaign ${sent.case}${sent.field ? ` in ${sent.field}` : ''}: request ${delivery}${sent.status ? ` (HTTP ${sent.status})` : ''}, saved view ${view}, script ${caseState.execution}${resources.length ? `, local resource requests ${resources.length}` : ''}. Silence is not a safe verdict`,
      caseState);
    if (!sent.ok) continue;
    for (const resource of resources)
      add('RUNTIME_CAMPAIGN_RESOURCE', 'http://127.0.0.1', severity.INFORMATIONAL, confidence.CERTAIN,
        `The configured ${sent.case} payload caused a request to the tool's loopback ${resource.resource} receiver. This does not establish which process sent it, access to other internal services or response readability`,
        { case: sent.case, resource: resource.resource, cookiePresent: resource.cookiePresent, authorizationPresent: resource.authorizationPresent });
    if (sent.case === 'api-loopback-url' && resources.length)
      add('RUNTIME_CAMPAIGN_API_EFFECT', 'http://127.0.0.1', severity.INFORMATIONAL, confidence.FIRM,
        'The configured page API call was followed by a request to its unique loopback URL; this verifies a network effect, not IPC authorization or access to other hosts',
        { case: sent.case, field: sent.field, slot: sent.slot });
    if (sent.case.startsWith('nav-'))
      add('RUNTIME_CAMPAIGN_NAVIGATION', action?.url || sent.route || 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
        `${sent.case}: link ${action?.clicked ? 'clicked' : 'not confirmed clicked'}, Electron window ${action?.navigated ? 'changed URL' : 'did not show a URL change'}, loopback receiver ${resources.length ? 'received a request' : 'did not observe a request'}. OS handoff and policy enforcement require separate evidence`,
        { case: sent.case, field: sent.field, slot: sent.slot, clicked: !!action?.clicked, navigated: !!action?.navigated, requests: resources.length });
    for (const [name, signal] of [['cookie-canary', 'cookie-canary-read'], ['localstorage-canary', 'localstorage-canary-read'],
      ['indexeddb-canary', 'indexeddb-canary-read']]) if (sent.case === name && signals.some(r => r.signal === signal))
      add('RUNTIME_CAMPAIGN_DATA_CANARY', signals.find(r => r.signal === signal).url, severity.INFORMATIONAL, confidence.FIRM,
        `The configured document script read the tool's own ${name} value in this origin. This does not demonstrate access to authentication data or another origin`,
        { case: name, field: sent.field, slot: sent.slot });
    if (sent.case.startsWith('api-') && signals.some(r => r.signal === 'api-invoked'))
      add('RUNTIME_CAMPAIGN_API', signals.find(r => r.signal === 'api-invoked').url, severity.INFORMATIONAL, confidence.CERTAIN,
        `The ${sent.case} probe called a configured page API; ${signals.some(r => r.signal === 'api-resolved') ? 'the call resolved' : signals.some(r => r.signal === 'api-rejected') ? 'the call rejected' : 'the outcome was not observed'}. No IPC authorization or privileged effect is inferred from the call result`,
        { case: sent.case, outcome: signals.some(r => r.signal === 'api-resolved') ? 'resolved' : signals.some(r => r.signal === 'api-rejected') ? 'rejected' : 'unknown' });
    if (execution && EXECUTION.has(sent.case))
      add('RUNTIME_CAMPAIGN_SCRIPT', signals[0]?.url || 'runtime', severity.MEDIUM, confidence.FIRM,
        `The ${sent.case} probe executed through a configured save/view workflow. Account boundaries and exposed privileges require separate evidence`,
        { case: sent.case, delivery, view, execution: 'observed' });
    for (const [signal, id, sev] of [['fs-read', 'RUNTIME_CAMPAIGN_FS_READ', severity.HIGH],
      ['node-available', 'RUNTIME_CAMPAIGN_NODE', severity.LOW], ['electron-available', 'RUNTIME_CAMPAIGN_ELECTRON', severity.MEDIUM],
      ['eval-allowed', 'RUNTIME_CAMPAIGN_EVAL', severity.LOW]]) if (signals.some(r => r.signal === signal))
      add(id, signals.find(r => r.signal === signal).url, sev, confidence.FIRM,
        signal === 'fs-read' ? 'Renderer script read a unique, tool-created file canary through Node fs' :
          `${sent.case} probe reported ${signal} in the page world; assess the window and origin`,
        { case: sent.case, signal, delivery });
  }
  for (const error of records.filter(r => r.kind === 'campaign-error'))
    add('RUNTIME_CAMPAIGN_COVERAGE', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      `Campaign incomplete: ${error.message}`, { error: error.message });
  for (const restore of records.filter(r => r.kind === 'campaign-restore' && (!r.ok || r.verification === 'mismatch')))
    add('RUNTIME_CAMPAIGN_RESTORE', 'runtime', severity.MEDIUM, confidence.CERTAIN,
      `The campaign could not restore the original test field${restore.status ? ` (HTTP ${restore.status})` : ''}; inspect the disposable record`,
      { status: restore.status, error: restore.error, verification: restore.verification });
  for (const restore of records.filter(r => r.kind === 'campaign-restore' && r.ok && r.verification !== 'matched'))
    add('RUNTIME_CAMPAIGN_COVERAGE', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      `Restore request was accepted; original saved values ${restore.verification || 'not verified'}. Configure verify.url for read-back evidence`, { verification: restore.verification || 'not configured' });
  for (const cleanup of records.filter(r => r.kind === 'campaign-cleanup' && !r.ok))
    add('RUNTIME_CAMPAIGN_CLEANUP', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      'The campaign could not verify removal of all tool-owned browser data canaries from the configured view', { count: cleanup.count });
  const docxCases = [];
  for (const sent of records.filter(r => r.kind === 'docx-send')) {
    const opened = records.some(r => r.kind === 'docx-view' && r.case === sent.case && r.opened);
    const requested = records.some(r => r.kind === 'docx-resource' && r.case === sent.case);
    const state = { case: sent.case, accepted: !!sent.ok, viewOpened: opened, loopbackRequested: requested, sha256: sent.sha256, bytes: sent.bytes };
    docxCases.push(state);
    add('RUNTIME_DOCX_IMPORT_CASE', sent.route || 'runtime', severity.INFORMATIONAL, confidence.CERTAIN,
      `DOCX ${sent.case}: import ${sent.ok ? 'accepted' : 'failed or rejected'}${sent.status ? ` (HTTP ${sent.status})` : ''}, configured view ${opened ? 'opened' : 'not observed'}${requested ? ', loopback relationship requested' : ''}. Acceptance does not prove conversion or rendering`, state);
    if (sent.ok && requested)
      add('RUNTIME_DOCX_RESOURCE', 'http://127.0.0.1', severity.INFORMATIONAL, confidence.FIRM,
        'The DOCX import was accompanied by a request to its controlled external relationship; the initiating process and response readability remain unknown', state);
  }

  const started = records.some(r => r.kind === 'start');
  for (const record of records.filter(r => r.kind === 'debug-coverage'))
    add('RUNTIME_DEBUG_COVERAGE', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN, record.message, { observer: 'renderer-cdp', mainProcess: false });
  const pages = records.filter(r => r.kind === 'page' && !INTERNAL_PAGES.test(r.url));
  const prefsById = new Map(pages.map(p => [p.id, p.prefs || {}]));
  // preload scripts captured where each window was constructed (getLastWebPreferences() omits them)
  const preloadByContents = new Map();
  for (const r of records.filter(r => r.kind === 'window')) if (r.id !== undefined && r.preload) preloadByContents.set(r.id, r.preload);

  // what each window really ran with
  for (const page of pages) {
    const prefs = page.prefs || {};
    const where = origin(page.url);
    const settings = Object.fromEntries(['nodeIntegration', 'contextIsolation', 'sandbox', 'webSecurity'].map(name => [name, { value: prefs[name], source: prefs[name] === undefined ? 'unavailable' : 'observed' }]));
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

  // a page from another origin than the window started on, still running the window's preload: the preload's APIs are
  // exposed to that site (a sign-in provider, a link target, a redirect)
  const firstOrigin = new Map();
  for (const page of pages) {
    if (!firstOrigin.has(page.id)) { firstOrigin.set(page.id, origin(page.url)); continue; }
    const preload = (page.prefs || {}).preload || preloadByContents.get(page.id);
    if (preload && origin(page.url) !== firstOrigin.get(page.id) && /^https?:/i.test(page.url) && !LOCAL_HOSTS.test(hostOf(page.url)) && first(`preload-foreign:${page.id}:${origin(page.url)}`))
      add('RUNTIME_PRELOAD_FOREIGN_ORIGIN', page.url, severity.MEDIUM, confidence.CERTAIN,
        `A page from ${origin(page.url)} ran in a window that started on ${firstOrigin.get(page.id)}, with its preload ${preload}: everything the preload exposes is available to that site`,
        { preload, origin: origin(page.url), windowOrigin: firstOrigin.get(page.id) }, `${DOCS}#20-do-not-expose-electron-apis-to-untrusted-web-content`);
  }

  // server redirects the app followed to another origin (will-navigate never sees these)
  for (const r of records.filter(r => r.kind === 'will-redirect' && !r.prevented && /^https?:/i.test(r.url || ''))) {
    if (origin(r.url) === origin(r.from) || !first(`redirect:${r.id}:${origin(r.url)}`)) continue;
    add('RUNTIME_REDIRECT', r.url, r.marker ? severity.HIGH : severity.MEDIUM, r.marker ? confidence.CERTAIN : confidence.FIRM,
      `A window followed a server redirect from ${r.from} to ${origin(r.url)}${r.marker ? ' carrying the planted marker' : ''}; will-navigate allowlists don't see redirects, will-redirect does`,
      { from: r.from, marker: !!r.marker }, 'https://www.electronjs.org/docs/latest/api/web-contents#event-will-redirect');
  }

  // windows of different privilege sharing one session: cookies, storage and permission grants are common
  const bySession = new Map();
  for (const page of pages.filter(p => p.session)) {
    if (!bySession.has(page.session)) bySession.set(page.session, new Map());
    const prefs = page.prefs || {};
    const privileged = prefs.nodeIntegration === true || prefs.contextIsolation === false || prefs.sandbox === false || !!(prefs.preload || preloadByContents.get(page.id));
    const windows = bySession.get(page.session);
    windows.set(page.id, { privileged: (windows.get(page.id) || {}).privileged || privileged, url: page.url });
  }
  for (const [session, windows] of bySession) {
    if (windows.size < 2) continue;
    const strong = [...windows.values()].filter(w => w.privileged);
    const weak = [...windows.values()].filter(w => !w.privileged);
    const name = session === 'default' ? 'the default session' : `session '${session}'`;
    if (strong.length && weak.length)
      add('RUNTIME_WINDOW_SESSION', weak[0].url, severity.LOW, confidence.CERTAIN,
        `Windows without privileges (${weak.map(w => origin(w.url)).join(', ')}) shared ${name} with privileged ones (${strong.map(w => origin(w.url)).join(', ')}): cookies, storage and permission grants are common`,
        { session, privileged: strong.map(w => w.url), unprivileged: weak.map(w => w.url) }, 'https://www.electronjs.org/docs/latest/api/session');
    else
      add('RUNTIME_WINDOW_SESSION', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN, `${windows.size} windows shared ${name}`, { session, windows: [...windows.values()].map(w => w.url) });
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
  // checks without an origin come from Chromium itself (media device enumeration and the like), not from a page
  for (const r of records.filter(r => r.kind === 'permission-check' && r.granted && r.origin)) {
    if (!first(`permcheck:${r.permission}:${origin(r.origin)}`)) continue;
    if (r.default) add('RUNTIME_PERMISSION_CHECK', r.origin, severity.MEDIUM, confidence.CERTAIN, `The '${r.permission}' permission check was allowed for ${r.origin} automatically, as the app has no setPermissionCheckHandler`, undefined, `${DOCS}#5-handle-session-permission-requests-from-remote-content`);
    else add('RUNTIME_PERMISSION_CHECK', r.origin, severity.INFORMATIONAL, confidence.CERTAIN, `The app's permission check handler allowed '${r.permission}' for ${r.origin}`);
  }
  // what the renderer-side observer saw inside pages: script-bearing DOM changes, and planted-marker reflections
  for (const r of records.filter(r => r.kind === 'dom-observed')) {
    if (r.event === 'marker') {
      if (!first(`marker:${origin(r.url)}:${r.frame ? 'frame' : 'top'}:${r.live}`)) continue;
      const where = `${r.url}${r.frame ? ` (inside a frame: ${r.frame})` : ''}`;
      if (r.live) add('RUNTIME_MARKER', r.url, severity.LOW, confidence.FIRM, `Planted marker appeared as HTML at ${where}. This establishes rendering of markup, not script execution or access across accounts`, { marker: r.detail, live: true, frame: r.frame }, `${DOCS}#7-define-a-content-security-policy`);
      else add('RUNTIME_MARKER', r.url, severity.INFORMATIONAL, confidence.CERTAIN, `Planted marker appeared as text (escaped) at ${where}`, { marker: r.detail, live: false, frame: r.frame });
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

  // entry points the user exercised: paste, drag and drop, file pickers and dialogs, files and deep links
  const entryPoints = {};
  for (const r of records.filter(r => r.kind === 'entry')) entryPoints[r.detail] = (entryPoints[r.detail] || 0) + 1;

  // API endpoints the pages called, for server-side testing: grouped by method and path (ids replaced by {id}), with
  // whether any request sent HTML in its body. Stored content that reaches other users goes through these endpoints,
  // and the server is where it must be validated: an endpoint that accepted markup is where to start.
  const endpoints = new Map();
  for (const r of records.filter(r => r.kind === 'api')) {
    const route = apiRoute(r.url);
    if (!route) continue;
    const key = `${r.method} ${route}`;
    if (!endpoints.has(key)) endpoints.set(key, { method: r.method, route, calls: 0, statuses: new Set(), htmlBody: false, maxBodyBytes: 0, fields: new Map() });
    const endpoint = endpoints.get(key);
    endpoint.calls++;
    if (r.status) endpoint.statuses.add(r.status);
    if (r.htmlBody) endpoint.htmlBody = true;
    endpoint.maxBodyBytes = Math.max(endpoint.maxBodyBytes, r.bodyBytes || 0);
    // field names, whether each carried markup and whether it carried the planted marker (values are never recorded)
    for (const field of r.fields || []) {
      const known = endpoint.fields.get(field.name) || { name: field.name, html: false, marker: false };
      endpoint.fields.set(field.name, { name: field.name, html: known.html || !!field.html, marker: known.marker || !!field.marker });
    }
  }
  const api = [...endpoints.values()].map(e => ({ ...e, statuses: [...e.statuses].sort(), fields: [...e.fields.values()] })).sort((a, b) => Number(b.htmlBody) - Number(a.htmlBody) || b.calls - a.calls);
  for (const endpoint of api.filter(e => e.htmlBody && e.statuses.some(status => status < 400))) {
    add('RUNTIME_HTML_ENDPOINT', endpoint.route, severity.INFORMATIONAL, confidence.CERTAIN,
      `${endpoint.method} ${endpoint.route} accepted a request body containing HTML markup (${endpoint.calls} call${endpoint.calls === 1 ? '' : 's'}, status ${endpoint.statuses.join('/')}): verify on the server that stored markup is sanitized before other users receive it`,
      { method: endpoint.method, route: endpoint.route }, 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html');
    issues[issues.length - 1].manualReview = true;
  }

  markerEvidence(records, add, first, api, issues);

  // the traffic checks that ran inside the app: its last report holds every finding so far
  const trafficRecord = records.filter(r => r.kind === 'traffic').pop();
  const traffic = trafficRecord ? { ...trafficRecord.summary, findings: trafficRecord.findings.length } : undefined;
  if (traffic) {
    traffic.notes = records.filter(r => r.kind === 'traffic-note').map(r => r.message).slice(0, 20);
    issues.push(...trafficIssues(trafficRecord.findings, 'watch'));
  }
  consoleAndErrors(records, add, first, issues);

  const paths = records.filter(r => r.kind === 'paths').pop();
  // evidence screenshots (--watch-screenshots), attached to the findings about the same page
  const screenshots = records.filter(r => r.kind === 'screenshot').map(r => ({ reason: r.reason, url: r.url, file: r.file }));
  for (const issue of issues) {
    const shot = screenshots.find(s => s.url === issue.file);
    if (shot) issue.properties = { ...(issue.properties || {}), screenshot: shot.file };
  }
  return { issues, summary: { screenshots, started, windows: new Set(pages.map(p => p.id)).size, pages: pages.length, channels: registered.size, usedChannels: used.size, unusedChannels, entryPoints, api, traffic,
    docxCampaign: docxCases.length ? { attempted: docxCases.length, accepted: docxCases.filter(c => c.accepted).length, cases: docxCases } : undefined,
    campaign: campaignCases.length ? { attempted: campaignCases.length, accepted: campaignCases.filter(c => c.delivery === 'accepted').length,
      executed: campaignCases.filter(c => c.execution === 'observed').length, cases: campaignCases } : undefined,
    userData: paths && paths.userData } };
}

// Secrets written to the consoles, errors nothing handled, and CSP violations: each once per kind and place
function consoleAndErrors(records, add, first, issues) {
  for (const r of records.filter(r => r.kind === 'console-secret')) {
    const where = r.where === 'main' ? 'the main process' : `a page${r.url ? ` (${r.url})` : ''}`;
    if (!first(`console-secret:${r.where}:${(r.kinds || []).join(',')}`)) continue;
    add('RUNTIME_SECRET_IN_CONSOLE', r.url || r.where, severity.LOW, confidence.FIRM, `${(r.kinds || []).join(', ')} written to the console by ${where}: console output ends up in log files and crash reports`,
      { where: r.where, kinds: r.kinds, evidence: r.evidence }, 'https://cwe.mitre.org/data/definitions/532.html');
    issues[issues.length - 1].sample = (r.evidence || [])[0] || '';
  }
  for (const r of records.filter(r => r.kind === 'main-exception' || r.kind === 'page-exception')) {
    const main = r.kind === 'main-exception';
    if (!first(`exception:${r.kind}:${r.url || ''}:${String(r.message).slice(0, 60)}`)) continue;
    add('RUNTIME_UNCAUGHT_EXCEPTION', main ? 'main process' : r.url, severity.LOW, confidence.CERTAIN,
      `An exception nothing handled was thrown in ${main ? 'the main process' : `a page (${r.url || '?'})`}: ${r.message}`, { where: main ? 'main' : 'renderer', line: r.line },
      'https://cwe.mitre.org/data/definitions/248.html');
  }
  for (const r of records.filter(r => r.kind === 'csp-violation')) {
    if (!first(`csp-violation:${origin(r.url)}:${r.directive}:${r.blocked}`)) continue;
    add('RUNTIME_CSP_VIOLATION', r.url, severity.MEDIUM, confidence.FIRM,
      `The Content Security Policy blocked ${r.blocked || 'a resource'}${r.directive ? ` (${r.directive})` : ''} on ${r.url || 'a page'}: find what tried to load it; content injected into the page is a common cause`,
      { directive: r.directive, blocked: r.blocked }, 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP');
  }
}

// Where the planted marker (--watch-marker) turned up: each is runtime proof for a finding that needs review. A value
// from content reached an HTML sink (with the script location that wrote it), openExternal, openPath, a navigation, a
// new window, IPC or a command line; or the app blocked it.
function markerEvidence(records, add, first, api, issues) {
  for (const r of records.filter(r => r.kind === 'sink' && r.live)) {
    const frame = (r.frames || [])[0];
    const where = frame ? `${frame.url}:${frame.line}:${frame.column}` : 'an unknown script';
    if (!first(`marker-sink:${r.sink}:${where}`)) continue;
    add('RUNTIME_MARKER_SINK', frame ? frame.url : r.url, severity.LOW, confidence.FIRM,
      `Marker markup was written into the page with ${r.sink} by ${where} (page ${r.url}${r.frame ? `, inside a frame: ${r.frame}` : ''}). Script execution and the input's trust boundary remain unverified`,
      { sink: r.sink, frames: r.frames, page: r.url, frame: r.frame }, 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html');
    // at the script location, so it lines up with the static finding there
    if (frame) issues[issues.length - 1].location = { line: frame.line, column: frame.column };
  }
  for (const endpoint of api.filter(e => e.fields.some(f => f.marker))) {
    if (!first(`marker-sent:${endpoint.method} ${endpoint.route}`)) continue;
    const fields = endpoint.fields.filter(f => f.marker).map(f => f.name);
    add('RUNTIME_MARKER_SENT', endpoint.route, severity.INFORMATIONAL, confidence.CERTAIN,
      `The planted marker was sent with ${endpoint.method} ${endpoint.route} in: ${fields.join(', ')}`, { method: endpoint.method, route: endpoint.route, fields });
  }
  // requests the validation assistant re-sent itself (after the tester confirmed): the same evidence, whether the marker
  // was put in by hand or sent for the tester
  for (const r of records.filter(r => r.kind === 'marker-request' && r.ok && r.route)) {
    if (!first(`marker-sent:${r.method} ${r.route}`)) continue;
    const fields = r.fields || [];
    add('RUNTIME_MARKER_SENT', r.route, severity.INFORMATIONAL, confidence.CERTAIN,
      `The planted marker was sent with ${r.method} ${r.route}${fields.length ? ` in: ${fields.join(', ')}` : ''} (re-sent by the validation assistant)`, { method: r.method, route: r.route, fields });
  }
  for (const r of records.filter(r => r.kind === 'shell' && r.marker)) {
    if (r.method === 'openExternal') {
      const web = /^(https?|mailto)$/i.test(r.scheme || '');
      if (!first(`marker-external:${web}:${r.scheme}`)) continue;
      if (web) add('RUNTIME_MARKER_OPEN_EXTERNAL', r.target, severity.INFORMATIONAL, confidence.CERTAIN, `A marker link with the ${r.scheme}: scheme reached shell.openExternal. This does not test the scheme allowlist`, { scheme: r.scheme }, `${DOCS}#15-do-not-use-shellopenexternal-with-untrusted-content`);
      else add('RUNTIME_MARKER_OPEN_EXTERNAL', r.target, severity.MEDIUM, confidence.FIRM, `A marker link with the ${r.scheme}: scheme reached shell.openExternal in this session. Review which handler and user action allowed it`, { scheme: r.scheme }, `${DOCS}#15-do-not-use-shellopenexternal-with-untrusted-content`);
    } else if (first(`marker-path:${r.method}`)) {
      add('RUNTIME_MARKER_OPEN_PATH', r.target, severity.MEDIUM, confidence.FIRM, `A marker path reached shell.${r.method}. Whether the caller can choose arbitrary paths remains unverified`, { method: r.method }, 'https://www.electronjs.org/docs/latest/api/shell');
    }
  }
  for (const r of records.filter(r => r.kind === 'will-navigate' && r.marker)) {
    if (!first(`marker-nav:${r.prevented}`)) continue;
    if (r.prevented) add('RUNTIME_MARKER_NAVIGATION', r.url, severity.INFORMATIONAL, confidence.CERTAIN, `A link from content (carrying the planted marker) tried to navigate an app window, and the app blocked it`, { blocked: true }, `${DOCS}#13-disable-or-limit-navigation`);
    else add('RUNTIME_MARKER_NAVIGATION', r.url, severity.MEDIUM, confidence.FIRM, `Navigation for a marker link to ${r.url} was not blocked at will-navigate. Check the resulting page and its privileges`, { blocked: false }, `${DOCS}#13-disable-or-limit-navigation`);
  }
  for (const r of records.filter(r => r.kind === 'window-open' && r.marker)) {
    const denied = r.action === 'deny';
    if (!first(`marker-window:${denied}`)) continue;
    if (denied) add('RUNTIME_MARKER_NEW_WINDOW', r.url, severity.INFORMATIONAL, confidence.CERTAIN, 'A link from content (carrying the planted marker) tried to open a new window, and the app refused', { blocked: true }, `${DOCS}#14-disable-or-limit-creation-of-new-windows`);
    else add('RUNTIME_MARKER_NEW_WINDOW', r.url, severity.LOW, confidence.FIRM, `A new-window request for a marker link was allowed${r.default ? ' by the default handler' : ''}. Check the resulting window and its privileges`, { blocked: false }, `${DOCS}#14-disable-or-limit-creation-of-new-windows`);
  }
  for (const r of records.filter(r => r.kind === 'ipc' && r.marker)) {
    if (first(`marker-ipc:${r.channel}`))
      add('RUNTIME_MARKER_IPC', 'runtime', severity.INFORMATIONAL, confidence.CERTAIN, `Marker data reached IPC channel '${r.channel}'${r.sender ? ` from ${r.sender}` : ''}. This does not establish sender validation or a cross-account route`, { channel: r.channel, sender: r.sender });
  }
  for (const r of records.filter(r => r.kind === 'module-load' && r.marker)) {
    if (!first(`marker-module:${r.resolved || r.request}:${r.ok}`)) continue;
    add('RUNTIME_MARKER_MODULE', r.parent || r.resolved || 'N/A', r.ok ? severity.MEDIUM : severity.INFORMATIONAL, confidence.FIRM,
      r.ok ? 'A planted marker reached a CommonJS module path and the module loaded. Path traversal, caller control and exploitability remain unverified.' :
        'A planted marker reached a CommonJS module path; the load failed. This does not establish that a security policy rejected it.',
      { request: r.request, resolved: r.resolved, parent: r.parent, loaded: !!r.ok, errorCode: r.errorCode, sink: 'require' }, 'https://owasp.org/www-community/attacks/Path_Traversal');
  }
  for (const r of records.filter(r => r.kind === 'process' && r.marker)) {
    if (first(`marker-process:${r.program}`))
      add('RUNTIME_MARKER_COMMAND', 'runtime', severity.MEDIUM, confidence.FIRM, `Marker data reached a command invocation (${r.program}, via ${r.method}). Command injection and argument control remain unverified`, { program: r.program, method: r.method }, 'https://owasp.org/www-community/attacks/Command_Injection');
  }
}

// https://host/api/documents/42/comments?x=1 -> https://host/api/documents/{id}/comments: numbers, UUIDs and long hex or
// base64-like segments are identifiers
export function apiRoute(url) {
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split('/').map(segment => {
      if (/^\d+$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment) ||
        /^[0-9a-f]{16,}$/i.test(segment) || (/^[\w-]{20,}$/.test(segment) && /\d/.test(segment))) return '{id}';
      return segment;
    });
    return `${parsed.origin}${segments.join('/')}`;
  } catch {
    return undefined;
  }
}

// script-src, or default-src when there is none
function scriptPolicy(policy) {
  const directives = policy.split(';').map(d => d.trim());
  return directives.find(d => /^script-src\s/i.test(d)) || directives.find(d => /^default-src\s/i.test(d)) || '';
}
