// Links what the static scan found to what watch mode observed, so the report can show one problem with both sources
// instead of two unrelated rows, and can point out windows the static scan knows about that were never opened at runtime.
// Called after the runtime findings have been merged into the static ones.
import path from 'node:path';
import { severity, confidence } from '../finder/attributes.js';

const DOCS = 'https://www.electronjs.org/docs/latest/tutorial/security';

// runtime finding id -> the static check that reports the same problem in code
const SAME_PROBLEM = {
  RUNTIME_NODE_INTEGRATION: 'NODE_INTEGRATION_JS_CHECK',
  RUNTIME_CONTEXT_ISOLATION: 'CONTEXT_ISOLATION_JS_CHECK',
  RUNTIME_WEB_SECURITY: 'WEB_SECURITY_JS_CHECK',
  RUNTIME_SANDBOX: 'SANDBOX_JS_CHECK',
};

const baseName = (p) => (p && p !== 'dynamic path' && p !== 'dynamic' ? path.basename(String(p)) : undefined);
const place = (issue) => `${issue.file}${issue.location && issue.location.line ? ':' + issue.location.line : ''}`;

/**
 * Mutates `issues` in place: cross-references runtime and static findings, and appends a coverage finding for windows
 * the static scan found that were never opened during the session. @returns the same array.
 */
export function reconcileRuntime(issues, summary) {
  linkMarkerEvidence(issues);
  const runtimeWindows = issues.filter(i => i.id === 'RUNTIME_WINDOW_SUMMARY');
  if (runtimeWindows.length === 0) return issues; // nothing was observed: leave the static findings untouched
  entryCoverage(issues, summary);
  const staticWindows = issues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK');

  // link windows by preload script: the same preload means the static definition and the observed window are the same
  const observed = new Set();
  for (const sw of staticWindows) {
    const preload = baseName(sw.properties && sw.properties.preload);
    const match = preload && runtimeWindows.find(rw => baseName(rw.properties && rw.properties.preload) === preload);
    if (match) {
      sw.properties = { ...sw.properties, observedAt: match.properties.url };
      match.properties = { ...match.properties, staticWindow: place(sw) };
      observed.add(sw);
    }
  }

  // a problem seen both in the code and at runtime: mark each as confirmed by the other
  for (const [runtimeId, staticId] of Object.entries(SAME_PROBLEM)) {
    const runtimeHits = issues.filter(i => i.id === runtimeId);
    const staticHits = issues.filter(i => i.id === staticId);
    if (runtimeHits.length === 0 || staticHits.length === 0) continue;
    for (const r of runtimeHits) if (!/also found/.test(r.description)) {
      r.description += ` (also found by static analysis: ${staticId})`;
      r.properties = { ...r.properties, confirmedByStatic: staticId };
    }
    for (const s of staticHits) s.properties = { ...s.properties, confirmedByRuntime: runtimeId };
  }

  // windows the static scan found but that were never opened: coverage beyond the IPC channels already reported
  const unopened = staticWindows.filter(sw => !observed.has(sw) && baseName(sw.properties && sw.properties.preload));
  if (unopened.length > 0) {
    const list = unopened.map(sw => `${sw.properties.window} (${baseName(sw.properties.preload)}) at ${place(sw)}`);
    issues.push({
      file: 'runtime', sample: '', location: { line: 0, column: 0 }, id: 'RUNTIME_WINDOW_COVERAGE',
      description: `${unopened.length} of ${staticWindows.length} window(s) defined in the code were not opened during the session: ${list.join('; ')}`,
      properties: { unopened: list }, shortenedURL: DOCS, severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN,
      manualReview: false, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime'
    });
  }
  return issues;
}

const STATIC_EDITOR = new Set(['RICH_TEXT_EDITOR_JS_CHECK', 'SANITIZER_CONFIG_JS_CHECK', 'ANGULAR_TRUST_HTML_JS_CHECK']);

/**
 * Ways content gets into the app that the code handles but the session never tried: pasting HTML, drag and drop,
 * importing files, deep links and file associations. Each is a route for content someone else wrote, so a session
 * that skipped them didn't test them.
 */
function entryCoverage(issues, summary) {
  const used = (summary && summary.entryPoints) || {};
  const tried = (...names) => Object.keys(used).some(key => names.some(name => key === name || key.startsWith(`${name}-`)));
  const origins = new Set(issues.map(i => i.properties && i.properties.origin).filter(Boolean));
  const editor = issues.some(i => STATIC_EDITOR.has(i.id)) || origins.has('pasted or dropped content') || origins.has('clipboard content');
  const imports = origins.has('an imported document or file');
  const deepLinks = issues.some(i => i.id === 'FILE_HANDLER_JS_CHECK');
  const routes = [
    { name: 'pasting formatted content (HTML from Word or a web page)', relevant: editor, done: tried('paste-html') },
    { name: 'dragging and dropping content or files', relevant: editor || imports, done: tried('drop') },
    { name: 'importing or opening a file', relevant: imports, done: tried('file-picker', 'open-dialog', 'drop-file', 'paste-file', 'open-file') },
    { name: 'a deep link, file association or second instance', relevant: deepLinks, done: tried('open-url', 'open-file', 'second-instance') },
  ];
  const untried = routes.filter(route => route.relevant && !route.done).map(route => route.name);
  if (untried.length === 0) return;
  issues.push({
    file: 'runtime', sample: '', location: { line: 0, column: 0 }, id: 'RUNTIME_ENTRY_COVERAGE',
    description: `The code handles content arriving by ${untried.join('; ')}, but the session did not try ${untried.length === 1 ? 'it' : 'them'}: content another person wrote can come in this way`,
    properties: { untried, entryPoints: used }, shortenedURL: DOCS, severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN,
    manualReview: false, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime'
  });
}

const HTML_CODE = new Set(['XSS_SINK_JS_CHECK', 'ANGULAR_TRUST_HTML_JS_CHECK', 'RICH_TEXT_EDITOR_JS_CHECK', 'DANGEROUS_FUNCTIONS_JS_CHECK', 'SANITIZER_CONFIG_JS_CHECK']);
const withoutQuery = (url) => String(url || '').split(/[?#]/)[0];
// a static file (a path, or the URL of a script captured from the server) and a script URL from a stack trace
function sameScript(file, url) {
  const a = withoutQuery(file);
  const b = withoutQuery(url);
  if (!a || !b) return false;
  if (a === b) return true;
  const tail = (p) => p.split(/[\\/]/).filter(Boolean).slice(-2).join('/');
  return tail(a) !== '' && tail(a) === tail(b);
}

/**
 * Marks static findings the planted marker confirmed (or ruled out) during the session: `validation` = { status, text }.
 * HTML sinks are matched to the exact script line that wrote the markup; the others by kind (the marker shows the app
 * does it somewhere, the static finding says where it can happen).
 */
function linkMarkerEvidence(issues) {
  const of = (id) => issues.filter(i => i.id === id);
  const mark = (issue, status, text) => { if (!issue.validation || issue.validation.status !== 'confirmed') issue.validation = { status, text }; };

  for (const sink of of('RUNTIME_MARKER_SINK')) {
    const frames = (sink.properties && sink.properties.frames) || [];
    for (const issue of issues.filter(i => HTML_CODE.has(i.id))) {
      if (!issue.location) continue;
      // the scanned file is the script itself, or the original source its source map pointed to
      const frame = frames.find(f => (f.original && f.original.file === issue.file && f.original.line === issue.location.line) ||
        (f.line === issue.location.line && sameScript(issue.file, f.url)));
      if (frame) {
        mark(issue, 'confirmed', `Confirmed at runtime: markup planted as another user's content was written with ${sink.properties.sink} from this line (${frame.url}:${frame.line}:${frame.column}${frame.original ? `, ${frame.original.file.replace(/^.* \(source: (.*)\)$/, '$1')}:${frame.original.line}` : ''}).`);
        sink.properties = { ...sink.properties, staticFinding: `${issue.id} at ${issue.file}:${issue.location.line}` };
      }
    }
  }
  const external = of('RUNTIME_MARKER_OPEN_EXTERNAL');
  for (const issue of of('OPEN_EXTERNAL_JS_CHECK')) {
    const nonWeb = external.find(r => r.properties && !/^(https?|mailto)$/i.test(r.properties.scheme || ''));
    if (nonWeb) mark(issue, 'confirmed', `Confirmed at runtime: a ${nonWeb.properties.scheme}: link from content reached shell.openExternal, so there is no scheme allowlist (the session does not tell which openExternal call it was).`);
    else if (external.length) mark(issue, 'observed', 'Seen at runtime: links from content reach shell.openExternal. Try a file:/// link in the next session to check the scheme allowlist.');
  }
  const paths = of('RUNTIME_MARKER_OPEN_PATH');
  for (const issue of issues.filter(i => i.id === 'OPEN_PATH_JS_CHECK' || i.id === 'SHOWITEMINFOLDER_JS_CHECK'))
    if (paths.length) mark(issue, 'confirmed', `Confirmed at runtime: a path from content reached shell.${paths[0].properties.method}.`);
  const navigation = of('RUNTIME_MARKER_NAVIGATION');
  for (const issue of issues.filter(i => /^LIMIT_NAVIGATION_/.test(i.id) || i.id === 'RUNTIME_NAVIGATION')) {
    if (navigation.some(r => r.properties && !r.properties.blocked)) mark(issue, 'confirmed', 'Confirmed at runtime: a link from content navigated an app window.');
    else if (navigation.length) mark(issue, 'safe', 'Checked at runtime: the app blocked a link from content from navigating the window.');
  }
  const windows = of('RUNTIME_MARKER_NEW_WINDOW');
  for (const issue of issues.filter(i => i.id === 'WINDOW_OPEN_HANDLER_JS_CHECK' || i.id === 'RUNTIME_NEW_WINDOW')) {
    if (windows.some(r => r.properties && !r.properties.blocked)) mark(issue, 'confirmed', 'Confirmed at runtime: a link from content opened a new app window.');
    else if (windows.length) mark(issue, 'safe', 'Checked at runtime: the app refused to open a window for a link from content.');
  }
  const commands = of('RUNTIME_MARKER_COMMAND');
  for (const issue of of('COMMAND_INJECTION_JS_CHECK'))
    if (commands.length) mark(issue, 'confirmed', `Confirmed at runtime: content reached a command line (${commands.map(c => c.properties.program).join(', ')}).`);
  const channels = new Map(of('RUNTIME_MARKER_IPC').map(r => [r.properties.channel, r.properties.sender]));
  for (const issue of of('IPC_SENDER_VALIDATION_JS_CHECK')) {
    const channel = issue.properties && issue.properties.channel;
    if (channel && channels.has(channel)) mark(issue, 'observed', `Seen at runtime: content from other users reaches '${channel}'${channels.get(channel) ? ` (sent from ${channels.get(channel)})` : ''}, so this handler must check the sender and validate the value.`);
  }
}
