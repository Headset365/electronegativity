// Links what the static scan found to what watch mode observed, so the report can show one problem with both sources
// instead of two unrelated rows, and can point out windows the static scan knows about that were never opened at runtime.
// Called after the runtime findings have been merged into the static ones.
import path from 'node:path';
import { severity, confidence } from '../finder/attributes.js';
import { recordValidation } from '../finder/validation.js';

const DOCS = 'https://www.electronjs.org/docs/latest/tutorial/security';

const baseName = (p) => (p && p !== 'dynamic path' && p !== 'dynamic' ? path.basename(String(p)) : undefined);
const place = (issue) => `${issue.file}${issue.location && issue.location.line ? ':' + issue.location.line : ''}`;

/**
 * Mutates `issues` in place: cross-references runtime and static findings, and appends a coverage finding for windows
 * the static scan found that were never opened during the session. @returns the same array.
 */
export function reconcileRuntime(issues, summary) {
  linkMarkerEvidence(issues);
  for (const proof of issues.filter(i => i.id === 'RUNTIME_FUSE_PROOF' && i.validation?.status === 'confirmed')) {
    const fuse = proof.properties.test === 'run-as-node' ? 'RunAsNode' : proof.properties.test === 'node-inspector' ? 'EnableNodeCliInspectArguments' : undefined;
    if (fuse) for (const finding of issues.filter(i => i.id === 'PACKAGED_FUSES' && i.properties?.fuse === fuse)) recordValidation(finding, proof.validation);
  }
  // a navigation or new-window proof "blocked" while the code passes those URLs to shell.openExternal: the app opened no
  // window of its own, and handed the link to the operating system instead
  const handOff = { navigation: /navigation requested by web content/i, 'window-open': /window\.open\(\) call or link in web content/i };
  for (const proof of issues.filter(i => i.id === 'RUNTIME_PROOF' && handOff[i.properties?.test] && i.properties.outcome === 'blocked' && !i.properties.handedToOs)) {
    const code = issues.find(i => /^OPEN_EXTERNAL_JS_CHECK$/.test(i.id) && handOff[proof.properties.test].test(i.description || ''));
    if (!code) continue;
    proof.properties = { ...proof.properties, handedToOs: 'static' };
    proof.description = `${proof.properties.test}: the app opened no window of its own, but its handler passes the URL to shell.openExternal (${code.file}:${code.location?.line}), so the link is handed to the operating system. ${proof.description.replace(/^[^.]*\.\s*/, '')}`;
    if (proof.validation) proof.validation = { ...proof.validation, text: proof.description };
  }
  const runtimeWindows = issues.filter(i => i.id === 'RUNTIME_WINDOW_SUMMARY');
  if (runtimeWindows.length === 0) return issues; // nothing was observed: leave the static findings untouched
  entryCoverage(issues, summary);
  const staticWindows = issues.filter(i => i.id === 'WINDOW_SUMMARY_JS_CHECK');

  // A preload is only a useful hint when it uniquely identifies a window on both sides.
  const observed = new Set();
  for (const sw of staticWindows) {
    const preload = baseName(sw.properties && sw.properties.preload);
    const candidates = preload && runtimeWindows.filter(rw => baseName(rw.properties && rw.properties.preload) === preload);
    if (candidates && candidates.length === 1 && staticWindows.filter(w => baseName(w.properties && w.properties.preload) === preload).length === 1) {
      const match = candidates[0];
      sw.properties = { ...sw.properties, observedAt: match.properties.url };
      match.properties = { ...match.properties, staticWindow: place(sw) };
      observed.add(sw);
      const settings = sw.properties.settings || {};
      const effective = Object.fromEntries(Object.entries(match.properties.settings || {}).map(([name, value]) => [name, value.value]));
      const differing = Object.entries(settings).filter(([name, value]) => typeof value.value === 'boolean' && typeof effective[name] === 'boolean' && value.value !== effective[name])
        .map(([name, value]) => ({ setting: name, static: value.value, runtime: effective[name] }));
      if (differing.length) {
        const description = `Static/runtime settings differ for the uniquely matched preload ${preload}: ${differing.map(d => `${d.setting} static=${d.static}, observed=${d.runtime}`).join('; ')}. This session does not establish dead code or settings of unvisited windows; static severity is retained.`;
        recordValidation(sw, { status: 'observed', scope: 'configuration-discrepancy', text: description });
        issues.push({ file: sw.file, sample: '', location: sw.location, id: 'RUNTIME_STATIC_DISCREPANCY', description,
          properties: { differing, staticWindow: place(sw), runtimeWindow: match.file }, shortenedURL: DOCS, severity: severity.INFORMATIONAL, confidence: confidence.FIRM,
          manualReview: false, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime' });
      }
    }
  }

  // With no unique window match, report a session-wide contrast, never suppression.
  if (issues.some(i => i.id === 'NODE_INTEGRATION_JS_CHECK') && !issues.some(i => i.id === 'RUNTIME_NODE_INTEGRATION') && runtimeWindows.every(w => w.properties?.settings?.nodeIntegration?.value === false)) {
    const description = 'Static code enables Node integration, while every observed window had it off. The session cannot prove that unvisited window definitions are dead code; the static findings retain their severity.';
    issues.push({ file: 'runtime', sample: '', location: { line: 0, column: 0 }, id: 'RUNTIME_STATIC_DISCREPANCY', description,
      properties: { setting: 'nodeIntegration', observedWindows: runtimeWindows.length }, shortenedURL: DOCS,
      severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: false,
      visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime' });
  }

  // windows the static scan found but that were never opened: coverage beyond the IPC channels already reported
  const unopened = staticWindows.filter(sw => !observed.has(sw) && baseName(sw.properties && sw.properties.preload));
  if (unopened.length > 0) {
    const list = unopened.map(sw => `${sw.properties.window} (${baseName(sw.properties.preload)}) at ${place(sw)}`);
    issues.push({
      file: 'runtime', sample: '', location: { line: 0, column: 0 }, id: 'RUNTIME_WINDOW_COVERAGE',
      description: `${unopened.length} of ${staticWindows.length} window definition(s) could not be matched to an observed window by a unique preload during this session: ${list.join('; ')}`,
      properties: { unmatched: list }, shortenedURL: DOCS, severity: severity.INFORMATIONAL, confidence: confidence.FIRM,
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
  // Identical path tails on different servers are not the same script.
  if (/^\w+:\/\//.test(a) && /^\w+:\/\//.test(b)) return false;
  const tail = (p) => p.split(/[\\/]/).filter(Boolean).slice(-2).join('/');
  return tail(a) !== '' && tail(a) === tail(b);
}

/**
 * A marker can establish that data reached a sink, not that executable content ran or a guard was absent.
 * Only connect an HTML finding with a matching script line, or an IPC handler with a matching channel.
 */
function linkMarkerEvidence(issues) {
  const of = (id) => issues.filter(i => i.id === id);
  const mark = (issue, text, source) => recordValidation(issue, { status: 'observed', scope: 'data-flow', text,
    evidence: [`${source.id} at ${place(source)}: ${source.description}`] });

  for (const sink of of('RUNTIME_MARKER_SINK')) {
    const frames = (sink.properties && sink.properties.frames) || [];
    for (const issue of issues.filter(i => HTML_CODE.has(i.id))) {
      if (!issue.location) continue;
      // the scanned file is the script itself, or the original source its source map pointed to
      const frame = frames.find(f => (f.original && f.original.file === issue.file && f.original.line === issue.location.line) ||
        (f.line === issue.location.line && sameScript(issue.file, f.url) &&
          new Set(issues.filter(i => HTML_CODE.has(i.id) && sameScript(i.file, f.url)).map(i => i.file)).size === 1));
      if (frame) {
        mark(issue, `Observed at runtime: marker markup reached ${sink.properties.sink} from this line (${frame.url}:${frame.line}:${frame.column}${frame.original ? `, ${frame.original.file.replace(/^.* \(source: (.*)\)$/, '$1')}:${frame.original.line}` : ''}). Script execution and exploitability remain untested.`, sink);
        sink.properties = { ...sink.properties, staticFinding: `${issue.id} at ${issue.file}:${issue.location.line}` };
        sink.properties.staticFindings = [...new Set([...(sink.properties.staticFindings || []), `${issue.id} at ${place(issue)}`])];
      }
    }
  }
  for (const issue of issues.filter(i => ['IPC_SENDER_VALIDATION_JS_CHECK', 'IPC_HANDLER_JS_CHECK', 'IPC_FILE_ACCESS_JS_CHECK'].includes(i.id))) {
    const channel = issue.properties && issue.properties.channel;
    if (channel) for (const source of of('RUNTIME_MARKER_IPC').filter(r => r.properties?.channel === channel)) {
      mark(issue, `Seen at runtime: marker data reached '${channel}'${source.properties.sender ? ` (sent from ${source.properties.sender})` : ''}. The handler's sender and value checks remain unverified.`, source);
      source.properties.staticFindings = [...new Set([...(source.properties.staticFindings || []), `${issue.id} at ${place(issue)}`])];
    }
  }
}
