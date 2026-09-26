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
export function reconcileRuntime(issues) {
  const runtimeWindows = issues.filter(i => i.id === 'RUNTIME_WINDOW_SUMMARY');
  if (runtimeWindows.length === 0) return issues; // nothing was observed: leave the static findings untouched
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
