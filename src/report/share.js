// A findings report redacted for sharing (--share), e.g. to get a second opinion on what to fix first without handing
// over the app. It keeps what judging a finding needs (check, severity, confidence, who can exploit it, what the victim
// has to do, runtime confirmation, the file's place in the app and line, the description) and removes what identifies
// the app or its users: the app, company and user names (and --redact terms), the home folder and user folders, hosts
// (stable pseudonyms), query strings, e-mail and IP addresses, and anything that looks like a secret. Code is left out
// unless asked for (--share-code), and then its strings and comments are masked. Review the file before sending it.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { sensitiveTerms, makeSanitizer } from '../util/diagnostics.js';
import { consequenceOf, interactionOf } from '../finder/consequences.js';

const require = createRequire(import.meta.url);
const { redactText, looksRandomSecret } = require('../traffic/secrets.cjs');

const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const CONFIDENCES = ['CERTAIN', 'FIRM', 'TENTATIVE'];
const MAX_CODE = 400;
// inventories worth listing even though they are informational: they are the map a reviewer needs
const INVENTORY = ['WINDOW_SUMMARY_JS_CHECK', 'EXPOSED_API_JS_CHECK', 'IPC_HANDLER_JS_CHECK', 'IPC_CHANNEL_MAP_GLOBAL_CHECK', 'RUNTIME_WINDOW_SUMMARY',
  'DOCUMENT_PIPELINE_JS_CHECK', 'WORD_LAUNCH_JS_CHECK', 'RUNTIME_IPC', 'WINDOW_SESSION_GLOBAL_CHECK', 'RUNTIME_WINDOW_SESSION'];
// properties that describe the finding, not the app's data
const SAFE_PROPERTIES = ['channel', 'capabilities', 'issue', 'validatesArguments', 'argumentsUsed', 'source', 'operation', 'call', 'hygiene', 'gate', 'behavior',
  'library', 'purpose', 'process', 'launcher', 'locate', 'shell', 'flags', 'directives', 'partition', 'event', 'blocks', 'store', 'kind', 'settings', 'preload',
  'window', 'world', 'members', 'channels', 'senders', 'windows', 'passThrough', 'live', 'sink', 'marker', 'permission', 'default', 'fields', 'method', 'maps',
  'inline', 'withSources', 'total', 'counts', 'kev', 'backported', 'name', 'version', 'advisory', 'advisories', 'package', 'chromium',
  'basis', 'unmatched', 'entryPoints', 'blocked', 'status', 'validationStatus'];

// Replaces what a sanitizer from the diagnostics report doesn't: user folders, query strings, e-mail and IP addresses, secrets
function extraRedaction(text) {
  return redactText(String(text))
    .replace(/\b[A-Za-z]:\\Users\\[^\\\s"'<>]+/g, 'C:\\Users\\<user>')
    .replace(/\/(home|Users)\/[^/\s"'<>]+/g, '/$1/<user>')
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>?#]*)[?#][^\s'"<>)]*/gi, '$1')
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b/g, '<email>')
    .replace(/\b(?!127\.)(\d{1,3}\.){3}\d{1,3}\b/g, '<ip>');
}

/** Code with its strings and comments masked: literals that could carry data become <str>, short identifiers stay. */
export function maskCode(code, clean) {
  // short, lowercase code tokens stay (channels, flags, schemes, file names); words with capitals are masked: names
  const safe = (text) => text.length <= 40 && /^[\w:./@#=&%+|-]*$/.test(text) && !/[A-Z]/.test(text) && !looksRandomSecret(text);
  // template text keeps its safe words (a command line's shape: start winword "${name}"), strings are kept or masked whole
  const maskWords = (text) => text.replace(/[^\s"'\\]+/g, word => safe(word) ? word : '…');
  let out = String(code || '').replace(/`(?:\\.|[^\\`])*`|(['"])(?:\\.|(?!\1)[^\\\n])*\1/g, (literal, quote) => {
    if (quote) return safe(literal.slice(1, -1)) ? literal : `${quote}<str>${quote}`;
    return '`' + literal.slice(1, -1).split(/(\$\{[^}]*\})/).map(part => /^\$\{/.test(part) ? part : maskWords(part)).join('') + '`';
  });
  out = out.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  out = out.replace(/\s+/g, ' ').trim();
  out = clean(out);
  return out.length > MAX_CODE ? `${out.slice(0, MAX_CODE)}…` : out;
}

const rank = (list, value) => { const i = list.indexOf(value); return i === -1 ? list.length : i; };

/**
 * @param {string} file where to write: .json for JSON, anything else for Markdown
 * @param {Object} scan { input, issues (the reported findings), suppressed, electronVersion, bundled, runtime, redact, code, version }
 */
export function buildShare(scan) {
  const terms = sensitiveTerms(scan.input, scan.redact || []);
  const sanitize = makeSanitizer(terms);
  // URL hosts also occur as bare cookie domains and in prose. Give each the same stable alias.
  const hosts = new Map();
  const collect = (value, key = '') => {
    if (typeof value === 'string') {
      for (const match of value.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>?#)]+/gi)) {
        try { const host = new URL(match[0]).hostname; if (host) hosts.set(host.toLowerCase(), `host-${crypto.createHash('sha256').update(host).digest('hex').slice(0, 8)}`); } catch { /* incomplete URL */ }
      }
      if (/^(?:host|domain)$/i.test(key) && /^[\w.-]+\.[A-Za-z]{2,}$/.test(value)) {
        const host = value.replace(/^\./, '').toLowerCase();
        hosts.set(host, `host-${crypto.createHash('sha256').update(host).digest('hex').slice(0, 8)}`);
      }
    } else if (Array.isArray(value)) value.forEach(v => collect(v, key));
    else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) collect(v, k);
  };
  for (const issue of scan.issues || []) { collect(issue.description); collect(issue.file); collect(issue.properties); }
  const clean = (text) => {
    let value = String(text ?? '');
    for (const [host, alias] of [...hosts].sort((a, b) => b[0].length - a[0].length))
      value = value.replace(new RegExp(`(^|[^\\w.-])(${host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})(?=$|[^\\w.-])`, 'gi'), (_all, before) => before + alias);
    return extraRedaction(sanitize(value));
  };
  const cleanValue = value => typeof value === 'string' ? clean(value) : Array.isArray(value) ? value.map(cleanValue) :
    value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cleanValue(item)])) : value;
  const root = scan.input ? path.resolve(scan.input) : undefined;
  const place = (file) => {
    if (!file || file === 'N/A') return 'application-wide';
    let shown = String(file);
    if (root && path.isAbsolute(shown) && (shown === root || shown.startsWith(root + path.sep))) shown = path.relative(root, shown) || path.basename(root);
    return clean(shown.split(path.sep).join('/'));
  };
  const properties = (props) => {
    if (!props || typeof props !== 'object') return undefined;
    const out = {};
    for (const key of SAFE_PROPERTIES) {
      if (props[key] === undefined || props[key] === null || props[key] === '') continue;
      let value = props[key];
      out[key] = cleanValue(value);
    }
    return Object.keys(out).length ? out : undefined;
  };
  const findings = [...scan.issues]
    .sort((a, b) => rank(SEVERITIES, a.severity.name) - rank(SEVERITIES, b.severity.name) || rank(CONFIDENCES, a.confidence.name) - rank(CONFIDENCES, b.confidence.name))
    .map(issue => ({
      id: issue.id,
      severity: issue.severity.name,
      confidence: issue.confidence.name,
      exploitableBy: consequenceOf(issue.id)?.label,
      interaction: interactionOf(issue.id),
      needsReview: !!issue.manualReview,
      runtime: issue.validation ? issue.validation.status : undefined,
      runtimeEvidence: issue.validation ? clean(issue.validation.text) : undefined,
      file: place(issue.file),
      line: issue.location && issue.location.line ? issue.location.line : undefined,
      description: clean(issue.description),
      properties: properties(issue.properties),
      code: scan.code && issue.sample ? maskCode(issue.sample, clean) : undefined,
    }));
  const count = (key) => findings.reduce((acc, f) => { const k = f[key] || 'Other'; acc[k] = (acc[k] || 0) + 1; return acc; }, {});
  const bundled = scan.bundled || {};
  return {
    about: 'Electronegativity findings, redacted for sharing: app, company and user names (and --redact terms), user folders, hosts (pseudonyms), query strings, e-mail and IP addresses and secret-like values are replaced; code is ' +
      (scan.code ? 'included with its strings and comments masked' : 'left out') + '. Review this file before sending it.',
    tool: scan.version,
    electron: scan.electronVersion || 'not detected',
    bundled: Object.fromEntries(Object.entries({ chromium: bundled.chromium, node: bundled.node }).filter(([, v]) => v)),
    watchSession: !!scan.runtime,
    redactedTerms: terms.length,
    counts: { total: findings.length, bySeverity: count('severity'), byExploitableBy: count('exploitableBy'), acceptedOrSuppressed: (scan.suppressed || []).length },
    findings,
  };
}

function markdown(report) {
  const lines = [];
  const counts = report.counts;
  lines.push('# Electronegativity findings (redacted for sharing)', '', `> ${report.about}`, '');
  lines.push(`- Tool ${report.tool}; Electron ${report.electron}${report.bundled.chromium ? ` (Chromium ${report.bundled.chromium}${report.bundled.node ? `, Node.js ${report.bundled.node}` : ''})` : ''}; ${report.watchSession ? 'includes a watch session' : 'static scan only'}`);
  lines.push(`- ${counts.total} findings: ${SEVERITIES.filter(s => counts.bySeverity[s]).map(s => `${counts.bySeverity[s]} ${s.toLowerCase()}`).join(', ')}${counts.acceptedOrSuppressed ? `; ${counts.acceptedOrSuppressed} accepted/suppressed, not listed` : ''}`);
  lines.push(`- Potential source of input (based on check type): ${Object.entries(counts.byExploitableBy).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', ')}`, '');

  const groups = new Map();
  for (const f of report.findings) {
    if (!groups.has(f.id)) groups.set(f.id, []);
    groups.get(f.id).push(f);
  }
  const actionable = [...groups].filter(([, list]) => list.some(f => f.severity !== 'INFORMATIONAL'));
  const inventory = [...groups].filter(([id, list]) => list.every(f => f.severity === 'INFORMATIONAL') && INVENTORY.includes(id));
  const other = [...groups].filter(([id, list]) => list.every(f => f.severity === 'INFORMATIONAL') && !INVENTORY.includes(id));

  const entry = (f, n) => {
    const where = `${f.file}${f.line ? `:${f.line}` : ''}`;
    const tags = [f.runtime ? `runtime: ${f.runtime}` : undefined, f.needsReview ? 'needs review' : undefined].filter(Boolean);
    lines.push(`${n}. **${f.severity}/${f.confidence}** \`${where}\`${tags.length ? ` (${tags.join(', ')})` : ''}: ${f.description}`);
    if (f.runtimeEvidence) lines.push(`   - runtime evidence: ${f.runtimeEvidence}`);
    if (f.properties) lines.push(`   - details: \`${JSON.stringify(f.properties)}\``);
    if (f.code) lines.push('   ```js', `   ${f.code}`, '   ```');
  };
  const section = (title, list) => {
    if (list.length === 0) return;
    lines.push(`## ${title}`, '');
    for (const [id, items] of list) {
      const bySeverity = SEVERITIES.filter(s => items.some(f => f.severity === s)).map(s => `${items.filter(f => f.severity === s).length} ${s.toLowerCase()}`).join(', ');
      const first = items[0];
      lines.push(`### ${id} (${bySeverity})`, '');
      if (first.exploitableBy) lines.push(`Potential input source: ${first.exploitableBy}. Possible interaction: ${first.interaction || 'n/a'}. These are check-level threat models, not verified exploit conditions.`, '');
      items.forEach((f, i) => entry(f, i + 1));
      lines.push('');
    }
  };
  section('Findings, most severe first', actionable);
  section('Inventory (informational)', inventory);
  section('Other informational findings', other);
  return lines.join('\n');
}

/** Writes the shareable report: JSON for a .json file, Markdown otherwise. Returns the report. */
export function writeShare(file, scan) {
  const report = buildShare(scan);
  fs.writeFileSync(file, /\.json$/i.test(file) ? JSON.stringify(report, null, 2) : markdown(report));
  return report;
}
