// A findings report redacted for sharing (--share), e.g. to get a second opinion on what to fix first without handing
// over the app. It keeps what judging a finding needs (check, severity, confidence, who can exploit it, what the victim
// has to do, runtime confirmation, the file's place in the app and line, the description) and removes what identifies
// the app or its users: the app, company and user names (and --redact terms), the home folder and user folders, hosts
// (stable pseudonyms), query strings, e-mail and IP addresses, and anything that looks like a secret. Code is left out
// unless asked for (--share-code), and then its strings and comments are masked. A last pass over everything written
// replaces any of the names that survived (its count is in the report's audit). Review the file before sending it.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { createRequire } from 'node:module';
import { sensitiveTerms, makeSanitizer, isHostname } from '../util/diagnostics.js';
import { consequenceOf, interactionOf } from '../finder/consequences.js';
import { remediationOf } from '../finder/remediation.js';

const require = createRequire(import.meta.url);
const { redactText, looksRandomSecret } = require('../traffic/secrets.cjs');

const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const CONFIDENCES = ['CERTAIN', 'FIRM', 'TENTATIVE'];
const MAX_CODE = 400;
// inventories worth listing even though they are informational: they are the map a reviewer needs
const INVENTORY = ['WINDOW_SUMMARY_JS_CHECK', 'EXPOSED_API_JS_CHECK', 'GLOBAL_EXPOSURE_JS_CHECK', 'IPC_HANDLER_JS_CHECK', 'IPC_CHANNEL_MAP_GLOBAL_CHECK', 'RUNTIME_WINDOW_SUMMARY',
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
    // random-looking names (a cookie named after an analytics project key) and long numeric ids in paths (a repository or account id)
    .replace(/[A-Za-z0-9]{24,}/g, token => looksRandomSecret(token) ? '<redacted>' : token)
    .replace(/(\/)\d{6,}(?=[/?#\s'"<>)]|$)/g, '$1<id>')
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>?#]*)[?#][^\s'"<>)]*/gi, '$1')
    .replace(/\\\\[^\\\s"'<>]+\\/g, '\\\\<server>\\')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>')
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b/g, '<email>')
    .replace(/\b(?!127\.)(\d{1,3}\.){3}\d{1,3}\b/g, '<ip>');
}

// Domain names written without a scheme (a cookie domain, "sign in at portal.contoso.com"). Only endings that are hardly ever
// a file extension are matched, and Electron's own names (electron.net, app.dev...) are left alone.
// (not endings that are common file extensions or code: .sh, .so, .md, .cc, .js, .ts, .in, .it, .to, .be...)
const TLDS = 'com|net|org|io|dev|app|info|biz|xyz|cloud|online|site|tech|edu|gov|mil|local|internal|corp|lan|intranet|test|example|invalid|' +
  'eu|uk|us|ca|au|de|fr|nl|jp|cn|ru|br|ch|se|dk|fi|ie|nz|za|mx|ai|co|me|tv|gg|ly|im|fm|es|pt|il|ae|sg|hk|kr|tw';
// (a leading dot, as in a cookie's domain, is kept: .linkedin.com becomes .host-1a2b3c4d)
const BARE_DOMAIN = new RegExp(`(?<![\\w@/-])(\\.?)((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:${TLDS}))(?![\\w-])(?!\\s*\\()`, 'gi');
// (two labels only: app.dev is code, app.contoso.com is a host)
const NOT_DOMAINS = /^(?:electron|app|net|process|window|document|global|module|exports|this|require|remote|shell|dialog|session|navigator|location|console|api)\.[^.]+$/i;
// findings whose text carries the secret values themselves when the run used --show-secrets (traffic, data at rest, consoles)
const REVEALS_SECRETS = /^(TRAFFIC_|STORAGE_|RUNTIME_SECRET_IN_CONSOLE)/;
// public documentation sites that name no one
const PUBLIC_HOSTS = /(?:^|\.)(?:electronjs\.org|nodejs\.org|mozilla\.org|owasp\.org|mitre\.org|github\.com|npmjs\.com|w3\.org|chromium\.org|example\.com|example\.org|example\.net)$/i;
const hostAlias = (host) => `host-${crypto.createHash('sha256').update(host.toLowerCase()).digest('hex').slice(0, 8)}`;

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
        try { const url = new URL(match[0]); if (url.protocol !== 'file:' && isHostname(url.hostname)) hosts.set(url.hostname.toLowerCase(), hostAlias(url.hostname)); } catch { /* incomplete URL */ }
      }
      if (/^(?:host|domain)$/i.test(key) && /^[\w.-]+\.[A-Za-z]{2,}$/.test(value)) {
        const host = value.replace(/^\./, '').toLowerCase();
        hosts.set(host, hostAlias(host));
      }
    } else if (Array.isArray(value)) value.forEach(v => collect(v, key));
    else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) collect(v, k);
  };
  for (const issue of scan.issues || []) {
    collect(issue.description); collect(issue.file); collect(issue.properties); collect(issue.validation && issue.validation.text);
    if (scan.code) collect(issue.sample);
  }
  const clean = (text) => {
    let value = String(text ?? '');
    for (const [host, alias] of [...hosts].sort((a, b) => b[0].length - a[0].length))
      value = value.replace(new RegExp(`(^|[^\\w.-])(${host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})(?=$|[^\\w.-])`, 'gi'), (_all, before) => before + alias);
    value = extraRedaction(sanitize(value));
    return value.replace(BARE_DOMAIN, (all, dot, domain) => NOT_DOMAINS.test(domain) || PUBLIC_HOSTS.test(domain) ? all : dot + hostAlias(domain));
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
  // with --show-secrets these findings' text holds full secret values that pattern redaction can't be trusted to catch
  const withheld = (issue) => !!scan.reveal && REVEALS_SECRETS.test(issue.id);
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
      runtimeEvidence: issue.validation && !withheld(issue) ? clean(issue.validation.text) : undefined,
      file: place(issue.file),
      line: issue.location && issue.location.line ? issue.location.line : undefined,
      description: withheld(issue) ? 'Details withheld: this run used --show-secrets, so the finding\'s text holds secret values. Run without it to share them.' : clean(issue.description),
      remediation: remediationOf(issue.id)?.fix,
      properties: properties(issue.properties),
      // (never with --show-secrets: the samples of that run can hold full secret values)
      code: scan.code && !scan.reveal && issue.sample ? maskCode(issue.sample, clean) : undefined,
    }));
  const count = (key) => findings.reduce((acc, f) => { const k = f[key] || 'Other'; acc[k] = (acc[k] || 0) + 1; return acc; }, {});
  const bundled = scan.bundled || {};
  const report = {
    about: 'Electronegativity findings, redacted for sharing: app, company and user names (and --redact terms), user folders, hosts (pseudonyms), query strings, e-mail and IP addresses and secret-like values are replaced; code is ' +
      (scan.code && scan.reveal ? 'left out because the run used --show-secrets' : scan.code ? 'included with its strings and comments masked' : 'left out') +
      (scan.reveal ? '; the text of traffic, data-at-rest and console-secret findings is withheld because the run used --show-secrets' : '') + '. Review this file before sending it.',
    tool: scan.version,
    electron: scan.electronVersion || 'not detected',
    bundled: Object.fromEntries(Object.entries({ chromium: bundled.chromium, node: bundled.node }).filter(([, v]) => v)),
    watchSession: !!scan.runtime,
    redactedTerms: terms.length,
    counts: { total: findings.length, bySeverity: count('severity'), byExploitableBy: count('exploitableBy'), acceptedOrSuppressed: (scan.suppressed || []).length },
    findings,
  };
  return finalPass(report, terms, [scan.input && path.resolve(scan.input), os.homedir()]);
}

/**
 * The last check on everything that will be written: the app, company, user and machine names and the input and home
 * folders must not appear anywhere, whatever put them there. What is left is replaced; the count says how many were.
 */
function finalPass(report, terms, folders) {
  const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const literals = [...terms, ...folders.filter(folder => folder && folder.length > 1)].sort((a, b) => b.length - a.length).map(escape);
  let replaced = 0;
  const scrub = literals.length === 0 ? (value) => value : (() => {
    // replacements made earlier (<redacted>, host-1a2b3c4d...) are kept: a short term must not eat into them
    const pattern = new RegExp(`(<[a-z-]+>|host-[0-9a-f]{8})|(${literals.join('|')})`, 'gi');
    return (text) => text.replace(pattern, (match, kept) => { if (kept) return match; replaced++; return '<redacted>'; });
  })();
  const walk = (value) => typeof value === 'string' ? scrub(value) : Array.isArray(value) ? value.map(walk) :
    value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, walk(item)])) : value;
  // only what came from the scan: the report's own wording ("redacted for sharing") must not be eaten by a short term
  const cleaned = { ...report, findings: walk(report.findings) };
  cleaned.audit = { finalPassReplacements: replaced };
  return cleaned;
}

// the scan's text on one line, its Markdown and HTML syntax escaped
const inline = (value) => String(value ?? '').replace(/\s+/g, ' ').trim().replace(/[\\`*[\]<>]/g, '\\$&');
function codeSpan(value) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  const fence = '`'.repeat(Math.max(0, ...[...text.matchAll(/`+/g)].map(m => m[0].length)) + 1);
  const pad = text.startsWith('`') || text.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${text}${pad}${fence}`;
}

function markdown(report) {
  const lines = [];
  const counts = report.counts;
  lines.push('# Electronegativity findings (redacted for sharing)', '', `> ${report.about}`, '');
  lines.push('**Reading this report (for a reviewer or an AI agent).** It was made from a scan of an Electron application whose identity has been removed on purpose: ' +
    'names appear as `<redacted>`, web hosts as `host-xxxxxxxx` (the same host always has the same alias), and addresses, folders and secrets as `<email>`, `<ip>`, `<user>`, `<uuid>` or `<redacted>`. ' +
    'Do not try to work out who the application or its owner is. Findings are ordered by severity; "Potential input source" is a check-level threat model, not a proven exploit. ' +
    'Useful replies: which findings to fix first and why, likely false positives, and how to confirm or fix each one.', '');
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
    lines.push(`${n}. **${f.severity}/${f.confidence}** ${codeSpan(where)}${tags.length ? ` (${tags.join(', ')})` : ''}: ${inline(f.description)}`);
    if (f.runtimeEvidence) lines.push(`   - runtime evidence: ${inline(f.runtimeEvidence)}`);
    if (f.properties) lines.push(`   - details: ${codeSpan(JSON.stringify(f.properties))}`);
    if (f.code) {
      const fence = '`'.repeat(Math.max(3, ...[...f.code.matchAll(/`{3,}/g)].map(m => m[0].length + 1)));
      lines.push(`   ${fence}js`, `   ${f.code}`, `   ${fence}`);
    }
  };
  const section = (title, list) => {
    if (list.length === 0) return;
    lines.push(`## ${title}`, '');
    for (const [id, items] of list) {
      const bySeverity = SEVERITIES.filter(s => items.some(f => f.severity === s)).map(s => `${items.filter(f => f.severity === s).length} ${s.toLowerCase()}`).join(', ');
      const first = items[0];
      lines.push(`### ${id} (${bySeverity})`, '');
      if (first.exploitableBy) lines.push(`Potential input source: ${first.exploitableBy}. Possible interaction: ${first.interaction || 'n/a'}. These are check-level threat models, not verified exploit conditions.`, '');
      if (first.remediation) lines.push(`How to fix: ${first.remediation}`, '');
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
