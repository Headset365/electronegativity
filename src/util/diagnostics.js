// Diagnostics for troubleshooting a scan without sharing the app: what was scanned or skipped, parse errors, checks that
// failed or ran slowly, network lookups that failed and what watch mode captured. Never finding descriptions, code or
// data that passed through the app. Everything is sanitized before it is written: the app's name, the user name, the
// machine name, the home folder and any extra terms are replaced, and hosts in URLs are pseudonymized.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

let current;

// The collector of the running scan, or undefined when --diagnostics wasn't given
export function diagnostics() {
  return current;
}

export function startDiagnostics() {
  current = new Diagnostics();
  return current;
}

export function stopDiagnostics() {
  current = undefined;
}

// Records something that went wrong or is worth knowing (network failures, hook status...), when diagnostics are on
export function note(kind, data) {
  if (current) current.events.push({ kind, ...data });
}

class Diagnostics {
  constructor() {
    this.startedAt = Date.now();
    this.phases = {};
    this.checks = new Map(); // check name -> { calls, ms, errors }
    this.events = [];
  }

  phase(name, ms) {
    this.phases[name] = Math.round((this.phases[name] || 0) + ms);
  }

  // `calls` > 1 when the run stands for a sample of that many calls (see Finder.runCheck)
  checkRun(name, ms, error, file, calls = 1) {
    if (!this.checks.has(name)) this.checks.set(name, { calls: 0, ms: 0, errors: [] });
    const entry = this.checks.get(name);
    entry.calls += calls;
    entry.ms += ms;
    if (error && entry.errors.length < 20) entry.errors.push({ file, message: String(error && error.message || error), stack: firstFrames(error) });
  }
}

// the top frames of a stack, which point into the tool's own code rather than the app's
function firstFrames(error) {
  if (!error || !error.stack) return undefined;
  return error.stack.split('\n').slice(1, 4).map(line => line.trim());
}

/**
 * Terms that identify the app, its developer or the machine, to replace in the report: the package.json name and
 * productName (with -, _, space and joined variants), the app folder name, the user name, the host name and extra
 * terms given with --redact.
 */
export function sensitiveTerms(input, extra = []) {
  const terms = new Set();
  const add = (value) => {
    if (typeof value !== 'string') return;
    const cleaned = value.replace(/^@/, '').trim();
    for (const part of [cleaned, ...cleaned.split('/')]) {
      if (part.length < 3) continue;
      terms.add(part);
      const words = part.split(/[-_ .]+/).filter(Boolean);
      if (words.length > 1) for (const joiner of ['', ' ', '-', '_', '.']) terms.add(words.join(joiner));
    }
  };
  // hosts and paths of a link: the owner in a repository URL or the company in a domain is a client name
  const CODE_HOSTS = /^(?:www\.)?(?:github|gitlab|bitbucket|npmjs|sourceforge)\.(?:com|org)$/i;
  const GENERIC_LABELS = /^(?:www|com|org|net|io|dev|app|co|edu|gov|info|git|issues|tree|blob|tags|releases|wiki|http|https|api)$/i;
  const addLink = (value) => {
    if (typeof value !== 'string') return;
    let url;
    try { url = new URL(value.replace(/^git\+/, '').replace(/^git@([^:]+):/, 'https://$1/')); } catch { return; }
    if (!CODE_HOSTS.test(url.hostname)) {
      add(url.hostname.replace(/^www\./, ''));
      for (const label of url.hostname.split('.')) if (!GENERIC_LABELS.test(label)) add(label);
    }
    for (const segment of url.pathname.split('/')) if (segment && !GENERIC_LABELS.test(segment.replace(/\.git$/i, ''))) add(segment.replace(/\.git$/i, ''));
  };
  const addEmail = (value) => {
    if (typeof value !== 'string' || !value.includes('@')) return;
    const [local, domain] = value.split('@');
    if (!/^(?:info|support|contact|hello|admin|team|dev|security|noreply|no-reply|mail|office|sales)$/i.test(local)) add(local);
    addLink(`https://${domain}`);
  };
  const resolved = input ? path.resolve(input) : undefined;
  // the project folder: the input itself, or the app folder around resources/app.asar
  const folders = [];
  if (resolved) {
    folders.push(resolved);
    const packaged = resolved.match(/^(.*?)[\\/](?:Contents[\\/])?resources[\\/]app(\.asar)?$/i);
    if (packaged) folders.push(packaged[1]);
  }
  for (const folder of folders) {
    const base = path.basename(folder).replace(/\.(app|asar)$/i, '');
    if (!/^(src|app|resources|dist|build|out)$/i.test(base)) add(base);
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(folder, 'package.json'), 'utf8'));
      add(manifest.name);
      add(manifest.productName);
      if (manifest.build) {
        add(manifest.build.productName);
        if (typeof manifest.build.appId === 'string') manifest.build.appId.split('.').forEach(add);
      }
      const author = typeof manifest.author === 'string' ? manifest.author.replace(/<.*?>|\(.*?\)/g, '') : manifest.author && manifest.author.name;
      add(author);
      // who the app belongs to shows in its links, contact addresses and publisher fields too
      for (const person of [manifest.author, ...(Array.isArray(manifest.contributors) ? manifest.contributors : [])]) {
        if (typeof person === 'string') { addEmail(person.match(/<([^>]+)>/)?.[1]); addLink(person.match(/\(([^)]+)\)/)?.[1]); }
        else if (person && typeof person === 'object') { add(person.name); addEmail(person.email); addLink(person.url); }
      }
      for (const link of [manifest.homepage, manifest.repository, manifest.bugs]) addLink(typeof link === 'string' ? link : link && link.url);
      if (manifest.build) {
        add(typeof manifest.build.copyright === 'string' ? manifest.build.copyright.replace(/copyright|\(c\)|©|\d{4}(\s*[-–]\s*\d{4})?/gi, '').trim() : undefined);
        for (const publish of [].concat(manifest.build.publish || [])) { if (publish && typeof publish === 'object') { add(publish.owner); addLink(publish.url); } }
        for (const publisher of [].concat(manifest.build.win && manifest.build.win.publisherName || [])) add(publisher);
      }
    } catch {
      // no readable package.json there
    }
  }
  try {
    add(os.userInfo().username);
  } catch {
    // no user info on this platform
  }
  add(os.hostname());
  for (const term of extra) add(term);
  // generic words that would wreck the report if replaced
  for (const generic of ['electron', 'main', 'renderer', 'preload', 'index', 'node_modules', 'package', 'test', 'user', 'root', 'admin', 'com', 'org', 'net', 'app', 'www', 'github', 'gitlab', 'http', 'https']) terms.delete(generic);
  return [...terms].sort((a, b) => b.length - a.length);
}

/** Returns a sanitizer that replaces the terms, the home folder, and pseudonymizes hosts in URLs. */
export function makeSanitizer(terms) {
  const home = os.homedir();
  const escaped = terms.map(term => term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const pattern = escaped.length > 0 ? new RegExp(escaped.join('|'), 'gi') : undefined;
  const hosts = new Map();
  const pseudonym = (host) => {
    if (/^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i.test(host)) return host;
    if (!hosts.has(host)) hosts.set(host, `host-${crypto.createHash('sha256').update(host).digest('hex').slice(0, 8)}`);
    return hosts.get(host);
  };
  const sanitizeString = (text) => {
    let out = String(text);
    if (home && home.length > 1) out = out.split(home).join('<home>');
    out = out.replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:'"<>]+)/gi, (match, scheme, host) => `${scheme}${pseudonym(host)}`);
    if (pattern) out = out.replace(pattern, '<redacted>');
    return out;
  };
  const sanitize = (value) => {
    if (typeof value === 'string') return sanitizeString(value);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [sanitizeString(k), sanitize(v)]));
    return value;
  };
  return sanitize;
}

/**
 * Builds the report and writes it, sanitized. `scan` holds what the runner gathered: input, loader counts, errors,
 * issues, runtime summary...
 */
export function writeDiagnostics(file, scan, { redact = [], version } = {}) {
  const collector = current;
  const terms = sensitiveTerms(scan.input, redact);
  const sanitize = makeSanitizer(terms);
  const bySeverity = {};
  const byCheck = {};
  for (const issue of scan.issues || []) {
    const key = `${issue.severity.name}/${issue.confidence.name}`;
    bySeverity[issue.severity.name] = (bySeverity[issue.severity.name] || 0) + 1;
    byCheck[issue.id] = byCheck[issue.id] || {};
    byCheck[issue.id][key] = (byCheck[issue.id][key] || 0) + 1;
  }
  const relative = (f) => scan.input && typeof f === 'string' && path.isAbsolute(f) ? path.relative(scan.input, f) || path.basename(f) : f;
  const checks = collector ? [...collector.checks.entries()].map(([name, c]) => ({ name, calls: c.calls, ms: Math.round(c.ms), errors: c.errors.map(e => ({ ...e, file: relative(e.file) })) }))
    .sort((a, b) => b.ms - a.ms) : [];
  const report = {
    about: 'Electronegativity diagnostics. Sanitized: the app name, user name, machine name, home folder and --redact terms are replaced, hosts are pseudonymized. Contains no code, finding descriptions or data that passed through the app. Review it before sharing.',
    tool: { version, node: process.version, platform: process.platform, arch: process.arch },
    options: scan.options,
    input: { type: scan.inputType, electronVersion: scan.electronVersion || null, electronVersionSource: scan.electronVersionSource, ...scan.files },
    durationMs: collector ? Date.now() - collector.startedAt : undefined,
    phasesMs: collector ? collector.phases : undefined,
    errors: (scan.errors || []).map(e => ({ file: relative(e.file), message: e.message, tolerable: !!e.tolerable, check: e.check })),
    checks: { failed: checks.filter(c => c.errors.length > 0), slowest: checks.slice(0, 10).map(({ name, calls, ms }) => ({ name, calls, ms })) },
    findings: { total: (scan.issues || []).length, bySeverity, byCheck },
    events: collector ? collector.events : [],
    watch: scan.watch,
    remote: scan.remote,
    dependencies: scan.dependencies,
    redactedTerms: terms.length,
  };
  fs.writeFileSync(file, JSON.stringify(sanitize(report), null, 2));
  return report;
}
