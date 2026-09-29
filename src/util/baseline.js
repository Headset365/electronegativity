// Baselines record findings that were reviewed and accepted, so later scans only report what's new.
// Findings are matched by a fingerprint that survives unrelated edits: check id, file (relative to the scanned
// folder), the trimmed code of the line and its occurrence number among identical findings; not the line number.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const BASELINE_VERSION = 1;

function relativeFile(root, file) {
  if (!file || file === 'N/A' || !path.isAbsolute(file)) return (file || 'N/A').split(path.sep).join('/');
  let base = root;
  try {
    if (!fs.statSync(root).isDirectory()) base = path.dirname(root);
  } catch { /* keep root */ }
  return path.relative(base, file).split(path.sep).join('/');
}

function normalizeSample(sample) {
  return (sample || '').replace(/\s+/g, ' ').trim();
}

// A description without the counts and lists that change with upstream data ("misses 4157 upstream security fixes
// (376 critical, ...)", "(41: GHSA-...)"), which would make an unchanged finding look new every time advisories are published
function stableDescription(text) {
  return String(text || '').replace(/\([^()]*[,:][^()]*\)/g, '()').replace(/\d+/g, '#').replace(/\s+/g, ' ').trim();
}

const hash = (text) => crypto.createHash('sha256').update(text).digest('hex').slice(0, 24);

/**
 * Fingerprints for a list of issues, in the same order: { fingerprint, legacy, file, code }. `legacy` is the fingerprint
 * earlier versions gave the finding (the whole description of a finding without code), still accepted when matching
 * baselines, suppressions and earlier reports.
 */
export function fingerprints(issues, root) {
  const seen = new Map();
  const count = (key) => {
    const occurrence = (seen.get(key) || 0) + 1;
    seen.set(key, occurrence);
    return occurrence;
  };
  return issues.map(issue => {
    const file = relativeFile(root, issue.file);
    // application-wide findings and those without code: their description identifies them
    const described = issue.file === 'N/A' || !issue.sample;
    const code = described ? issue.description : normalizeSample(issue.sample);
    const key = `${issue.id}|${file}|${described ? stableDescription(code) : code}`;
    const fingerprint = hash(`${key}|${count(key)}`);
    const legacyKey = described ? `legacy|${issue.id}|${file}|${issue.description}` : undefined;
    const legacy = legacyKey ? hash(`${legacyKey.slice('legacy|'.length)}|${count(legacyKey)}`) : fingerprint;
    return { fingerprint, legacy, file, code };
  });
}

/**
 * An expiry date as YYYY-MM-DD (2026-9-1 is padded), or undefined when it isn't a real date in that form: dates are
 * compared as text, and 31/12/2026 or 2026-9-1 would otherwise never expire.
 */
export function expiryDate(value) {
  const m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(String(value ?? '').trim());
  if (!m) return undefined;
  const iso = `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
  const date = new Date(`${iso}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === iso ? iso : undefined;
}

// an entry past its expiry date no longer accepts its finding; neither does one whose date can't be read
const lapsed = (expires, today) => expires !== undefined && expires !== null && expires !== '' && !(expiryDate(expires) >= today);

export function loadBaseline(file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!data || !Array.isArray(data.findings)) throw new Error(`${file} is not an Electronegativity baseline`);
  return data;
}

/**
 * Splits issues into the ones to report and the ones accepted by the baseline.
 * Returns { kept, suppressed, stale } where stale are baseline entries that no longer match anything.
 */
export function applyBaseline(issues, baseline, root, today = new Date().toISOString().slice(0, 10)) {
  const expired = baseline.findings.filter(f => lapsed(f.expires, today)).map(f => expiryDate(f.expires) ? f : { ...f, invalidExpiry: true });
  const expiredPrints = new Set(expired.map(f => f.fingerprint));
  const accepted = new Map(baseline.findings.filter(f => !expiredPrints.has(f.fingerprint)).map(f => [f.fingerprint, f]));
  const prints = fingerprints(issues, root);
  const kept = [];
  const suppressed = [];
  const matched = new Set();
  issues.forEach((issue, i) => {
    const entry = accepted.get(prints[i].fingerprint) || accepted.get(prints[i].legacy);
    if (entry) {
      matched.add(entry.fingerprint);
      suppressed.push({ ...issue, baselineReason: entry.reason, suppression: { reason: entry.reason, owner: entry.owner, expires: entry.expires, source: 'baseline' } });
    } else {
      kept.push(issue);
    }
  });
  const stale = baseline.findings.filter(f => !matched.has(f.fingerprint) && !expiredPrints.has(f.fingerprint));
  return { kept, suppressed, stale, expired };
}

// Writes the current findings as a baseline, keeping the reasons already recorded for known findings
export function writeBaseline(file, issues, root, previous) {
  const known = new Map((previous ? previous.findings : []).map(f => [f.fingerprint, f]));
  const prints = fingerprints(issues, root);
  const findings = issues.map((issue, i) => {
    // (an entry written by an earlier version is found by its legacy fingerprint, and rewritten with the new one)
    const before = known.get(prints[i].fingerprint) || known.get(prints[i].legacy) || {};
    return {
      fingerprint: prints[i].fingerprint,
      id: issue.id,
      severity: issue.severity.name,
      file: prints[i].file,
      code: prints[i].code,
      reason: before.reason || '',
      // who accepted it, and until when (optional; kept when the baseline is rewritten)
      ...(before.owner ? { owner: before.owner } : {}),
      ...(before.expires ? { expires: before.expires } : {}),
    };
  });
  fs.writeFileSync(file, JSON.stringify({ version: BASELINE_VERSION, generatedAt: new Date().toISOString(), findings }, null, 2) + '\n');
  return findings.length;
}
