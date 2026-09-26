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

// Fingerprints for a list of issues, in the same order
export function fingerprints(issues, root) {
  const seen = new Map();
  return issues.map(issue => {
    const file = relativeFile(root, issue.file);
    // application-wide findings have no code: their description identifies them
    const code = issue.file === 'N/A' || !issue.sample ? issue.description : normalizeSample(issue.sample);
    const key = `${issue.id}|${file}|${code}`;
    const occurrence = (seen.get(key) || 0) + 1;
    seen.set(key, occurrence);
    return { fingerprint: crypto.createHash('sha256').update(`${key}|${occurrence}`).digest('hex').slice(0, 24), file, code };
  });
}

export function loadBaseline(file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!data || !Array.isArray(data.findings)) throw new Error(`${file} is not an Electronegativity baseline`);
  return data;
}

/**
 * Splits issues into the ones to report and the ones accepted by the baseline.
 * Returns { kept, suppressed, stale } where stale are baseline entries that no longer match anything.
 */
export function applyBaseline(issues, baseline, root) {
  const accepted = new Map(baseline.findings.map(f => [f.fingerprint, f]));
  const prints = fingerprints(issues, root);
  const kept = [];
  const suppressed = [];
  const matched = new Set();
  issues.forEach((issue, i) => {
    const entry = accepted.get(prints[i].fingerprint);
    if (entry) {
      matched.add(entry.fingerprint);
      suppressed.push({ ...issue, baselineReason: entry.reason });
    } else {
      kept.push(issue);
    }
  });
  const stale = baseline.findings.filter(f => !matched.has(f.fingerprint));
  return { kept, suppressed, stale };
}

// Writes the current findings as a baseline, keeping the reasons already recorded for known findings
export function writeBaseline(file, issues, root, previous) {
  const reasons = new Map((previous ? previous.findings : []).map(f => [f.fingerprint, f.reason]));
  const prints = fingerprints(issues, root);
  const findings = issues.map((issue, i) => ({
    fingerprint: prints[i].fingerprint,
    id: issue.id,
    severity: issue.severity.name,
    file: prints[i].file,
    code: prints[i].code,
    reason: reasons.get(prints[i].fingerprint) || ''
  }));
  fs.writeFileSync(file, JSON.stringify({ version: BASELINE_VERSION, generatedAt: new Date().toISOString(), findings }, null, 2) + '\n');
  return findings.length;
}
