// Accepted risks by rule (--suppress) and comparison with a previous scan (--compare). A baseline (--baseline) accepts
// findings one by one; a suppressions file accepts them by check, file or text, with a reason, an owner and an expiry
// date. --compare reads an earlier JSON report and marks each finding new, unchanged or changed in severity, and lists
// what was fixed since. From Electron-Dynamic's triage.py.
import fs from 'node:fs';
import path from 'node:path';
import { fingerprints } from './baseline.js';

// shell-style glob (* and ?) as a regular expression, matched against the whole value
const glob = (pattern) => new RegExp(`^${String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');

/**
 * {"suppressions": [{ "fingerprint" | "check" | "file", "match"?, "reason", "owner"?, "expires"? }]}. "check" accepts a
 * trailing * (TRAFFIC_*); "file" is a glob over the finding's file or host; "match" a case-insensitive substring of its
 * description or code. Returns { entries, notes }: entries without a reason or a selector, and expired ones, are left
 * out with a note.
 */
export function loadSuppressions(file, today = new Date().toISOString().slice(0, 10)) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const list = Array.isArray(data) ? data : data && data.suppressions;
  if (!Array.isArray(list)) throw new Error(`${file}: expected a list under "suppressions"`);
  const entries = [];
  const notes = [];
  list.forEach((entry, i) => {
    const check = entry && (entry.check || entry.rule || entry.id);
    if (!entry || !entry.reason || !(entry.fingerprint || check || entry.file)) {
      notes.push(`suppression #${i + 1} ignored: it needs a "reason" and one of "fingerprint", "check" or "file"`);
      return;
    }
    if (entry.expires && String(entry.expires) < today) {
      notes.push(`suppression #${i + 1} expired on ${entry.expires} and was not applied (${entry.reason})`);
      return;
    }
    entries.push({ ...entry, check, index: i + 1 });
  });
  return { entries, notes };
}

function matches(entry, issue, fingerprint) {
  if (entry.fingerprint && entry.fingerprint !== fingerprint) return false;
  if (entry.check && !(entry.check.endsWith('*') ? String(issue.id).startsWith(entry.check.slice(0, -1)) : entry.check === issue.id)) return false;
  if (entry.file && !glob(entry.file).test(String(issue.file).split(path.sep).join('/')) && !glob(`*/${entry.file}`).test(String(issue.file).split(path.sep).join('/'))) return false;
  if (entry.match && !`${issue.description} ${issue.sample || ''}`.toLowerCase().includes(String(entry.match).toLowerCase())) return false;
  return true;
}

/** Splits issues into { kept, suppressed, notes }; suppressed issues carry `suppression`. */
export function applySuppressions(issues, entries, root) {
  const prints = fingerprints(issues, root);
  const used = new Set();
  const kept = [];
  const suppressed = [];
  issues.forEach((issue, i) => {
    const entry = entries.find(e => matches(e, issue, prints[i].fingerprint));
    if (!entry) return kept.push(issue);
    used.add(entry);
    suppressed.push({ ...issue, suppression: { reason: entry.reason, owner: entry.owner, expires: entry.expires, source: 'suppressions' } });
  });
  const notes = entries.filter(e => !used.has(e)).map(e => `suppression #${e.index} matched nothing: ${e.fingerprint || e.check || e.file} (${e.reason})`);
  return { kept, suppressed, notes };
}

const RANK = { HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };

/**
 * Compares the findings with an earlier JSON report (its issues carry fingerprints). Sets issue.comparison on each
 * ('new' | 'unchanged' | 'changed') and returns { file, new, unchanged, changed: [...], fixed: [...] }.
 */
export function compareWithReport(issues, previousFile, root, accepted = []) {
  const previous = JSON.parse(fs.readFileSync(previousFile, 'utf8'));
  if (!previous || !Array.isArray(previous.issues)) throw new Error(`${previousFile} is not an Electronegativity JSON report`);
  const before = new Map();
  for (const old of [...previous.issues, ...(previous.suppressed || [])]) if (old.fingerprint) before.set(old.fingerprint, old);
  const prints = fingerprints(issues, root);
  const changed = [];
  let fresh = 0;
  let unchanged = 0;
  issues.forEach((issue, i) => {
    const old = before.get(prints[i].fingerprint);
    if (!old) {
      issue.comparison = 'new';
      fresh++;
    } else if (old.severity !== issue.severity.name) {
      issue.comparison = 'changed';
      changed.push({ id: issue.id, file: issue.file, from: old.severity, to: issue.severity.name, direction: RANK[issue.severity.name] > RANK[old.severity] ? 'up' : 'down' });
    } else {
      issue.comparison = 'unchanged';
      unchanged++;
    }
  });
  // findings accepted since (baseline, suppressions) are still there: not fixed
  const now = new Set([...prints, ...fingerprints(accepted, root)].map(p => p.fingerprint));
  const fixed = previous.issues.filter(old => old.fingerprint && !now.has(old.fingerprint))
    .map(old => ({ id: old.id, severity: old.severity, file: old.file, line: old.line, description: String(old.description || '').slice(0, 200) }))
    .sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0));
  return { file: previousFile, new: fresh, unchanged, changed, fixed };
}
