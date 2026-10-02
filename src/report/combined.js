// The final report of a guided run (--app): the static scan and every watch session as one report, each finding once with
// the validation each session recorded, written after the last step. Each step's own reports stay in steps/ as backups.
import fs from 'node:fs';
import path from 'node:path';
import { combineRuns } from './markdown.js';
import { writeShare } from './share.js';
import { writeIssues, writeReports } from '../util/index.js';
import { checkComponentLinks } from '../util/link_check.js';

const unique = (values) => [...new Set(values)];

/**
 * The components of several steps, each once: a library a session downloaded joins the static scan's inventory, and what
 * one step found out about a component (its latest version, advisories, link checks) is kept.
 */
export function mergeDependencies(reports) {
  const present = reports.filter(Boolean);
  if (present.length === 0) return undefined;
  const byKey = new Map();
  for (const report of present) for (const row of report.rows || []) {
    const key = `${row.name}@${row.version}`;
    const earlier = byKey.get(key);
    if (!earlier) {
      byKey.set(key, { ...row, kinds: [...(row.kinds || [])], files: [...(row.files || [])], locations: [...(row.locations || [])] });
      continue;
    }
    // the step that could look the component up wins over one that could not
    const base = !earlier.latest && row.latest ? { ...row } : earlier;
    byKey.set(key, { ...base, kinds: unique([...(earlier.kinds || []), ...(row.kinds || [])]), files: unique([...(earlier.files || []), ...(row.files || [])]).slice(0, 5),
      locations: unique([...(earlier.locations || []), ...(row.locations || [])]), dev: earlier.dev !== false && row.dev !== false,
      advisories: (row.advisories || []).length > (earlier.advisories || []).length ? row.advisories : earlier.advisories });
  }
  const last = (field) => present.map(report => report[field]).filter(value => value !== undefined).pop();
  return { ...present[present.length - 1], rows: [...byKey.values()], errors: present.flatMap(report => report.errors || []),
    offline: present.every(report => report.offline), chromium: last('chromium'), bundled: last('bundled'), intel: last('intel') };
}

/**
 * Writes the combined report of `results` (one run() result per step, the static scan first) into `outDir`: `outputs`
 * (any format but .md), the reports folder (client findings and components workbook), `shares` (redacted copies) and
 * `diagnostics` (one file, with each step's sanitized diagnostics). Returns the files written and the combined findings.
 */
export async function writeCombinedReport({ outDir, results, steps, outputs = [], shares = [], diagnostics, stepDiagnostics = [], root, isRelative = false,
  redact = [], reveal = false, shareCode = false, version, checkLinks = true }) {
  const combined = combineRuns(results);
  const last = results[results.length - 1];
  const dependencies = mergeDependencies(results.map(result => result.dependencies));
  if (dependencies && checkLinks) await checkComponentLinks(dependencies);
  // the facts of the last step (its scan covers the app's code, and its session's runtime and traffic summaries), with the
  // findings, accepted risks and components of every step
  const meta = { ...last.outputMeta, outputs, suppressed: combined.suppressed, dependencies, steps };
  const written = [];
  for (const output of outputs.filter(file => !/\.md$/i.test(file))) {
    writeIssues(root, isRelative, output, combined.reported, /\.sarif$/i.test(output) && outputs.length === 1, meta);
    written.push(output);
  }
  const reports = writeReports(outDir, combined.reported, { version, generatedAt: new Date().toISOString(), input: root, ...meta, root });
  for (const share of shares) {
    writeShare(share, { input: root, issues: combined.reported, suppressed: combined.suppressed, electronVersion: meta.electronVersion, bundled: dependencies && dependencies.bundled,
      runtime: meta.runtime, redact, code: shareCode, reveal, version });
    written.push(share);
  }
  if (diagnostics) {
    // each step's diagnostics were sanitized when they were written
    const perStep = {};
    for (const { name, file } of stepDiagnostics) {
      try {
        perStep[name] = JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch {
        perStep[name] = { error: 'diagnostics not written' };
      }
    }
    fs.writeFileSync(diagnostics, JSON.stringify({
      about: 'Electronegativity diagnostics of a guided run: one section per step (the static scan, then each watch session), each sanitized as a single run\'s diagnostics are. Review it before sharing.',
      steps: perStep,
    }, null, 2));
    written.push(diagnostics);
  }
  return { ...combined, dependencies, reports, written: [...written, path.join(outDir, path.basename(reports.dir))] };
}
