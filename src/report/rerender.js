// --rerender: the client findings of an earlier scan written again with the current templates, from the scan's report.json
// (all the data comes from it), into a newReports subfolder of the earlier findings folder. The earlier findings are only
// read, to flag what the tester changed by hand: report.json records what the tool wrote in each finding, section by
// section, so an edited section is told apart from a template change. A review file lists those edits, with the
// tester's text, to carry over.
import fs from 'node:fs';
import path from 'node:path';
import { severity, confidence } from '../finder/attributes.js';
import { parseFinding, sectionDigest, findingFingerprints } from './markdown.js';
import { writeReports } from '../util/index.js';
import { TITLES } from './markdown_style.js';
import { findingFileName } from './markdown.js';

export const NEW_REPORTS = 'newReports';
export const NEW_TESTER_NOTES = 'newTesterNotes';

// findings an earlier version wrote under another name
const RENAMED = {
  'Outdated Electron Runtime.md': 'Outdated Software Components.md',
  'Outdated Third-Party Components.md': 'Outdated Software Components.md',
  ...Object.fromEntries(Object.entries(TITLES).filter(([from, to]) => from !== to).map(([from, to]) => [findingFileName(from), findingFileName(to)])),
};

/** A finding of report.json as the report writers take it. */
export function issueFromReport(entry) {
  // accepted risks: in full with their reason, or (earlier reports) with the reason flattened into the entry
  const suppression = entry.suppression || (entry.reason !== undefined || entry.owner !== undefined || entry.expires !== undefined
    ? { reason: entry.reason, owner: entry.owner, expires: entry.expires, source: entry.source } : undefined);
  return {
    id: entry.id,
    severity: severity[entry.severity] || severity.INFORMATIONAL,
    confidence: confidence[entry.confidence] || confidence.TENTATIVE,
    manualReview: !!entry.manualReview,
    file: entry.file,
    location: { line: entry.line ?? 0, column: entry.column ?? 0 },
    sample: entry.sample ?? '',
    description: entry.description ?? '',
    shortenedURL: entry.reference,
    ...(entry.session !== undefined ? { session: entry.session } : {}),
    ...(entry.validation ? { validation: entry.validation } : {}),
    ...(entry.notes ? { notes: entry.notes } : {}),
    ...(entry.properties ? { properties: entry.properties } : {}),
    ...(entry.comparison ? { comparison: entry.comparison } : {}),
    ...(suppression ? { suppression } : {}),
  };
}

// the finding files of a folder (not the tester's own notes): by file name, with their parts
function readFindings(dir) {
  const found = new Map();
  if (!dir || !fs.existsSync(dir)) return found;
  for (const name of fs.readdirSync(dir).filter(name => /\.md$/i.test(name))) {
    const content = fs.readFileSync(path.join(dir, name), 'utf8');
    const parsed = parseFinding(content);
    if (parsed.front && parsed.front.Title) found.set(name, parsed);
  }
  return found;
}

const quote = (text) => String(text).trim().split('\n').map(line => `> ${line}`.trimEnd()).join('\n');

/**
 * What changed in one earlier finding: with the fingerprints of what the tool wrote, the sections the tester edited,
 * added or removed and a changed rating or notes; without them (a report written before fingerprints were recorded),
 * every part that differs from the new finding, which may be a template change or an edit.
 */
export function compareFinding(old, recorded, fresh) {
  const changes = [];
  if (recorded) {
    if (sectionDigest(`${old.front.Consequence ?? ''}|${old.front.Likelihood ?? ''}`) !== recorded.rating)
      changes.push({ part: 'Rating', kind: 'edited', text: `Consequence: ${old.front.Consequence ?? '(none)'}, Likelihood: ${old.front.Likelihood ?? '(none)'}` });
    if (sectionDigest(JSON.stringify(old.front.Notes ?? [])) !== recorded.notes)
      changes.push({ part: 'Notes', kind: 'edited', text: [].concat(old.front.Notes ?? []).map(note => `- ${note}`).join('\n') || '(none)' });
    for (const [heading, digest] of Object.entries(recorded.sections || {})) {
      if (!(heading in old.sections)) changes.push({ part: heading, kind: 'removed' });
      else if (sectionDigest(old.sections[heading]) !== digest) changes.push({ part: heading, kind: 'edited', text: old.sections[heading] });
    }
    for (const heading of Object.keys(old.sections)) if (!(heading in (recorded.sections || {}))) changes.push({ part: heading, kind: 'added', text: old.sections[heading] });
    return { known: true, changes };
  }
  if (!fresh) return { known: false, changes };
  if (`${old.front.Consequence}|${old.front.Likelihood}` !== `${fresh.front.Consequence}|${fresh.front.Likelihood}`)
    changes.push({ part: 'Rating', kind: 'differs', text: `Consequence: ${old.front.Consequence ?? '(none)'}, Likelihood: ${old.front.Likelihood ?? '(none)'}` });
  for (const heading of new Set([...Object.keys(old.sections), ...Object.keys(fresh.sections)])) {
    if (!(heading in fresh.sections)) changes.push({ part: heading, kind: 'not in the new template', text: old.sections[heading] });
    else if (!(heading in old.sections)) continue;
    else if (sectionDigest(old.sections[heading]) !== sectionDigest(fresh.sections[heading])) changes.push({ part: heading, kind: 'differs', text: old.sections[heading] });
  }
  return { known: false, changes };
}

function reviewDocument({ data, dataFile, oldDir, outDir, compared, gone, added, version }) {
  const lines = ['# Review of the re-rendered findings', '',
    `The findings in \`${outDir}\` were written again from \`${dataFile}\` (the scan of ${data.app?.name || 'the application'}${data.generatedAt ? ` on ${data.generatedAt.slice(0, 10)}` : ''}, Electronegativity ${data.version || 'unknown'}) with the templates of Electronegativity ${version}. All their content comes from that scan's data.`,
    '', `The earlier findings in \`${oldDir}\` were compared with what the tool wrote, to find manual changes. Carry over the ones you want to keep: the earlier text is quoted below.`, ''];
  const edited = compared.filter(c => c.known && c.changes.length);
  const unknown = compared.filter(c => !c.known && c.changes.length);
  lines.push('## Manual changes to carry over', '');
  if (!edited.length) lines.push(compared.some(c => c.known) ? 'None: no finding was edited after the tool wrote it.' : 'None could be identified (see below).', '');
  for (const c of edited) {
    lines.push(`### ${c.title} (\`${c.file}\`${c.newFile && c.newFile !== c.file ? `, now \`${c.newFile}\`` : ''})`, '');
    for (const change of c.changes) {
      if (change.kind === 'removed') lines.push(`- **${change.part}**: the section was removed by hand.`, '');
      else lines.push(`- **${change.part}**: ${change.kind === 'added' ? 'a section added by hand' : 'edited by hand'}. The earlier text:`, '', quote(change.text), '');
    }
  }
  if (unknown.length) {
    lines.push('## Differences that may be manual changes', '',
      'These earlier findings were written before the tool recorded what it wrote, so a template change and a manual edit look the same. Each part below differs from the new finding: check whether it held an edit to carry over.', '');
    for (const c of unknown) {
      lines.push(`### ${c.title} (\`${c.file}\`${c.newFile && c.newFile !== c.file ? `, now \`${c.newFile}\`` : ''})`, '');
      for (const change of c.changes) lines.push(`- **${change.part}** (${change.kind}). The earlier text:`, '', quote(change.text), '');
    }
  }
  if (gone.length) {
    lines.push('## Earlier findings not written any more', '');
    for (const g of gone) lines.push(`- \`${g.file}\` (${g.title})${g.newFile ? `: now part of \`${g.newFile}\`` : ': the scan data no longer produces this finding'}`);
    lines.push('');
  }
  if (added.length) {
    lines.push('## New findings', '', 'Written from the same scan data by the current templates, with no earlier counterpart:', '');
    for (const file of added) lines.push(`- \`${file}\``);
    lines.push('');
  }
  const untouched = compared.filter(c => c.known && !c.changes.length).map(c => `\`${c.file}\``);
  if (untouched.length) lines.push('## Unchanged since the tool wrote them', '', untouched.join(', '), '');
  const same = compared.filter(c => !c.known && !c.changes.length).map(c => `\`${c.file}\``);
  if (same.length) lines.push('## Identical to the new findings', '', same.join(', '), '');
  return lines.join('\n');
}

/**
 * Writes the findings of `dataFile` (a report.json) again with the current templates into <oldDir>/newReports, with the
 * components workbook and a report.json of their own (the same data, with fingerprints of the new findings), and a review
 * of the manual changes found in `oldDir` next to it (<oldDir>/newReports-review.md). `oldDir` defaults to the reports
 * folder next to report.json (or, for an earlier layout, its markdown folder, or report.json's own folder).
 */
export function rerender({ dataFile, oldDir, version }) {
  const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  if (data.tool !== 'Electronegativity' || !Array.isArray(data.issues)) throw new Error(`${dataFile} is not an Electronegativity JSON report`);
  const base = path.dirname(path.resolve(dataFile));
  const folder = path.resolve(oldDir || ['reports', 'markdown'].map(name => path.join(base, name)).find(dir => fs.existsSync(dir)) || base);
  if (!fs.existsSync(folder)) throw new Error(`The earlier findings folder ${folder} does not exist`);
  const issues = data.issues.map(issueFromReport);
  const suppressed = (data.suppressed || []).map(issueFromReport);
  const meta = { ...data, version, generatedAt: new Date().toISOString(), suppressed, root: data.input, app: data.app, dependencies: data.dependencies };
  const old = readFindings(folder);
  const reports = writeReports(folder, issues, meta, NEW_REPORTS, NEW_TESTER_NOTES);
  const fresh = readFindings(reports.dir);
  // the same data with what the tool wrote this time, so the new findings can be re-rendered again later
  const { markdown: earlier, ...rest } = data;
  fs.writeFileSync(path.join(reports.dir, 'report.json'), JSON.stringify({ ...rest, markdown: reports.markdown,
    rerendered: { from: path.resolve(dataFile), at: meta.generatedAt, version, earlierMarkdown: earlier ? earlier.version : undefined } }, null, 2));

  const recorded = (earlier && earlier.findings) || {};
  const compared = [];
  const gone = [];
  for (const [file, parsed] of old) {
    const title = parsed.front.Title;
    // the same finding, under its name or a later one
    const target = fresh.has(file) ? file : RENAMED[file] && fresh.has(RENAMED[file]) ? RENAMED[file] : undefined;
    const merged = target && target !== file && Object.values(RENAMED).filter(to => to === target).length > 1;
    if (target && !merged) {
      compared.push({ file, newFile: target, title, ...compareFinding(parsed, recorded[file], fresh.get(target)) });
      continue;
    }
    // not written any more, or merged into another finding (whose text can't be compared with it): its edits are still
    // listed when the tool recorded what it wrote
    gone.push({ file, title, newFile: target });
    if (recorded[file]) compared.push({ file, newFile: target, title, ...compareFinding(parsed, recorded[file]) });
  }
  const added = [...fresh.keys()].filter(file => !old.has(file) && !Object.entries(RENAMED).some(([from, to]) => to === file && old.has(from)));
  const review = path.join(folder, `${NEW_REPORTS}-review.md`);
  fs.writeFileSync(review, reviewDocument({ data, dataFile: path.resolve(dataFile), oldDir: folder, outDir: reports.dir, compared, gone, added, version }));
  return { dir: reports.dir, notesDir: path.join(folder, NEW_TESTER_NOTES), review, findings: reports.findings, compared, gone, added };
}

export { findingFingerprints };
