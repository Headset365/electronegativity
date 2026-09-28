// Your own notes on findings (--finding-notes notes.json), shown in the HTML and Word reports: an explanation,
// preconditions, reproduction steps, impact, reachability and how to confirm, per check id or family, and an impact text
// per Electron fuse. The tool ships no such text of its own. See docs/finding-notes.example.json.
import fs from 'node:fs';

export const NOTE_FIELDS = [['about', 'About'], ['preconditions', 'Preconditions'], ['steps', 'Steps to reproduce'], ['impact', 'Impact'],
  ['reachability', 'Reachability'], ['confirm', 'How to confirm'], ['recommendation', 'Recommendation']];

export function loadFindingNotes(file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!data || typeof data !== 'object' || (data.rules && typeof data.rules !== 'object')) throw new Error(`${file} is not a finding notes file`);
  return { rules: data.rules || {}, fuses: data.fuses || {} };
}

/** The notes for a check id: an exact entry, else the longest matching family (a key ending in * is a prefix). */
export function notesFor(notes, id) {
  if (!notes || !notes.rules) return undefined;
  if (notes.rules[id]) return notes.rules[id];
  const families = Object.keys(notes.rules).filter(key => key.endsWith('*') && String(id).startsWith(key.slice(0, -1).replace(/\.$/, '')))
    .sort((a, b) => b.length - a.length);
  return families.length ? notes.rules[families[0]] : undefined;
}

/** Notes attached to the findings (issue.notes), fuse impacts included. Mutates the issues. */
export function applyFindingNotes(issues, notes) {
  if (!notes) return issues;
  for (const issue of issues) {
    const found = notesFor(notes, issue.id);
    const fuse = issue.properties && issue.properties.fuse && notes.fuses[issue.properties.fuse];
    if (found || fuse) issue.notes = { ...(found || {}), ...(fuse ? { impact: fuse } : {}) };
  }
  return issues;
}
