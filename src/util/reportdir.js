// --report-dir: one folder per run, named electronegativity-<UTC date and time>, holding every report of that run.
import fs from 'node:fs';
import path from 'node:path';

/** electronegativity-2026-09-28T14-30-05Z: sortable, and free of characters Windows refuses in a folder name. */
export function reportFolderName(date = new Date()) {
  return `electronegativity-${date.toISOString().replace(/\.\d+Z$/, 'Z').replace(/:/g, '-')}`;
}

/**
 * Creates the report folder inside `parent` (default: the current folder; created when missing) and returns its path.
 * Two runs in the same second get -2, -3... so a run never writes into another run's folder.
 */
export function createReportFolder(parent = '.', date = new Date()) {
  const base = path.resolve(parent);
  fs.mkdirSync(base, { recursive: true });
  const name = reportFolderName(date);
  for (let n = 1; ; n++) {
    const dir = path.join(base, n === 1 ? name : `${name}-${n}`);
    try {
      fs.mkdirSync(dir);
      return dir;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }
}

/** The files of a single scan's report folder. */
export function reportFiles(dir) {
  return {
    outputs: [path.join(dir, 'report.html'), path.join(dir, 'report.json')],
    shares: [path.join(dir, 'shareable-report.md'), path.join(dir, 'shareable-report.json')],
    diagnostics: path.join(dir, 'diagnostics.json'),
  };
}
