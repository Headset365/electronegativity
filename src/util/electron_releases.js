import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { major, valid, compare } from 'semver';

const RELEASES_URL = 'https://releases.electronjs.org/releases.json';
const CACHE_FILE = path.join(os.tmpdir(), 'electronegativity-electron-releases.json');
const CACHE_TTL = 12 * 60 * 60 * 1000;
// Electron supports the latest three stable major versions (https://www.electronjs.org/docs/latest/tutorial/electron-timelines)
export const SUPPORTED_MAJORS = 3;

let pending;

async function download() {
  const response = await fetch(RELEASES_URL, { signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const releases = (await response.json()).map(r => r.version).filter(v => valid(v) && !v.includes('-'));
  try { fs.writeFileSync(CACHE_FILE, JSON.stringify(releases)); } catch { /* the cache is optional */ }
  return releases;
}

/**
 * Stable Electron versions, newest first. Uses a cached copy for up to 12 hours, and a stale one when offline.
 */
export function getStableReleases() {
  pending ??= (async () => {
    let cached;
    try {
      const stat = fs.statSync(CACHE_FILE);
      cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
      if (Date.now() - stat.mtimeMs < CACHE_TTL) return sortDesc(cached);
    } catch { /* no cache yet */ }
    try {
      return sortDesc(await download());
    } catch (e) {
      if (cached) return sortDesc(cached);
      pending = undefined;
      throw e;
    }
  })();
  return pending;
}

function sortDesc(versions) {
  return [...versions].sort((a, b) => compare(b, a));
}

export function supportedMajors(releases) {
  const majors = [...new Set(releases.map(v => major(v)))].sort((a, b) => b - a);
  return majors.slice(0, SUPPORTED_MAJORS);
}
