// Where downloaded data (Electron releases, CISA KEV, EPSS, NVD) is cached: a folder of the user's own, never the shared
// temporary folder, where another local user could plant data the report would trust or a link the write would follow.
// ELECTRONEGATIVITY_CACHE_DIR moves it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function cacheDir() {
  if (process.env.ELECTRONEGATIVITY_CACHE_DIR) return process.env.ELECTRONEGATIVITY_CACHE_DIR;
  const home = os.homedir();
  if (process.platform === 'win32') return path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'electronegativity', 'cache');
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Caches', 'electronegativity');
  return path.join(process.env.XDG_CACHE_HOME || path.join(home, '.cache'), 'electronegativity');
}

/** Writes a cache file: to a new file first, then renamed over the old one, so an existing link is replaced, not followed. */
export function writeCacheFile(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temporary, text, { flag: 'wx', mode: 0o600 });
  try {
    fs.renameSync(temporary, file);
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}
