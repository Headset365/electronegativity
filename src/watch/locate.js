// Finds an Electron app from wherever the user points: an install folder, the executable, its resources\app.asar, a
// Squirrel install root (…\AppData\Local\<App> with app-<version> folders), a folder holding the install folder, a
// macOS .app bundle, or a project folder with Electron installed.
import fs from 'node:fs';
import path from 'node:path';
import { packagedBinaryFor } from './fuses.js';

const HELPERS = /^(chrome-sandbox|chrome_crashpad_handler|crashpad_handler|uninstall.*|squirrel\.exe|update\.exe|elevate\.exe|notification_helper\.exe)$/i;

const isDir = (p) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};
const isFile = (p) => {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
};

// resources\app.asar, or an unpacked resources\app folder
function appCode(folder) {
  const asar = path.join(folder, 'resources', 'app.asar');
  if (isFile(asar)) return asar;
  const unpacked = path.join(folder, 'resources', 'app');
  return isDir(unpacked) ? unpacked : undefined;
}

// the app's executable in an install folder: the one holding Electron's fuse wire, else the .exe (or executable file)
// named most like the folder, leaving helpers and uninstallers out
function executableIn(folder, code) {
  const withFuses = packagedBinaryFor(code);
  if (withFuses) return withFuses;
  let entries;
  try {
    entries = fs.readdirSync(folder, { withFileTypes: true }).filter(e => e.isFile() && !HELPERS.test(e.name));
  } catch {
    return undefined;
  }
  const candidates = entries.map(e => e.name).filter(name => process.platform === 'win32' ? /\.exe$/i.test(name) : /\.exe$/i.test(name) || !path.extname(name));
  const base = path.basename(folder).toLowerCase().replace(/[^a-z0-9]/g, '');
  candidates.sort((a, b) => Number(b.toLowerCase().replace(/[^a-z0-9]/g, '').startsWith(base)) - Number(a.toLowerCase().replace(/[^a-z0-9]/g, '').startsWith(base)));
  return candidates.length ? path.join(folder, candidates[0]) : undefined;
}

// Squirrel keeps each version in app-<version>: the newest one
function newestSquirrelVersion(folder) {
  let versions;
  try {
    versions = fs.readdirSync(folder).filter(name => /^app-\d+(\.\d+)*/.test(name) && isDir(path.join(folder, name)));
  } catch {
    return undefined;
  }
  const parts = (name) => name.slice(4).split(/[.-]/).map(n => Number.parseInt(n, 10) || 0);
  versions.sort((a, b) => {
    const x = parts(a); const y = parts(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (y[i] || 0) - (x[i] || 0);
    return 0;
  });
  return versions.length ? path.join(folder, versions[0]) : undefined;
}

/**
 * @returns {{ kind: 'packaged'|'project'|'bundle', executable?: string, code: string, folder: string, name: string }}
 * @throws when no Electron app is found there, saying what was looked for
 */
export function locateApp(target) {
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) throw new Error(`${target} does not exist`);

  // …\resources\app.asar or …\resources\app
  if (/\.asar$/i.test(resolved) || (/[\\/]resources[\\/]app$/i.test(resolved) && isDir(resolved))) {
    const folder = path.dirname(path.dirname(resolved));
    return { kind: 'packaged', executable: executableIn(folder, resolved), code: resolved, folder, name: path.basename(folder) };
  }
  // an executable: the app code is in resources next to it
  if (isFile(resolved)) {
    const folder = path.dirname(resolved);
    const code = appCode(folder);
    if (!code) throw new Error(`${target}: no resources${path.sep}app.asar next to it. Point at the app's install folder or its real executable (for Squirrel installs, the one in the app-<version> folder)`);
    return { kind: 'packaged', executable: resolved, code, folder, name: path.basename(resolved).replace(/\.exe$/i, '') };
  }
  // macOS bundle
  if (/\.app$/i.test(resolved)) {
    const code = path.join(resolved, 'Contents', 'Resources', 'app.asar');
    return { kind: 'bundle', executable: resolved, code: fs.existsSync(code) ? code : resolved, folder: resolved, name: path.basename(resolved, '.app') };
  }
  // a project folder with Electron installed
  if (isFile(path.join(resolved, 'package.json')) && !appCode(resolved)) return { kind: 'project', executable: resolved, code: resolved, folder: resolved, name: path.basename(resolved) };
  // the resources folder itself
  if (/[\\/]resources$/i.test(resolved) && appCode(path.dirname(resolved))) return locateApp(path.dirname(resolved));
  // an install folder
  const code = appCode(resolved);
  if (code) return { kind: 'packaged', executable: executableIn(resolved, code), code, folder: resolved, name: path.basename(resolved) };
  // a Squirrel install root: …\AppData\Local\<App>\app-<version>
  const squirrel = newestSquirrelVersion(resolved);
  if (squirrel && appCode(squirrel)) {
    const found = locateApp(squirrel);
    return { ...found, name: path.basename(resolved) };
  }
  // a folder holding the install folder: C:\Program Files\<Company> containing <App>
  let children = [];
  try {
    children = fs.readdirSync(resolved, { withFileTypes: true }).filter(e => e.isDirectory()).map(e => path.join(resolved, e.name));
  } catch {
    // unreadable
  }
  const apps = children.filter(child => appCode(child) || (newestSquirrelVersion(child) && appCode(newestSquirrelVersion(child))));
  if (apps.length === 1) return locateApp(apps[0]);
  if (apps.length > 1) throw new Error(`${target} holds several Electron apps: ${apps.map(a => path.basename(a)).join(', ')}. Point at one of them`);
  throw new Error(`No Electron app found in ${target}: expected resources${path.sep}app.asar (or resources${path.sep}app) next to the app's executable, an app-<version> folder (Squirrel), or a project folder with a package.json`);
}
