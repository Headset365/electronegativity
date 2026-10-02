// Where did the app put a password it was asked to remember? The tester types a unique, throwaway password (a
// "canary") into the app's login with "remember me" ticked, and passes the same value with --canary. Every place the
// app can write is then searched for it: raw bytes, UTF-16, base64 at any offset, base64url, hex and URL encoding, the
// decoded contents of LevelDB stores (their tables are Snappy-compressed on disk), and on Windows the app's registry
// keys. When it isn't found, a before/after comparison shows where the app did write: files that changed, new Windows
// Credential Manager entries (by name only) and files carrying DPAPI or safeStorage ciphertext. Nothing is decrypted.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { readStore, isLevelDb } from './leveldb.js';

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 50000;
const MAX_HITS = 200;
const CONTEXT = 40;

// CRYPTPROTECT blob header (version 1 and the DPAPI provider GUID), raw and base64
const DPAPI_RAW = Buffer.from('01000000d08c9ddf0115d1118c7a00c04fc297eb', 'hex');
const DPAPI_B64 = Buffer.from('AQAAANCMnd8BFdERjHoAwE/Cl+s');
// Chromium os_crypt / Electron safeStorage ciphertext prefixes ("v10", "v11"), base64
const SAFESTORAGE_B64 = ['djEw', 'djEx'];

// base64 substrings that appear whatever the value's offset inside a larger encoded value
function base64Variants(data) {
  const out = [];
  for (const pad of [0, 1, 2]) {
    const encoded = Buffer.concat([Buffer.alloc(pad), data]).toString('base64');
    const start = { 0: 0, 1: 2, 2: 3 }[pad]; // characters that depend on the padding bytes
    const tail = (data.length + pad) % 3;
    const end = encoded.length - (tail ? 4 : 0); // the last group depends on what follows
    const chunk = encoded.slice(start, Math.max(start, end));
    if (chunk.length >= 8) out.push(chunk);
  }
  return out;
}

/** [label, Buffer] pairs to search for one canary. */
export function canaryForms(value) {
  const utf8 = Buffer.from(value, 'utf8');
  const utf16 = Buffer.from(value, 'utf16le');
  const out = [['plaintext (UTF-8)', utf8], ['plaintext (UTF-16)', utf16]];
  for (const [label, data] of [['UTF-8', utf8], ['UTF-16', utf16]]) {
    for (const chunk of base64Variants(data)) {
      out.push([`base64 of ${label}`, Buffer.from(chunk)]);
      const url = chunk.replace(/\+/g, '-').replace(/\//g, '_');
      if (url !== chunk) out.push([`base64url of ${label}`, Buffer.from(url)]);
    }
  }
  out.push(['hex', Buffer.from(utf8.toString('hex'))], ['hex', Buffer.from(utf8.toString('hex').toUpperCase())]);
  out.push(['hex of UTF-16', Buffer.from(utf16.toString('hex'))], ['hex of UTF-16', Buffer.from(utf16.toString('hex').toUpperCase())]);
  const encoded = encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  if (encoded !== value) out.push(['URL-encoded', Buffer.from(encoded)]);
  const seen = new Set();
  return out.filter(([, bytes]) => !seen.has(bytes.toString('latin1')) && seen.add(bytes.toString('latin1')));
}

const isDir = (dir) => {
  try {
    return fs.statSync(dir).isDirectory();
  } catch {
    return false;
  }
};
// Windows (and macOS) folder names are case-insensitive: .MyApp and .myapp are one folder, searched once
const foldCase = process.platform === 'win32' || process.platform === 'darwin';
const inside = (child, parent) => {
  const [c, p] = foldCase ? [child.toLowerCase(), parent.toLowerCase()] : [child, parent];
  return c === p || c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
};

/**
 * The folders the app can write to: its profile and local app data (by app, package and publisher name), its updater
 * folder, dot-folders in the home folder, its install folder, and `extra` folders. Nested folders are merged.
 */
export function searchRoots(names, { extra = [], installDir, platform = process.platform, env = process.env, home = os.homedir() } = {}) {
  const unique = [...new Set(names.map(n => String(n || '').trim()).filter(Boolean))];
  const candidates = [];
  if (platform === 'win32') {
    for (const base of [env.APPDATA, env.LOCALAPPDATA, env.PROGRAMDATA].filter(Boolean))
      for (const name of unique) candidates.push(path.join(base, name), path.join(base, `${name}-updater`));
  } else {
    for (const name of unique)
      candidates.push(path.join(env.XDG_CONFIG_HOME || path.join(home, '.config'), name), path.join(home, 'Library', 'Application Support', name),
        path.join(home, '.local', 'share', name), path.join(home, 'Library', 'Caches', `${name}-updater`));
  }
  for (const name of unique) candidates.push(path.join(home, `.${name}`), path.join(home, `.${name.toLowerCase()}`));
  if (installDir) candidates.push(installDir);
  candidates.push(...extra);
  let roots = [];
  for (const candidate of candidates) {
    let real;
    try {
      real = fs.realpathSync(candidate);
    } catch {
      continue;
    }
    if (!isDir(real) || roots.some(root => inside(real, root))) continue;
    roots = roots.filter(root => !inside(root, real)).concat(real);
  }
  return roots;
}

function* walk(roots) {
  let count = 0;
  for (const root of roots) {
    let entries;
    try {
      entries = fs.readdirSync(root, { recursive: true, withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (++count > MAX_FILES) return;
      yield path.join(entry.parentPath, entry.name);
    }
  }
}

/** { path: [size, mtime] } of every file under the roots, to compare before and after a session. */
export function snapshot(roots) {
  const out = {};
  for (const file of walk(roots)) {
    try {
      const stat = fs.statSync(file);
      out[file] = [stat.size, stat.mtimeMs];
    } catch {
      // gone
    }
  }
  return out;
}

/** Files created or modified between two snapshots. */
export function changedFiles(before, after) {
  const rows = [];
  for (const [file, meta] of Object.entries(after)) {
    const old = before[file];
    if (!old) rows.push({ path: file, change: 'created', size: meta[0] });
    else if (old[0] !== meta[0] || old[1] !== meta[1]) rows.push({ path: file, change: 'modified', size: meta[0] });
  }
  return rows.sort((a, b) => a.path.localeCompare(b.path));
}

/** Windows Credential Manager target names for this user (names only: no secret is read). */
export function credentialTargets({ platform = process.platform, run = spawnSync } = {}) {
  if (platform !== 'win32') return [];
  const result = run('cmdkey', ['/list'], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (!result || result.status !== 0 || !result.stdout) return [];
  return [...new Set([...result.stdout.matchAll(/^\s*Target:\s*(.+)$/gim)].map(m => m[1].trim()))].sort();
}

/** [key, `reg query /s` text] for the HKCU\Software\<name> keys that exist. */
export function registryText(names, { platform = process.platform, run = spawnSync } = {}) {
  if (platform !== 'win32') return [];
  const out = [];
  for (const name of [...new Set(names.filter(Boolean))]) {
    const key = `HKCU\\Software\\${name}`;
    const result = run('reg', ['query', key, '/s'], { encoding: 'utf8', timeout: 30000, windowsHide: true });
    if (result && result.status === 0 && result.stdout && result.stdout.trim()) out.push([key, result.stdout]);
  }
  return out;
}

// the bytes around a match, printable, with UTF-16 zeros dropped
function context(data, at, length) {
  let chunk = data.subarray(Math.max(0, at - CONTEXT), at + length + CONTEXT);
  const zeros = chunk.filter(b => b === 0).length;
  if (zeros > chunk.length / 3) chunk = Buffer.from(chunk.filter(b => b !== 0));
  return chunk.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
}

function* find(data, patterns) {
  for (const { canary, label, bytes } of patterns) {
    const at = data.indexOf(bytes);
    if (at >= 0) yield { canary, label, at, length: bytes.length };
  }
}

function markers(data) {
  const found = [];
  if (data.includes(DPAPI_RAW) || data.includes(DPAPI_B64)) found.push('DPAPI blob');
  if (SAFESTORAGE_B64.some(prefix => ['"', '\'', '='].some(q => data.includes(Buffer.from(q + prefix))))) found.push('possible safeStorage / os_crypt value (v10/v11)');
  return found;
}

/**
 * Searches the roots (and the registry keys named after the app, on Windows) for the canaries.
 * @returns {{ files, leveldbStores, hits: [{ canary, location, encoding, context, match, store? }], markers: [{ path, markers }] }}
 * @param {{ registryNames?: string[], changedPaths?: Set<string>, platform?: string, run?: Function }} options changedPaths:
 *   only these files are checked for DPAPI/safeStorage markers (the files the session wrote)
 */
export function scanForCanaries(roots, canaries, { registryNames = [], changedPaths, platform, run } = {}) {
  const patterns = canaries.flatMap(canary => canaryForms(canary).map(([label, bytes]) => ({ canary, label, bytes })));
  const hits = [];
  const found = [];
  let files = 0;
  let skippedLargeFiles = 0, unreadableFiles = 0;
  const levelDbs = new Set();
  const addHit = (canary, location, label, data, at, length, store) => {
    if (hits.length >= MAX_HITS || hits.some(h => h.location === location && h.encoding === label)) return;
    hits.push({ canary, location, encoding: label, context: context(data, at, length), match: context(data.subarray(at, at + length), 0, length), ...(store ? { store } : {}) });
  };
  const levelDbCache = new Map();
  for (const file of walk(roots)) {
    files++;
    const dir = path.dirname(file);
    if (!levelDbCache.has(dir)) levelDbCache.set(dir, isLevelDb(dir));
    if (levelDbCache.get(dir)) levelDbs.add(dir);
    let data;
    try {
      if (fs.statSync(file).size > MAX_FILE_BYTES) { skippedLargeFiles++; continue; }
      data = fs.readFileSync(file);
    } catch {
      unreadableFiles++;
      continue;
    }
    for (const match of find(data, patterns)) addHit(match.canary, file, match.label, data, match.at, match.length);
    if (!changedPaths || changedPaths.has(file)) {
      let marks = markers(data);
      if (marks.length > 0 && path.basename(file) === 'Local State') marks = ['Chromium\'s own DPAPI-wrapped storage key (os_crypt), not the credential itself'];
      if (marks.length > 0) found.push({ path: file, markers: marks });
    }
  }
  // LevelDB tables are Snappy-compressed on disk: search the decoded keys and values too
  for (const dir of [...levelDbs].sort()) {
    for (const { key, value } of readStore(dir).values()) {
      for (const [data, part] of [[key, 'key'], [value, 'value']]) {
        for (const match of find(data, patterns)) {
          if (hits.some(h => h.location.startsWith(dir + path.sep) && h.encoding === match.label)) continue; // already in the store's log file
          addHit(match.canary, `${dir} [${part} ${context(key, 0, 0).slice(0, 60)}]`, match.label, data, match.at, match.length, 'LevelDB');
        }
      }
    }
  }
  for (const [key, text] of registryText(registryNames, { platform, run })) {
    const data = Buffer.from(text, 'utf8');
    for (const match of find(data, patterns.filter(p => p.label !== 'plaintext (UTF-16)'))) addHit(match.canary, key, `${match.label} (registry)`, data, match.at, match.length, 'registry');
  }
  return { files, leveldbStores: levelDbs.size, hits, markers: found, coverage: { skippedLargeFiles, unreadableFiles, fileLimitReached: files >= MAX_FILES, maxFileBytes: MAX_FILE_BYTES, maxFiles: MAX_FILES } };
}
