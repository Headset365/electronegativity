// Data at rest: a read-only review of what the app keeps in its own profile folder (its userData directory): the
// Chromium cookie store (SQLite) and Local Storage, Session Storage and IndexedDB (LevelDB). It reports secrets left in
// cleartext and cookies stored without the OS encryption. Nothing is modified; values are redacted unless asked
// otherwise (--show-secrets, for a report that stays on the tester's machine).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { readStore } from './leveldb.js';

const require = createRequire(import.meta.url);
const { findSecrets, isSensitiveParam, looksSecretValue, redact } = require('../traffic/secrets.cjs');

/** The profile folders an app called one of `names` would use: Electron puts userData under the app's name. */
export function defaultProfileDirs(names, { platform = process.platform, env = process.env, home = os.homedir() } = {}) {
  const dirs = [];
  for (const name of [...new Set(names.filter(Boolean))]) {
    if (platform === 'win32') {
      if (env.APPDATA) dirs.push(path.join(env.APPDATA, name));
    } else if (platform === 'darwin') {
      dirs.push(path.join(home, 'Library', 'Application Support', name));
    } else {
      dirs.push(path.join(env.XDG_CONFIG_HOME || path.join(home, '.config'), name));
    }
  }
  return dirs.filter(dir => {
    try {
      return fs.statSync(dir).isDirectory();
    } catch {
      return false;
    }
  });
}

/** Chromium's DOM storage encoding of keys and values: a leading 0 is UTF-16LE, 1 is Latin-1. */
export function decodeDom(bytes) {
  if (!bytes || bytes.length === 0) return '';
  if (bytes[0] === 0) return bytes.subarray(1).toString('utf16le');
  if (bytes[0] === 1) return bytes.subarray(1).toString('latin1');
  return bytes.toString('utf8');
}

/** [origin, key, value] entries of a Local Storage store: keys are `_<origin>\0<encoded key>` */
export function localStorageEntries(store) {
  const out = [];
  for (const { key, value } of store.values()) {
    if (key[0] !== 0x5f) continue; // '_'
    const zero = key.indexOf(0, 1);
    if (zero < 0) continue;
    out.push([key.subarray(1, zero).toString('utf8'), decodeDom(key.subarray(zero + 1)), decodeDom(value)]);
  }
  return out;
}

/** ['', key, value] entries of a Session Storage store: keys are `map-<id>-<key>`, values UTF-16LE */
export function sessionStorageEntries(store) {
  const out = [];
  for (const { key, value } of store.values()) {
    const text = key.toString('latin1');
    const match = text.match(/^map-\d+-(.*)$/s);
    if (!match) continue;
    out.push(['', match[1], value.length % 2 === 0 && value.length > 0 && value[1] === 0 ? value.toString('utf16le') : decodeDom(value)]);
  }
  return out;
}

// printable strings in a binary value (IndexedDB values are serialized V8 objects)
function strings(data) {
  const parts = [];
  // UTF-16LE runs: a printable character followed by a zero byte
  const utf16 = /(?:[\x20-\x7e]\x00){8,}/g; // eslint-disable-line no-control-regex
  for (const m of data.toString('latin1').matchAll(utf16)) parts.push(Buffer.from(m[0], 'latin1').toString('utf16le'));
  for (const m of data.toString('latin1').matchAll(/[\x20-\x7e]{12,}/g)) parts.push(m[0]);
  return parts;
}

const show = (value, reveal) => reveal ? String(value) : redact(value);

// [kind, shown value] when a value is or holds a secret
function secretIn(value, key, reveal) {
  if (key && isSensitiveParam(key) && value.length >= 6 && !/^\d+$/.test(value)) return ['value under a secret-named key', show(value, reveal)];
  const hit = findSecrets(value)[0];
  if (hit) return [hit.kind, show(hit.value, reveal)];
  if (looksSecretValue(value) && value.length >= 24) return ['high-entropy value', show(value, reveal)];
  return undefined;
}

/** Secrets in Local Storage, Session Storage and IndexedDB: [{ store, origin, key, kind, shown }] */
export function reviewWebStorage(profile, { reveal = false } = {}) {
  const out = [];
  const stores = [['Local Storage', path.join(profile, 'Local Storage', 'leveldb'), localStorageEntries], ['Session Storage', path.join(profile, 'Session Storage'), sessionStorageEntries]];
  for (const [label, dir, decode] of stores) {
    for (const [origin, key, value] of decode(readStore(dir))) {
      const hit = secretIn(value, key, reveal);
      if (hit) out.push({ store: label, origin, key, kind: hit[0], shown: hit[1] });
    }
  }
  const idb = path.join(profile, 'IndexedDB');
  let databases = [];
  try {
    databases = fs.readdirSync(idb).filter(name => name.endsWith('.leveldb'));
  } catch {
    // no IndexedDB
  }
  for (const database of databases) {
    const seen = new Set();
    for (const { value } of readStore(path.join(idb, database)).values()) {
      for (const text of strings(value)) {
        for (const hit of findSecrets(text)) {
          if (seen.has(hit.value)) continue;
          seen.add(hit.value);
          out.push({ store: 'IndexedDB', origin: database.split('_')[0], key: undefined, kind: hit.kind, shown: show(hit.value, reveal) });
        }
      }
    }
  }
  return out;
}

// Node's SQLite, loaded quietly (it prints an experimental-feature warning on first use)
let sqlite;
function openSqlite() {
  if (sqlite !== undefined) return sqlite;
  const emit = process.emitWarning;
  process.emitWarning = (warning, ...rest) => {
    const type = typeof rest[0] === 'string' ? rest[0] : rest[0] && rest[0].type;
    if (type === 'ExperimentalWarning' && /SQLite/i.test(String(warning))) return;
    return emit.call(process, warning, ...rest);
  };
  try {
    sqlite = require('node:sqlite');
  } catch {
    sqlite = null;
  } finally {
    process.emitWarning = emit;
  }
  return sqlite;
}

/**
 * The cookie store: cookies kept unencrypted, cookies under Chromium's fixed-key fallback (v10 without an OS keyring,
 * or when the EnableCookieEncryption fuse is off), and session-like cookies without Secure/HttpOnly.
 * @param {string} profile the userData folder
 * @param {{ cookieEncryption?: boolean, reveal?: boolean }} options cookieEncryption: the fuse state, when known
 */
export function reviewCookies(profile, { cookieEncryption, reveal = false } = {}) {
  const db = [path.join(profile, 'Network', 'Cookies'), path.join(profile, 'Cookies')].find(file => fs.existsSync(file));
  if (!db) return { present: false };
  const engine = openSqlite();
  if (!engine) return { present: true, error: 'this Node.js has no SQLite support (node:sqlite, Node 22.13+)' };
  const out = { present: true, file: db, total: 0, plaintext: [], weakEncryption: 0, insecureFlags: [] };
  // a copy: the app may hold the database open, and a read must never change it
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-cookies-'));
  let rows;
  try {
    const copy = path.join(tmp, 'Cookies');
    fs.copyFileSync(db, copy);
    for (const suffix of ['-wal', '-journal']) if (fs.existsSync(db + suffix)) fs.copyFileSync(db + suffix, copy + suffix);
    const database = new engine.DatabaseSync(copy, { readOnly: true });
    try {
      rows = database.prepare('select host_key, name, value, encrypted_value, is_secure, is_httponly, is_persistent from cookies').all();
    } finally {
      database.close();
    }
  } catch (error) {
    return { present: true, file: db, error: error.message };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  for (const row of rows) {
    out.total++;
    const encrypted = row.encrypted_value ? Buffer.from(row.encrypted_value) : Buffer.alloc(0);
    const scheme = encrypted.subarray(0, 3).toString('latin1');
    if (row.value) out.plaintext.push({ host: row.host_key, name: row.name, value: show(row.value, reveal) });
    // v10 on Linux is the fixed key Chromium falls back to without a keyring; with the fuse off nothing is encrypted
    else if (scheme === 'v10' && (process.platform === 'linux' || cookieEncryption === false)) out.weakEncryption++;
    const name = String(row.name || '');
    if (isSensitiveParam(name) || /session|auth/i.test(name)) {
      const missing = [['Secure', row.is_secure], ['HttpOnly', row.is_httponly]].filter(([, on]) => !on).map(([flag]) => flag);
      if (missing.length > 0) out.insecureFlags.push({ host: row.host_key, name, missing, persistent: !!row.is_persistent });
    }
  }
  return out;
}

/** Both reviews of one profile folder. */
export function reviewProfile(profile, { cookieEncryption, reveal = false } = {}) {
  return { profile, revealed: reveal, webStorage: reviewWebStorage(profile, { reveal }), cookies: reviewCookies(profile, { cookieEncryption, reveal }) };
}
