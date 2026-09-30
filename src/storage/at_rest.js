// Data at rest: a read-only review of what the app keeps in its own profile folder (its userData directory): the
// Chromium cookie store (SQLite) and Local Storage, Session Storage and IndexedDB (LevelDB). It reports secrets left in
// cleartext and cookies stored without the OS encryption. Nothing is modified; values are redacted unless asked
// otherwise (--show-secrets, for a report that stays on the tester's machine).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
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
  const hit = findSecrets(value)[0];
  if (hit) return [hit.kind, show(hit.value, reveal), 'pattern'];
  // A long identifier under an analytics/session-id key is not necessarily a reusable credential.
  if (key && isSensitiveParam(key) && value.length >= 6 && !/^\d+$/.test(value)) return ['value under a secret-named key', show(value, reveal), 'name'];
  if (looksSecretValue(value) && value.length >= 24) return ['high-entropy value (identity unknown)', show(value, reveal), 'entropy'];
  return undefined;
}

/** Secrets in Local Storage, Session Storage and IndexedDB: [{ store, origin, key, kind, shown }] */
export function reviewWebStorage(profile, { reveal = false } = {}) {
  const out = [];
  const stores = [['Local Storage', path.join(profile, 'Local Storage', 'leveldb'), localStorageEntries], ['Session Storage', path.join(profile, 'Session Storage'), sessionStorageEntries]];
  for (const [label, dir, decode] of stores) {
    for (const [origin, key, value] of decode(readStore(dir))) {
      const hit = secretIn(value, key, reveal);
      if (hit) out.push({ store: label, origin, key, kind: hit[0], shown: hit[1], basis: hit[2] });
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

// Chromium's simple disk cache: every entry file (<hash>_0) starts with a 24-byte header (magic, version, key length,
// key hash) followed by the key, the URL, and then the response body and headers.
const SIMPLE_MAGIC = Buffer.from('305c72a71b6dfbfc', 'hex'); // 0xfcfb6d1ba7725c30, little-endian
const MAX_CACHE_FILES = 5000;
const MAX_CACHE_BYTES = 16 * 1024 * 1024;

// HTTP cache keys carry the isolation key before the URL: "1/0/_dk_https://a https://a https://a/path"
const urlOfKey = (key) => (key.match(/(https?:\/\/\S+)$/) || [])[1] || key;
// a gzip-encoded body is searched decoded as well
function withDecoded(body) {
  const gzip = body.indexOf(Buffer.from([0x1f, 0x8b, 0x08]));
  if (gzip === -1) return body;
  try {
    return Buffer.concat([body, zlib.gunzipSync(body.subarray(gzip), { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: MAX_CACHE_BYTES })]);
  } catch {
    return body; // not a whole gzip stream: search the raw bytes
  }
}

export function readCacheEntry(data) {
  if (!data || data.length < 24 || !data.subarray(0, 8).equals(SIMPLE_MAGIC)) return undefined;
  const keyLength = data.readUInt32LE(12);
  if (keyLength === 0 || 24 + keyLength > data.length) return undefined;
  const key = data.subarray(24, 24 + keyLength).toString('utf8');
  return { url: urlOfKey(key), body: withDecoded(data.subarray(24 + keyLength)) };
}

// Chromium's blockfile disk cache, the HTTP cache backend on Windows: index, data_0..data_3 (block files with an 8 KB
// header starting with 0xC104CAC3) and f_xxxxxx files for large streams. Entries are EntryStore records in data_1:
// the key (the URL) at offset 96, the sizes of the four streams at 40 and their addresses at 56. An address: bit 31 set
// when used; bits 28-30 the file type (0: an f_ file named by bits 0-27, 1-4: block files of 36, 256, 1024 and 4096
// bytes); for block files, bits 24-25 the block count minus one, 16-23 the data_N number and 0-15 the first block.
const BLOCK_MAGIC = 0xc104cac3;
const BLOCK_HEADER = 8192;

function blockfileEntries(dir) {
  const files = new Map();
  const blockFile = (n) => {
    if (!files.has(n)) {
      let data;
      try {
        const file = path.join(dir, `data_${n}`);
        data = fs.statSync(file).size <= 64 * MAX_CACHE_BYTES ? fs.readFileSync(file) : undefined;
      } catch {
        data = undefined;
      }
      files.set(n, data && data.length >= BLOCK_HEADER && data.readUInt32LE(0) === BLOCK_MAGIC ? data : undefined);
    }
    return files.get(n);
  };
  const read = (address, size) => {
    if (!(address & 0x80000000) || size <= 0) return undefined;
    const type = (address >>> 28) & 7;
    const length = Math.min(size, MAX_CACHE_BYTES);
    if (type === 0) {
      try {
        const fd = fs.openSync(path.join(dir, `f_${(address & 0x0fffffff).toString(16).padStart(6, '0')}`), 'r');
        try {
          const buffer = Buffer.alloc(length);
          return buffer.subarray(0, fs.readSync(fd, buffer, 0, length, 0));
        } finally {
          fs.closeSync(fd);
        }
      } catch {
        return undefined;
      }
    }
    const data = blockFile((address >>> 16) & 0xff);
    if (!data) return undefined;
    const blockSize = data.readUInt32LE(12);
    const start = BLOCK_HEADER + (address & 0xffff) * blockSize;
    return start < data.length ? data.subarray(start, Math.min(data.length, start + Math.min(length, (((address >>> 24) & 3) + 1) * blockSize))) : undefined;
  };
  const entries = blockFile(1);
  if (!entries || entries.readUInt32LE(12) !== 256) return [];
  const out = [];
  for (let at = BLOCK_HEADER; at + 256 <= entries.length && out.length < MAX_CACHE_FILES; at += 256) {
    const keyLength = entries.readInt32LE(at + 32);
    if (keyLength <= 0 || keyLength > 64 * 1024) continue;
    const longKey = entries.readUInt32LE(at + 36);
    const keyBytes = longKey ? read(longKey, keyLength) : entries.subarray(at + 96, Math.min(entries.length, at + 96 + keyLength));
    const key = keyBytes && keyBytes.toString('utf8').replace(/\0+$/, '');
    if (!key || !/^(\d+\/\d+\/|_dk_|https?:\/\/)/.test(key) || !/https?:\/\//.test(key)) continue;
    // stream 1 is the response body; stream 0 the response headers, which name its encoding
    const body = read(entries.readUInt32LE(at + 56 + 4), entries.readInt32LE(at + 40 + 4)) || Buffer.alloc(0);
    out.push({ key, url: urlOfKey(key), body: withDecoded(body) });
  }
  return out;
}

const hostOfUrl = (url) => {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
};
const withoutQuery = (url) => String(url).replace(/[?#].*$/, '');

function cacheFiles(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { recursive: true, withFileTypes: true });
  } catch {
    return [];
  }
  return entries.filter(e => e.isFile() && /^[0-9a-f]{16}_0$/.test(e.name)).map(e => path.join(e.parentPath, e.name)).slice(0, MAX_CACHE_FILES);
}

/**
 * Responses kept on disk: the Cache Storage of service workers and the HTTP cache. Documents and API responses stay
 * there after logout; secrets in their bodies (tokens in JSON responses) are reported like those in web storage.
 */
export function reviewCaches(profile, { reveal = false } = {}) {
  const stores = [
    { store: 'Cache Storage', dir: path.join(profile, 'Service Worker', 'CacheStorage') },
    { store: 'HTTP cache', dir: path.join(profile, 'Cache', 'Cache_Data') },
    { store: 'HTTP cache', dir: path.join(profile, 'Cache') },
  ];
  const out = { stores: {}, secrets: [] };
  const seen = new Set();
  const done = new Set();
  const blockfileDirs = new Set();
  for (const { store, dir } of stores) {
    const entries = [];
    for (const file of cacheFiles(dir)) {
      if (done.has(file)) continue;
      done.add(file);
      let data;
      try {
        if (fs.statSync(file).size > MAX_CACHE_BYTES) continue;
        data = fs.readFileSync(file);
      } catch {
        continue;
      }
      const entry = readCacheEntry(data);
      if (entry) entries.push(entry);
    }
    // the blockfile format (Windows): one set of data_N files per cache folder, each entry once by key
    if (!blockfileDirs.has(dir)) {
      blockfileDirs.add(dir);
      const keys = new Set();
      for (const entry of blockfileEntries(dir)) if (!keys.has(entry.key)) { keys.add(entry.key); entries.push(entry); }
    }
    for (const entry of entries) {
      const summary = out.stores[store] || (out.stores[store] = { entries: 0, hosts: {} });
      summary.entries++;
      const host = hostOfUrl(entry.url);
      if (host) summary.hosts[host] = (summary.hosts[host] || 0) + 1;
      for (const hit of findSecrets(entry.body.toString('utf8'), { maxHits: 20 })) {
        if (seen.has(hit.value)) continue;
        seen.add(hit.value);
        out.secrets.push({ store, url: withoutQuery(entry.url), kind: hit.kind, shown: show(hit.value, reveal) });
      }
    }
  }
  return out;
}

/** The reviews of one profile folder. */
export function reviewProfile(profile, { cookieEncryption, reveal = false } = {}) {
  return { profile, revealed: reveal, webStorage: reviewWebStorage(profile, { reveal }), cookies: reviewCookies(profile, { cookieEncryption, reveal }),
    caches: reviewCaches(profile, { reveal }) };
}
