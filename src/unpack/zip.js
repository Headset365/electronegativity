// A small read-only zip reader (stored and deflated entries, zip64 sizes) for Squirrel packages (.nupkg) and zipped
// app builds. Entries are extracted inside the destination only.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { safeJoin } from './sevenzip.js';
import { MAX_STREAM, MAX_TOTAL, limitMessage } from './limits.js';

export class ZipError extends Error {}

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

/** The entries of a zip archive: [{ name, method, compressedSize, size, localOffset, isDir }] */
export function zipEntries(data) {
  let eocd = -1;
  for (let i = data.length - 22; i >= Math.max(0, data.length - 22 - 65535); i--) {
    if (data.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipError('not a zip archive (no end of central directory)');
  let count = data.readUInt16LE(eocd + 10);
  let offset = data.readUInt32LE(eocd + 16);
  // zip64: the end-of-central-directory locator just before
  if ((offset === 0xffffffff || count === 0xffff) && eocd >= 20 && data.readUInt32LE(eocd - 20) === 0x07064b50) {
    const record = Number(data.readBigUInt64LE(eocd - 20 + 8));
    count = Number(data.readBigUInt64LE(record + 32));
    offset = Number(data.readBigUInt64LE(record + 48));
  }
  const entries = [];
  let at = offset;
  for (let i = 0; i < count; i++) {
    if (at + 46 > data.length || data.readUInt32LE(at) !== CENTRAL) throw new ZipError('bad central directory');
    const method = data.readUInt16LE(at + 10);
    let compressedSize = data.readUInt32LE(at + 20);
    let size = data.readUInt32LE(at + 24);
    const nameLength = data.readUInt16LE(at + 28);
    const extraLength = data.readUInt16LE(at + 30);
    const commentLength = data.readUInt16LE(at + 32);
    let localOffset = data.readUInt32LE(at + 42);
    const flags = data.readUInt16LE(at + 8);
    const name = data.subarray(at + 46, at + 46 + nameLength).toString(flags & 0x800 ? 'utf8' : 'latin1');
    // zip64 extra field: the 32-bit values set to 0xffffffff, in order
    const extra = data.subarray(at + 46 + nameLength, at + 46 + nameLength + extraLength);
    for (let e = 0; e + 4 <= extra.length;) {
      const id = extra.readUInt16LE(e);
      const length = extra.readUInt16LE(e + 2);
      if (id === 1) {
        let p = e + 4;
        if (size === 0xffffffff) { size = Number(extra.readBigUInt64LE(p)); p += 8; }
        if (compressedSize === 0xffffffff) { compressedSize = Number(extra.readBigUInt64LE(p)); p += 8; }
        if (localOffset === 0xffffffff) localOffset = Number(extra.readBigUInt64LE(p));
      }
      e += 4 + length;
    }
    entries.push({ name, method, compressedSize, size, localOffset, isDir: name.endsWith('/'), encrypted: !!(flags & 1) });
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** The contents of one entry. */
export function zipRead(data, entry) {
  if (entry.encrypted) throw new ZipError(`${entry.name} is encrypted`);
  if (entry.size > MAX_STREAM) throw new ZipError(limitMessage(entry.name, entry.size));
  const at = entry.localOffset;
  if (data.readUInt32LE(at) !== LOCAL) throw new ZipError(`bad local header for ${entry.name}`);
  const start = at + 30 + data.readUInt16LE(at + 26) + data.readUInt16LE(at + 28);
  const raw = data.subarray(start, start + entry.compressedSize);
  let out;
  if (entry.method === 0) out = raw;
  else if (entry.method === 8) {
    // never more than the entry says it holds: a zip bomb stops at its declared size
    try {
      out = zlib.inflateRawSync(raw, { maxOutputLength: Math.max(1, entry.size) });
    } catch (error) {
      throw new ZipError(`${entry.name}: ${error.code === 'ERR_BUFFER_TOO_LARGE' ? 'inflates to more than its declared size' : error.message}`);
    }
  } else throw new ZipError(`${entry.name}: unsupported zip method ${entry.method}`);
  if (out.length !== entry.size) throw new ZipError(`${entry.name}: ${out.length} bytes, but the archive declares ${entry.size}`);
  return out;
}

export const isZip = (data) => data.length >= 4 && data.readUInt32LE(0) === LOCAL;

/** Extracts every file under dest (no absolute paths or ../ escapes). Returns the names written. */
export function extractZip(data, dest) {
  const root = path.resolve(dest);
  const written = [];
  const entries = zipEntries(data);
  const total = entries.reduce((sum, entry) => sum + (entry.isDir ? 0 : entry.size), 0);
  if (total > MAX_TOTAL) throw new ZipError(limitMessage('zip archive', total, MAX_TOTAL));
  for (const entry of entries) {
    if (entry.isDir) continue;
    const target = safeJoin(root, entry.name);
    if (!target) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, zipRead(data, entry));
    written.push(entry.name);
  }
  return written;
}
