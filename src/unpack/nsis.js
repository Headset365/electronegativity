// The app package inside an NSIS installer. electron-builder's NSIS target embeds the app as $PLUGINSDIR\app-64.7z (or
// app-32 / app-arm64) with SetCompress off, so the 7z archive is a stored data block. The FirstHeader is found, the data
// blocks are walked (decompressed when needed: deflate or LZMA, solid or not) and every embedded 7z is returned. The
// installer script header is also decompressed, for the URL protocols and file associations it registers and the
// package URLs of web installers. A port of Electron-Dynamic's nsis.py (bzip2 installers are not supported there either).
import zlib from 'node:zlib';
import { decodeLzmaStream, bcjX86Decode } from './lzma.js';
import { SIGNATURE as SEVEN_ZIP } from './sevenzip.js';

const FIRST_HEADER = Buffer.concat([Buffer.from([0xef, 0xbe, 0xad, 0xde]), Buffer.from('NullsoftInst', 'latin1')]);
const FIRST_HEADER_SIZE = 28;

export class NsisError extends Error {}

/** NSIS looks for the FirstHeader at 512-byte aligned offsets. */
export function findFirstHeader(data) {
  for (let at = data.indexOf(FIRST_HEADER); at !== -1; at = data.indexOf(FIRST_HEADER, at + 1)) {
    const offset = at - 4;
    if (offset >= 0 && offset % 512 === 0) return offset;
  }
  return -1;
}

function lzma(buffer, limit) {
  let filter = 0;
  let data = buffer;
  if ((data[0] === 0 || data[0] === 1) && data.length > 6 && data[1] === 0x5d) {
    filter = data[0];
    data = data.subarray(1);
  }
  let out;
  try {
    out = decodeLzmaStream(data, { limit });
  } catch {
    return Buffer.alloc(0);
  }
  return filter === 1 ? bcjX86Decode(Buffer.from(out)) : out;
}

// raw deflate; a stream cut short (the start of a block, or data running past the end) keeps what inflated
function deflate(buffer, limit) {
  const out = zlib.inflateRawSync(buffer, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
  return limit ? out.subarray(0, limit) : out;
}

function decompress(method, buffer, limit) {
  if (method === 'lzma') return lzma(buffer, limit);
  if (method === 'bzip2') throw new NsisError('NSIS bzip2 streams are not supported');
  if (method === 'deflate') return deflate(buffer, limit);
  return buffer;
}

const looksLzma = (b) => b.length >= 6 && ((b[0] === 0x5d && b[1] === 0) || ((b[0] === 0 || b[0] === 1) && b[1] === 0x5d && b[2] === 0));

// [method, solid] from the bytes after the FirstHeader
function detect(data, start) {
  const a = data.subarray(start, start + 8);
  const b = data.subarray(start + 4, start + 12);
  if (looksLzma(a)) return ['lzma', true];
  if (looksLzma(b)) return ['lzma', false];
  if (b.length >= 2 && b[0] === 0x31 && b[1] < 14) return ['bzip2', false]; // NSIS bzip2: block-size digit, no magic
  if (a.length >= 2 && a[0] === 0x31 && a[1] < 14) return ['bzip2', true];
  const first = data.readUInt32LE(start);
  const n = first & 0x7fffffff;
  if (first & 0x80000000 && n > 0 && n < data.length - start) return ['deflate', false];
  if (!(first & 0x80000000) && n > 0 && n < data.length - start) return ['none', false];
  return ['deflate', true];
}

/**
 * @returns {{ offset, flags, compression, solid, header: Buffer, payloads: Array<{ kind: '7z'|'7z-blob', offset?, size?, data? }>, strings, warnings }}
 */
export function parseNsis(data, { maxSolid = 2 ** 31 - 1 } = {}) {
  const offset = findFirstHeader(data);
  if (offset < 0) throw new NsisError('no NSIS FirstHeader found');
  const flags = data.readUInt32LE(offset);
  const dataLength = data.readUInt32LE(offset + 24);
  const start = offset + FIRST_HEADER_SIZE;
  const [method, solid] = detect(data, start);
  const info = { offset, flags, compression: method, solid, header: Buffer.alloc(0), payloads: [], warnings: [] };
  if (solid && method === 'bzip2') throw new NsisError('solid bzip2 NSIS installers are not supported');
  if (solid && method !== 'none') {
    const blob = decompress(method, data.subarray(start, offset + dataLength), maxSolid);
    if (blob.length < 4) throw new NsisError('could not decompress the solid NSIS data');
    const headerLength = blob.readUInt32LE(0);
    info.header = blob.subarray(4, 4 + headerLength);
    for (let pos = 4 + headerLength; pos + 4 <= blob.length;) {
      const n = blob.readUInt32LE(pos) & 0x7fffffff;
      const chunk = blob.subarray(pos + 4, pos + 4 + n);
      if (chunk.subarray(0, 6).equals(SEVEN_ZIP)) info.payloads.push({ kind: '7z-blob', data: chunk });
      pos += 4 + n;
    }
  } else {
    const end = Math.min(data.length, dataLength ? offset + dataLength : data.length);
    let first = true;
    for (let pos = start; pos + 4 <= end;) {
      const raw = data.readUInt32LE(pos);
      const compressed = !!(raw & 0x80000000);
      const n = raw & 0x7fffffff;
      const body = pos + 4;
      if (n === 0 || body + n > end) break;
      const block = data.subarray(body, body + n);
      if (first) {
        try {
          info.header = compressed ? decompress(method, block) : block;
        } catch (error) {
          info.warnings.push(`could not decompress the NSIS script header (${method}): ${error.message}`);
        }
        first = false;
      } else if (!compressed && block.subarray(0, 6).equals(SEVEN_ZIP)) info.payloads.push({ kind: '7z', offset: body, size: n });
      else if (compressed && method !== 'bzip2') {
        let head;
        try {
          head = decompress(method, block.subarray(0, Math.min(n, 1 << 16)), 64);
        } catch {
          head = Buffer.alloc(0);
        }
        if (head.subarray(0, 6).equals(SEVEN_ZIP)) info.payloads.push({ kind: '7z-blob', data: decompress(method, block) });
      }
      pos = body + n;
    }
  }
  info.strings = headerStrings(info.header);
  return info;
}

/** Printable UTF-16 and ASCII strings of the installer script. */
export function headerStrings(header, limit = 20000) {
  const out = [];
  const seen = new Set();
  const text = header.toString('latin1');
  const add = (s) => {
    if (!seen.has(s) && out.length < limit) {
      seen.add(s);
      out.push(s);
    }
  };
  const utf16 = /(?:[\x20-\x7e]\x00){6,}/g; // eslint-disable-line no-control-regex
  for (const m of text.matchAll(utf16)) add(Buffer.from(m[0], 'latin1').toString('utf16le'));
  for (const m of text.matchAll(/[\x20-\x7e]{6,}/g)) add(m[0]);
  return out;
}

/** URL protocols and file extensions the installer registers (HKCR / Software\Classes). */
export function registryClasses(strings) {
  const protocols = [];
  const extensions = [];
  const urlProtocol = strings.some(s => s.includes('URL Protocol'));
  for (const s of strings) {
    for (const m of s.matchAll(/Software\\Classes\\([^\\\s"]+)/gi)) {
      const name = m[1];
      if (name.startsWith('$') || ['applications', 'clsid', '*', 'directory'].includes(name.toLowerCase())) continue;
      if (name.startsWith('.')) { if (!extensions.includes(name)) extensions.push(name); }
      else if (urlProtocol && !protocols.includes(name) && !name.includes('.')) protocols.push(name);
    }
  }
  return { protocols, extensions };
}

export function packageUrls(strings) {
  const urls = [];
  for (const s of strings) for (const m of s.matchAll(/https?:\/\/[^\s"'<>]+/g)) if (!urls.includes(m[0])) urls.push(m[0]);
  return urls;
}
