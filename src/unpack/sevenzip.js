// A read-only 7z archive reader for the app packages electron-builder builds (app-64.7z inside NSIS installers): the
// Copy, LZMA, LZMA2, Deflate, Delta, BCJ (x86) and BCJ2 coders, encoded headers, CRC checks. Encrypted archives and other
// coders (PPMd, ARM64 ...) are refused with a clear error. A port of Electron-Dynamic's sevenzip.py.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { decodeLzma, decodeLzma2, bcjX86Decode } from './lzma.js';

export const SIGNATURE = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
export class SevenZipError extends Error {}

const k = { End: 0, Header: 1, ArchiveProperties: 2, AdditionalStreamsInfo: 3, MainStreamsInfo: 4, FilesInfo: 5, PackInfo: 6, UnPackInfo: 7,
  SubStreamsInfo: 8, Size: 9, CRC: 10, Folder: 11, CodersUnPackSize: 12, NumUnPackStream: 13, EmptyStream: 14, EmptyFile: 15, Name: 17,
  WinAttributes: 21, EncodedHeader: 23 };
const METHODS = { '00': 'Copy', '03': 'Delta', '21': 'LZMA2', '030101': 'LZMA', '03030103': 'BCJ', '0303011b': 'BCJ2', '040108': 'Deflate', '06f10701': 'AES' };
const crc32 = (data) => zlib.crc32(data) >>> 0;

class Reader {
  constructor(data) {
    this.data = data;
    this.pos = 0;
  }

  byte() {
    if (this.pos >= this.data.length) throw new SevenZipError('truncated header');
    return this.data[this.pos++];
  }

  bytes(n) {
    if (this.pos + n > this.data.length) throw new SevenZipError('truncated header');
    const out = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  u32() {
    return this.bytes(4).readUInt32LE(0);
  }

  number() {
    const first = this.byte();
    let mask = 0x80;
    let value = 0;
    for (let i = 0; i < 8; i++) {
      if ((first & mask) === 0) return value + (first & (mask - 1)) * 2 ** (8 * i);
      value += this.byte() * 2 ** (8 * i);
      mask >>>= 1;
    }
    return value;
  }

  bits(n) {
    const out = [];
    let mask = 0;
    let current = 0;
    for (let i = 0; i < n; i++) {
      if (mask === 0) {
        current = this.byte();
        mask = 0x80;
      }
      out.push(!!(current & mask));
      mask >>>= 1;
    }
    return out;
  }

  defined(n) {
    return this.byte() ? new Array(n).fill(true) : this.bits(n);
  }
}

const totalOut = (folder) => folder.coders.reduce((n, c) => n + c.outputs, 0);
const totalIn = (folder) => folder.coders.reduce((n, c) => n + c.inputs, 0);
function mainOutput(folder) {
  const bound = new Set(folder.bindPairs.map(([, out]) => out));
  for (let i = 0; i < totalOut(folder); i++) if (!bound.has(i)) return i;
  throw new SevenZipError('folder has no unbound output');
}
const unpackSize = (folder) => folder.unpackSizes[mainOutput(folder)];

export class SevenZipArchive {
  /** @param {Buffer} data the archive, or a file holding it at `base` */
  constructor(data, base = 0) {
    this.data = data;
    this.base = base;
    this.packPos = 0;
    this.packSizes = [];
    this.folders = [];
    this.entries = [];
    this.skipped = [];
    this.readSignatureHeader();
  }

  static open(file, base = 0) {
    return new SevenZipArchive(fs.readFileSync(file), base);
  }

  at(offset, length) {
    const start = this.base + offset;
    if (start + length > this.data.length) throw new SevenZipError('unexpected end of archive');
    return this.data.subarray(start, start + length);
  }

  readSignatureHeader() {
    const head = this.at(0, 32);
    if (!head.subarray(0, 6).equals(SIGNATURE)) throw new SevenZipError('not a 7z archive');
    if (crc32(head.subarray(12, 32)) !== head.readUInt32LE(8)) throw new SevenZipError('start header CRC mismatch');
    const nextOffset = Number(head.readBigUInt64LE(12));
    const nextSize = Number(head.readBigUInt64LE(20));
    const nextCrc = head.readUInt32LE(28);
    if (nextSize === 0) return; // empty archive
    let header = this.at(32 + nextOffset, nextSize);
    if (crc32(header) !== nextCrc) throw new SevenZipError('header CRC mismatch');
    for (let depth = 0; depth < 4; depth++) { // encoded headers may nest
      const r = new Reader(header);
      const id = r.byte();
      if (id === k.Header) return this.readHeader(r);
      if (id !== k.EncodedHeader) throw new SevenZipError(`unexpected header id ${id}`);
      const streams = this.readStreamsInfo(r);
      const saved = [this.packPos, this.packSizes, this.folders];
      [this.packPos, this.packSizes, this.folders] = [streams.packPos, streams.packSizes, streams.folders];
      this.headerMethods = streams.folders.length ? streams.folders[0].coders.map(c => c.name) : [];
      header = this.decodeFolder(0);
      [this.packPos, this.packSizes, this.folders] = saved;
    }
    throw new SevenZipError('too many nested encoded headers');
  }

  readHeader(r) {
    let id = r.byte();
    if (id === k.ArchiveProperties) {
      while (r.byte() !== k.End) r.bytes(r.number());
      id = r.byte();
    }
    if (id === k.AdditionalStreamsInfo) {
      this.readStreamsInfo(r);
      id = r.byte();
    }
    if (id === k.MainStreamsInfo) {
      ({ packPos: this.packPos, packSizes: this.packSizes, folders: this.folders } = this.readStreamsInfo(r));
      id = r.byte();
    }
    if (id === k.FilesInfo) {
      this.readFilesInfo(r);
      id = r.byte();
    }
    if (id !== k.End) throw new SevenZipError(`bad header end marker ${id}`);
  }

  readStreamsInfo(r) {
    let packPos = 0;
    let packSizes = [];
    let folders = [];
    for (;;) {
      const id = r.byte();
      if (id === k.End) break;
      if (id === k.PackInfo) {
        packPos = r.number();
        const n = r.number();
        for (;;) {
          const t = r.byte();
          if (t === k.End) break;
          if (t === k.Size) packSizes = Array.from({ length: n }, () => r.number());
          else if (t === k.CRC) for (const d of r.defined(n)) { if (d) r.u32(); }
          else r.bytes(r.number());
        }
      } else if (id === k.UnPackInfo) folders = this.readUnpackInfo(r);
      else if (id === k.SubStreamsInfo) this.readSubStreamsInfo(r, folders);
      else throw new SevenZipError(`unexpected streams property ${id}`);
    }
    let index = 0;
    for (const folder of folders) {
      folder.packIndex = index;
      index += folder.packedStreams.length;
      if (!folder.substreamSizes) folder.substreamSizes = folder.substreams === 1 ? [unpackSize(folder)] : [];
    }
    return { packPos, packSizes, folders };
  }

  readUnpackInfo(r) {
    if (r.byte() !== k.Folder) throw new SevenZipError('expected kFolder');
    const n = r.number();
    if (r.byte() !== 0) throw new SevenZipError('external folders are not supported');
    const folders = [];
    for (let f = 0; f < n; f++) {
      const coders = [];
      const count = r.number();
      for (let c = 0; c < count; c++) {
        const flags = r.byte();
        const method = r.bytes(flags & 0x0f).toString('hex');
        let inputs = 1;
        let outputs = 1;
        if (flags & 0x10) {
          inputs = r.number();
          outputs = r.number();
        }
        const props = flags & 0x20 ? Buffer.from(r.bytes(r.number())) : Buffer.alloc(0);
        if (flags & 0x80) throw new SevenZipError('alternative coder methods are not supported');
        coders.push({ method, name: METHODS[method] || method, inputs, outputs, props });
      }
      const folder = { coders, bindPairs: [], packedStreams: [], substreams: 1 };
      for (let i = 0; i < totalOut(folder) - 1; i++) folder.bindPairs.push([r.number(), r.number()]);
      const packed = totalIn(folder) - folder.bindPairs.length;
      if (packed === 1) {
        const boundIn = new Set(folder.bindPairs.map(([input]) => input));
        for (let i = 0; i < totalIn(folder); i++) if (!boundIn.has(i)) { folder.packedStreams.push(i); break; }
      } else for (let i = 0; i < packed; i++) folder.packedStreams.push(r.number());
      folders.push(folder);
    }
    if (r.byte() !== k.CodersUnPackSize) throw new SevenZipError('expected kCodersUnPackSize');
    for (const folder of folders) folder.unpackSizes = Array.from({ length: totalOut(folder) }, () => r.number());
    let id = r.byte();
    if (id === k.CRC) {
      const defined = r.defined(folders.length);
      folders.forEach((folder, i) => { if (defined[i]) folder.crc = r.u32(); });
      id = r.byte();
    }
    if (id !== k.End) throw new SevenZipError('bad unpack info end');
    return folders;
  }

  readSubStreamsInfo(r, folders) {
    let id = r.byte();
    if (id === k.NumUnPackStream) {
      for (const folder of folders) folder.substreams = r.number();
      id = r.byte();
    }
    if (id === k.Size) {
      for (const folder of folders) {
        if (folder.substreams === 0) continue;
        const sizes = Array.from({ length: folder.substreams - 1 }, () => r.number());
        sizes.push(unpackSize(folder) - sizes.reduce((a, b) => a + b, 0));
        folder.substreamSizes = sizes;
      }
      id = r.byte();
    } else for (const folder of folders) if (folder.substreams === 1) folder.substreamSizes = [unpackSize(folder)];
    const needed = folders.reduce((n, f) => n + (f.substreams === 1 && f.crc !== undefined ? 0 : f.substreams), 0);
    let crcs = [];
    if (id === k.CRC) {
      crcs = r.defined(needed).map(d => d ? r.u32() : undefined);
      id = r.byte();
    }
    let at = 0;
    for (const folder of folders) {
      if (folder.substreams === 1 && folder.crc !== undefined) folder.substreamCrcs = [folder.crc];
      else {
        folder.substreamCrcs = crcs.slice(at, at + folder.substreams);
        at += folder.substreams;
      }
    }
    while (id !== k.End) {
      r.bytes(r.number());
      id = r.byte();
    }
  }

  readFilesInfo(r) {
    const n = r.number();
    const entries = Array.from({ length: n }, () => ({ name: '', size: 0, isDir: false, hasStream: true }));
    let emptyStream = new Array(n).fill(false);
    let emptyFile = [];
    for (;;) {
      const type = r.byte();
      if (type === k.End) break;
      const size = r.number();
      if (type === k.EmptyStream) emptyStream = r.bits(n);
      else if (type === k.EmptyFile) emptyFile = r.bits(emptyStream.filter(Boolean).length);
      else if (type === k.Name) {
        const sub = new Reader(r.bytes(size));
        if (sub.byte() !== 0) throw new SevenZipError('external names are not supported');
        const names = sub.data.subarray(sub.pos).toString('utf16le').split('\0');
        entries.forEach((e, i) => { e.name = (names[i] || '').replace(/\\/g, '/'); });
      } else if (type === k.WinAttributes) {
        const sub = new Reader(r.bytes(size));
        const defined = sub.defined(n);
        if (sub.byte() !== 0) throw new SevenZipError('external attributes are not supported');
        entries.forEach((e, i) => { if (defined[i]) e.attributes = sub.u32(); });
      } else r.bytes(size); // times, anti items, start positions, padding
    }
    let emptyIndex = 0;
    let folderIndex = 0;
    let substream = 0;
    let offset = 0;
    entries.forEach((e, i) => {
      if (emptyStream[i]) {
        e.hasStream = false;
        const isFile = emptyFile[emptyIndex++] || false;
        e.isDir = !isFile || (e.attributes !== undefined && !!(e.attributes & 0x10));
        return;
      }
      while (folderIndex < this.folders.length && substream >= this.folders[folderIndex].substreams) {
        folderIndex++;
        substream = 0;
        offset = 0;
      }
      if (folderIndex >= this.folders.length) throw new SevenZipError('more file streams than folders');
      const folder = this.folders[folderIndex];
      e.folder = folderIndex;
      e.size = folder.substreamSizes[substream];
      e.offset = offset;
      e.crc = (folder.substreamCrcs || [])[substream];
      offset += e.size;
      substream++;
    });
    this.entries = entries;
  }

  /** The coders used, in order of first use. */
  methods() {
    return [...new Set(this.folders.flatMap(f => f.coders.map(c => c.name)))];
  }

  packStream(index) {
    const offset = this.packPos + this.packSizes.slice(0, index).reduce((a, b) => a + b, 0);
    return this.at(32 + offset, this.packSizes[index]);
  }

  decodeFolder(index) {
    const folder = this.folders[index];
    const inBase = [];
    const outBase = [];
    let a = 0;
    let b = 0;
    for (const coder of folder.coders) {
      inBase.push(a);
      outBase.push(b);
      a += coder.inputs;
      b += coder.outputs;
    }
    const cache = new Map();
    const coderOfOutput = (out) => {
      const i = folder.coders.findIndex((c, ci) => out >= outBase[ci] && out < outBase[ci] + c.outputs);
      if (i < 0) throw new SevenZipError('bad coder output');
      return i;
    };
    const input = (inIndex) => {
      const pair = folder.bindPairs.find(([i]) => i === inIndex);
      if (pair) return output(pair[1]);
      const packed = folder.packedStreams.indexOf(inIndex);
      if (packed >= 0) return this.packStream(folder.packIndex + packed);
      throw new SevenZipError('unbound coder input');
    };
    const output = (outIndex) => {
      if (cache.has(outIndex)) return cache.get(outIndex);
      const ci = coderOfOutput(outIndex);
      const coder = folder.coders[ci];
      const size = folder.unpackSizes[outIndex];
      let data;
      switch (coder.name) {
        case 'Copy': data = input(inBase[ci]); break;
        case 'LZMA': data = decodeLzma(coder.props, input(inBase[ci]), size); break;
        case 'LZMA2': data = decodeLzma2(input(inBase[ci]), size); break;
        case 'BCJ': data = bcjX86Decode(Buffer.from(input(inBase[ci]))); break;
        case 'Deflate': data = zlib.inflateRawSync(input(inBase[ci])); break;
        case 'Delta': data = deltaDecode(Buffer.from(input(inBase[ci])), coder.props.length ? coder.props[0] + 1 : 1); break;
        case 'BCJ2': data = bcj2Decode(input(inBase[ci]), input(inBase[ci] + 1), input(inBase[ci] + 2), input(inBase[ci] + 3), size); break;
        case 'AES': throw new SevenZipError('encrypted 7z archives are not supported');
        default: throw new SevenZipError(`unsupported 7z coder ${coder.name}`);
      }
      if (data.length < size) throw new SevenZipError(`${coder.name}: short output (${data.length} < ${size})`);
      data = data.subarray(0, size);
      cache.set(outIndex, data);
      return data;
    };
    const result = output(mainOutput(folder));
    if (folder.crc !== undefined && crc32(result) !== folder.crc) throw new SevenZipError('folder CRC mismatch');
    return result;
  }

  /** [entry, Buffer] for every file, each folder decoded once; `want(entry)` can skip files. */
  *files(want = () => true) {
    const byFolder = new Map();
    for (const e of this.entries) {
      if (e.isDir) continue;
      if (!e.hasStream) {
        if (want(e)) yield [e, Buffer.alloc(0)];
        continue;
      }
      byFolder.set(e.folder, [...(byFolder.get(e.folder) || []), e]);
    }
    for (const index of [...byFolder.keys()].sort((x, y) => x - y)) {
      const wanted = byFolder.get(index).filter(want);
      if (wanted.length === 0) continue;
      const data = this.decodeFolder(index);
      for (const e of wanted) {
        const blob = data.subarray(e.offset, e.offset + e.size);
        if (e.crc !== undefined && crc32(blob) !== e.crc) throw new SevenZipError(`CRC mismatch for ${e.name}`);
        yield [e, blob];
      }
    }
  }

  /** Extracts every file under `dest` (no absolute paths or ../ escapes). Returns the names written. */
  extractAll(dest) {
    const root = path.resolve(dest);
    const written = [];
    for (const e of this.entries) if (e.isDir) {
      const target = safeJoin(root, e.name);
      if (target) fs.mkdirSync(target, { recursive: true });
    }
    for (const [e, blob] of this.files()) {
      const target = safeJoin(root, e.name);
      if (!target) continue;
      try {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, blob);
        written.push(e.name);
      } catch {
        this.skipped.push(e.name);
      }
    }
    return written;
  }
}

/** A path inside root for an archive entry name, or undefined for absolute paths and ../ escapes. */
export function safeJoin(root, name) {
  const clean = String(name).replace(/\\/g, '/').replace(/^\/+/, '');
  if (!clean || /^[A-Za-z]:/.test(clean)) return undefined;
  const target = path.resolve(root, ...clean.split('/').filter(part => part && part !== '.'));
  return target === root || target.startsWith(root + path.sep) ? target : undefined;
}

function deltaDecode(data, distance) {
  for (let i = distance; i < data.length; i++) data[i] = (data[i] + data[i - distance]) & 0xff;
  return data;
}

/**
 * 7-Zip's BCJ2: x86 CALL/JMP targets moved into two streams, with a range-coded flag per candidate opcode.
 * main: the code with branches removed; call / jump: big-endian absolute targets; rc: the range-coder stream.
 */
export function bcj2Decode(main, call, jump, rc, size) {
  const out = Buffer.alloc(size);
  const probs = new Uint16Array(258).fill(1024);
  if (rc.length < 5) throw new SevenZipError('BCJ2: short range-coder stream');
  let code = rc.readUInt32BE(1);
  let range = 0xffffffff;
  let rcPos = 5;
  let callPos = 0;
  let jumpPos = 0;
  let inPos = 0;
  let outPos = 0;
  let prev = 0;
  while (outPos < size && inPos < main.length) {
    const b = main[inPos++];
    out[outPos++] = b;
    const isJump = (b & 0xfe) === 0xe8 || (prev === 0x0f && (b & 0xf0) === 0x80);
    if (!isJump) {
      prev = b;
      continue;
    }
    if (outPos >= size) break;
    const index = b === 0xe8 ? prev : b === 0xe9 ? 256 : 257;
    const p = probs[index];
    const bound = (range >>> 11) * p;
    let bit;
    if (code < bound) {
      range = bound;
      probs[index] = p + ((2048 - p) >>> 5);
      bit = 0;
    } else {
      range -= bound;
      code -= bound;
      probs[index] = p - (p >>> 5);
      bit = 1;
    }
    if (range < 0x1000000) {
      range = (range << 8) >>> 0;
      code = ((code << 8) | (rcPos < rc.length ? rc[rcPos] : 0)) >>> 0;
      rcPos++;
    }
    if (bit === 0) {
      prev = b;
      continue;
    }
    let src;
    if (b === 0xe8) {
      src = call.readUInt32BE(callPos);
      callPos += 4;
    } else {
      src = jump.readUInt32BE(jumpPos);
      jumpPos += 4;
    }
    const dest = (src - (outPos + 4)) >>> 0;
    const n = Math.min(4, size - outPos);
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(dest);
    bytes.copy(out, outPos, 0, n);
    outPos += n;
    prev = dest >>> 24;
  }
  return out.subarray(0, outPos);
}

/** Offsets of CRC-valid 7z signature headers inside a buffer. */
export function findEmbedded(data, start = 0) {
  const hits = [];
  for (let at = data.indexOf(SIGNATURE, start); at !== -1; at = data.indexOf(SIGNATURE, at + 1)) {
    const head = data.subarray(at, at + 32);
    if (head.length === 32 && crc32(head.subarray(12, 32)) === head.readUInt32LE(8)) hits.push(at);
  }
  return hits;
}
