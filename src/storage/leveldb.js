// Read-only LevelDB reader for Chromium profile stores (Local Storage, Session Storage, IndexedDB). No dependencies.
//
// Reads write-ahead logs (*.log) and sorted tables (*.ldb / *.sst, with Snappy block compression). It never writes, never
// takes the LOCK, and tolerates torn or corrupt records: a damaged block is skipped, not fatal. Deleted and overwritten
// entries may still be returned (LevelDB keeps them until a compaction), which is what a data-at-rest review wants to see.
import fs from 'node:fs';
import path from 'node:path';

const MAX_FILE = 256 * 1024 * 1024;
const TABLE_MAGIC = Buffer.from([0x57, 0xfb, 0x80, 0x8b, 0x24, 0x75, 0x47, 0xdb]);

/** [value, nextPosition] of the varint at `pos` */
export function varint(buf, pos) {
  let result = 0;
  let shift = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error('truncated varint');
    const b = buf[pos++];
    result += (b & 0x7f) * 2 ** shift;
    if (!(b & 0x80)) return [result, pos];
    shift += 7;
    if (shift > 63) throw new Error('varint too long');
  }
}

/** Raw Snappy block format, as LevelDB tables use it. */
export function snappyDecompress(buf) {
  let [length, pos] = varint(buf, 0);
  const out = Buffer.alloc(length);
  let written = 0;
  while (pos < buf.length) {
    const tag = buf[pos++];
    const kind = tag & 3;
    if (kind === 0) { // literal
      let len = tag >> 2;
      if (len >= 60) {
        const extra = len - 59;
        len = buf.readUIntLE(pos, extra);
        pos += extra;
      }
      len += 1;
      if (written + len > length || pos + len > buf.length) throw new Error('bad snappy literal');
      buf.copy(out, written, pos, pos + len);
      written += len;
      pos += len;
      continue;
    }
    let len;
    let offset;
    if (kind === 1) {
      len = ((tag >> 2) & 7) + 4;
      offset = ((tag >> 5) << 8) | buf[pos];
      pos += 1;
    } else if (kind === 2) {
      len = (tag >> 2) + 1;
      offset = buf.readUInt16LE(pos);
      pos += 2;
    } else {
      len = (tag >> 2) + 1;
      offset = buf.readUInt32LE(pos);
      pos += 4;
    }
    if (offset === 0 || offset > written || written + len > length) throw new Error('bad snappy offset');
    const start = written - offset;
    for (let i = 0; i < len; i++) out[written + i] = out[start + i]; // may overlap: byte by byte
    written += len;
  }
  if (written !== length) throw new Error('snappy length mismatch');
  return out;
}

// Logical records of a write-ahead log, reassembled from its 32 KiB blocks (types 1=FULL 2=FIRST 3=MIDDLE 4=LAST)
function* logRecords(data) {
  const BLOCK = 32768;
  let pos = 0;
  let pending = [];
  while (pos + 7 <= data.length) {
    const left = BLOCK - (pos % BLOCK);
    if (left < 7) {
      pos += left;
      continue;
    }
    const length = data.readUInt16LE(pos + 4);
    const type = data[pos + 6];
    const payload = data.subarray(pos + 7, pos + 7 + length);
    pos += 7 + length;
    if (type === 0 && length === 0) continue;
    if (type === 1) yield payload;
    else if (type === 2) pending = [payload];
    else if (type === 3) pending.push(payload);
    else if (type === 4) {
      pending.push(payload);
      yield Buffer.concat(pending);
      pending = [];
    }
  }
}

// A log record is a WriteBatch: [key, value] for each Put
function* batchPuts(record) {
  if (record.length < 12) return;
  const count = record.readUInt32LE(8);
  let pos = 12;
  for (let i = 0; i < count && pos < record.length; i++) {
    const tag = record[pos++];
    let length;
    if (tag === 0) { // deletion: key only
      [length, pos] = varint(record, pos);
      pos += length;
      continue;
    }
    if (tag !== 1) return; // unknown tag: the record is torn
    [length, pos] = varint(record, pos);
    const key = record.subarray(pos, pos + length);
    pos += length;
    [length, pos] = varint(record, pos);
    const value = record.subarray(pos, pos + length);
    pos += length;
    yield [key, value];
  }
}

/** [key, value] puts from a LevelDB write-ahead log (*.log). */
export function* logKeyValues(data) {
  for (const record of logRecords(data)) {
    try {
      yield* batchPuts(record);
    } catch {
      // a damaged record is skipped
    }
  }
}

// Entries of one table block: prefix-compressed keys, with the restart array at the tail
function* blockEntries(block) {
  if (block.length < 4) return;
  const restarts = block.readUInt32LE(block.length - 4);
  const end = block.length - 4 - restarts * 4;
  let pos = 0;
  let lastKey = Buffer.alloc(0);
  while (pos < end) {
    let shared;
    let nonShared;
    let valueLength;
    try {
      [shared, pos] = varint(block, pos);
      [nonShared, pos] = varint(block, pos);
      [valueLength, pos] = varint(block, pos);
    } catch {
      return;
    }
    const key = Buffer.concat([lastKey.subarray(0, shared), block.subarray(pos, pos + nonShared)]);
    pos += nonShared;
    const value = block.subarray(pos, pos + valueLength);
    pos += valueLength;
    lastKey = key;
    yield [key, value];
  }
}

// A block is `size` bytes, then one type byte (0 raw, 1 Snappy) and a 4-byte CRC
function readBlock(data, offset, size) {
  if (offset + size >= data.length) return undefined;
  const raw = data.subarray(offset, offset + size);
  const type = data[offset + size];
  if (type === 1) {
    try {
      return snappyDecompress(raw);
    } catch {
      return undefined;
    }
  }
  return type === 0 ? raw : undefined;
}

/**
 * [userKey, value] puts from a LevelDB table (*.ldb / *.sst), best effort: the index block leads to the data blocks,
 * whose keys are internal keys (user key + an 8-byte trailer whose low byte is the type: 1 value, 0 deletion).
 */
export function* tableKeyValues(data) {
  if (data.length < 48 || !data.subarray(data.length - 8).equals(TABLE_MAGIC)) return;
  const footer = data.subarray(data.length - 48, data.length - 8);
  let pos = 0;
  let indexOffset;
  let indexSize;
  try {
    [, pos] = varint(footer, pos); // metaindex handle
    [, pos] = varint(footer, pos);
    [indexOffset, pos] = varint(footer, pos);
    [indexSize] = varint(footer, pos);
  } catch {
    return;
  }
  const index = readBlock(data, indexOffset, indexSize);
  if (!index) return;
  for (const [, handle] of blockEntries(index)) {
    let blockOffset;
    let blockSize;
    try {
      let at;
      [blockOffset, at] = varint(handle, 0);
      [blockSize] = varint(handle, at);
    } catch {
      continue;
    }
    const block = readBlock(data, blockOffset, blockSize);
    if (!block) continue;
    for (const [internalKey, value] of blockEntries(block)) {
      if (internalKey.length < 8) continue;
      if (internalKey[internalKey.length - 8] === 1) yield [internalKey.subarray(0, internalKey.length - 8), value];
    }
  }
}

/**
 * Every live key/value in a LevelDB directory, as a Map keyed by the key's latin1 string (keys are bytes). Read-only.
 * Newer *.log puts win over older *.ldb data (approximately: files in name order). Never throws: unreadable files are
 * skipped.
 */
export function readStore(dir, maxEntries = 20000) {
  const out = new Map();
  let files;
  try {
    files = fs.readdirSync(dir).sort();
  } catch {
    return out;
  }
  for (const name of files) {
    const lower = name.toLowerCase();
    if (!/\.(ldb|sst|log)$/.test(lower)) continue;
    let data;
    try {
      const file = path.join(dir, name);
      if (fs.statSync(file).size > MAX_FILE) continue;
      data = fs.readFileSync(file);
    } catch {
      continue;
    }
    try {
      for (const [key, value] of lower.endsWith('.log') ? logKeyValues(data) : tableKeyValues(data)) {
        out.set(key.toString('latin1'), { key: Buffer.from(key), value: Buffer.from(value) });
        if (out.size >= maxEntries) return out;
      }
    } catch {
      // a damaged file is skipped
    }
  }
  return out;
}

/** Whether a directory looks like a LevelDB store. */
export function isLevelDb(dir) {
  try {
    return fs.existsSync(path.join(dir, 'CURRENT')) && fs.readdirSync(dir).some(name => /\.(ldb|log|sst)$/i.test(name));
  } catch {
    return false;
  }
}
