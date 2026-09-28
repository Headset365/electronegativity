// Builds tiny but valid PE32+ files for tests (no compiler needed): sections, a resource tree (VS_VERSIONINFO, the
// INTEGRITY/ELECTRONASAR entry), DllCharacteristics, an optional Authenticode certificate table and the fuse wire.
// A port of Electron-Dynamic's tests/fixtures/fakepe.py.
const align = (n, a) => Math.ceil(n / a) * a;
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const pad4 = (b) => Buffer.concat([b, Buffer.alloc(align(b.length, 4) - b.length)]);

function vsBlock(key, value = Buffer.alloc(0), children = Buffer.alloc(0), type = 1, valueLength) {
  const keyBytes = Buffer.concat([Buffer.from(key, 'utf16le'), Buffer.alloc(2)]);
  const headLength = 6 + keyBytes.length;
  const pad = Buffer.alloc(align(headLength, 4) - headLength);
  const body = pad4(value);
  const total = headLength + pad.length + body.length + children.length;
  const vlen = valueLength ?? (type === 1 ? value.length / 2 : value.length);
  return Buffer.concat([u16(total), u16(vlen), u16(type), keyBytes, pad, body, children]);
}

export function versionInfo(strings) {
  const fixed = Buffer.concat([0xfeef04bd, 0x10000, 0x10000, 0, 0x10000, 0, 0x3f, 0, 0x40004, 1, 0, 0, 0].map(u32));
  const entries = Buffer.concat(Object.entries(strings).map(([k, v]) => vsBlock(k, Buffer.concat([Buffer.from(v, 'utf16le'), Buffer.alloc(2)]))));
  const table = vsBlock('040904b0', Buffer.alloc(0), entries, 1, 0);
  const sfi = vsBlock('StringFileInfo', Buffer.alloc(0), table, 1, 0);
  return vsBlock('VS_VERSION_INFO', fixed, sfi, 0, fixed.length);
}

// resources: [[type, name, Buffer]] with numeric or string types/names; one language (1033)
function buildRsrc(resources, rva) {
  const types = new Map();
  for (const [type, name, data] of resources) types.set(type, [...(types.get(type) || []), [name, data]]);
  const order = (a, b) => (typeof a === 'string' ? 0 : 1) - (typeof b === 'string' ? 0 : 1) || String(a).localeCompare(String(b));
  const typeKeys = [...types.keys()].sort(order);
  const header = (named, ids) => Buffer.concat([u32(0), u32(0), u16(0), u16(0), u16(named), u16(ids)]);
  const level1Size = 16 + 8 * typeKeys.length;
  const level2Sizes = typeKeys.map(t => 16 + 8 * types.get(t).length);
  const leaves = typeKeys.reduce((n, t) => n + types.get(t).length, 0);
  const dirTotal = level1Size + level2Sizes.reduce((a, b) => a + b, 0) + leaves * 24;
  const strings = [];
  let stringLength = 0;
  const stringOffsets = new Map();
  const addString = (s) => {
    if (stringOffsets.has(s)) return;
    stringOffsets.set(s, dirTotal + stringLength);
    const bytes = Buffer.concat([u16(s.length), Buffer.from(s, 'utf16le')]);
    strings.push(bytes);
    stringLength += bytes.length;
  };
  for (const t of typeKeys) {
    if (typeof t === 'string') addString(t);
    for (const [n] of types.get(t)) if (typeof n === 'string') addString(n);
  }
  const stringBlock = pad4(Buffer.concat(strings));
  const dataEntriesAt = dirTotal + stringBlock.length;
  const dataAt = dataEntriesAt + 16 * leaves;
  const level1 = [header(typeKeys.filter(t => typeof t === 'string').length, typeKeys.filter(t => typeof t !== 'string').length)];
  const level2 = [];
  const level3 = [];
  const dataEntries = [];
  const blobs = [];
  let level2Length = 0;
  let level3Length = 0;
  let blobLength = 0;
  let leaf = 0;
  const level2Base = level1Size;
  const level3Base = level1Size + level2Sizes.reduce((a, b) => a + b, 0);
  for (const t of typeKeys) {
    level1.push(u32(typeof t === 'string' ? (0x80000000 | stringOffsets.get(t)) : t), u32(0x80000000 | (level2Base + level2Length)));
    const items = [...types.get(t)].sort((a, b) => order(a[0], b[0]));
    const l2 = [header(items.filter(([n]) => typeof n === 'string').length, items.filter(([n]) => typeof n !== 'string').length)];
    for (const [n, data] of items) {
      l2.push(u32(typeof n === 'string' ? (0x80000000 | stringOffsets.get(n)) : n), u32(0x80000000 | (level3Base + level3Length)));
      const entry = Buffer.concat([header(0, 1), u32(1033), u32(dataEntriesAt + 16 * leaf)]);
      level3.push(entry);
      level3Length += entry.length;
      dataEntries.push(Buffer.concat([u32(rva + dataAt + blobLength), u32(data.length), u32(0), u32(0)]));
      const blob = pad4(data);
      blobs.push(blob);
      blobLength += blob.length;
      leaf++;
    }
    const l2Buffer = Buffer.concat(l2);
    level2.push(l2Buffer);
    level2Length += l2Buffer.length;
  }
  return Buffer.concat([...level1, ...level2, ...level3, stringBlock, ...dataEntries, ...blobs]);
}

/**
 * @param {{ payload?: Buffer, resources?: Array, dllCharacteristics?: number, signature?: Buffer }} options
 *   dllCharacteristics: 0x8160 = high-entropy VA, ASLR, DEP, terminal-server aware; add 0x4000 for CFG
 */
export function buildPe({ payload = Buffer.from('payload'), resources = [], dllCharacteristics = 0x8160, signature } = {}) {
  const fileAlign = 0x200;
  const sectionAlign = 0x1000;
  const headersSize = 0x400;
  const dataRva = 0x1000;
  const dataRaw = align(payload.length, fileAlign);
  const rsrcRva = align(dataRva + payload.length, sectionAlign);
  const rsrc = resources.length > 0 ? buildRsrc(resources, rsrcRva) : Buffer.alloc(0);
  const rsrcRaw = rsrc.length ? align(rsrc.length, fileAlign) : 0;
  const sections = rsrc.length ? 2 : 1;
  const dos = Buffer.alloc(64);
  dos.write('MZ', 0, 'latin1');
  dos.writeUInt32LE(0x40, 0x3c);
  const coff = Buffer.concat([u16(0x8664), u16(sections), u32(0x5f000000), u32(0), u32(0), u16(240), u16(0x22)]);
  const opt = Buffer.alloc(240);
  opt.writeUInt16LE(0x20b, 0);
  opt.writeUInt32LE(dataRva, 16);
  opt.writeBigUInt64LE(0x140000000n, 24);
  opt.writeUInt32LE(sectionAlign, 32);
  opt.writeUInt32LE(fileAlign, 36);
  opt.writeUInt32LE(align(rsrcRva + Math.max(rsrc.length, 1), sectionAlign), 56);
  opt.writeUInt32LE(headersSize, 60);
  opt.writeUInt16LE(2, 68);
  opt.writeUInt16LE(dllCharacteristics, 70);
  opt.writeUInt32LE(16, 108);
  if (rsrc.length) {
    opt.writeUInt32LE(rsrcRva, 112 + 16);
    opt.writeUInt32LE(rsrc.length, 112 + 20);
  }
  const section = (name, vsize, vaddr, rawSize, rawPtr, flags) => {
    const b = Buffer.alloc(40);
    b.write(name, 0, 'latin1');
    b.writeUInt32LE(vsize, 8);
    b.writeUInt32LE(vaddr, 12);
    b.writeUInt32LE(rawSize, 16);
    b.writeUInt32LE(rawPtr, 20);
    b.writeUInt32LE(flags, 36);
    return b;
  };
  const table = [section('.data', payload.length, dataRva, dataRaw, headersSize, 0xc0000040)];
  if (rsrc.length) table.push(section('.rsrc', rsrc.length, rsrcRva, rsrcRaw, headersSize + dataRaw, 0x40000040));
  let head = Buffer.concat([dos, Buffer.from('PE\0\0', 'latin1'), coff, opt, ...table]);
  head = Buffer.concat([head, Buffer.alloc(headersSize - head.length)]);
  const body = Buffer.concat([payload, Buffer.alloc(dataRaw - payload.length), rsrc, Buffer.alloc(rsrcRaw - rsrc.length)]);
  let pe = Buffer.concat([head, body]);
  if (signature) {
    // WIN_CERTIFICATE: length, revision 0x0200, type 2 (PKCS#7 SignedData), padded to 8 bytes
    const certificate = Buffer.concat([u32(0), u16(0x200), u16(2), signature]);
    const padded = Buffer.concat([certificate, Buffer.alloc(align(certificate.length, 8) - certificate.length)]);
    padded.writeUInt32LE(padded.length, 0);
    const offset = pe.length;
    pe = Buffer.concat([pe, padded]);
    pe.writeUInt32LE(offset, 0x40 + 4 + 20 + 112 + 32);
    pe.writeUInt32LE(padded.length, 0x40 + 4 + 20 + 112 + 36);
  }
  return pe;
}

/** The fuse wire as Electron writes it: sentinel, version 1, count, one byte per fuse ('0' off, '1' on). */
export function fuseWire(states) {
  return Buffer.concat([Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'latin1'), Buffer.from([1, states.length]), Buffer.from(states, 'latin1')]);
}
