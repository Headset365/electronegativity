// A minimal, read-only PE (Windows executable) reader: machine, DllCharacteristics (ASLR, DEP, CFG), sections, the
// Authenticode certificate table and resources (the INTEGRITY/ELECTRONASAR entry electron-builder and
// @electron/packager embed, and VS_VERSIONINFO). It only reads bytes, so it works on any host.

const MACHINES = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'arm64', 0x1c4: 'arm' };
export const RT_VERSION = 16;

export function isPe(data) {
  if (data.length < 0x40 || data[0] !== 0x4d || data[1] !== 0x5a) return false;
  const peOffset = data.readUInt32LE(0x3c);
  return peOffset + 4 <= data.length && data.readUInt32LE(peOffset) === 0x4550;
}

/**
 * @returns {{ machine, is64, isDll, dllCharacteristics, aslr, highEntropyVa, dep, cfg, sections, securityOffset,
 *   securitySize, signed, resources: [{ type, name, offset, size }], versionInfo }}
 */
export function parsePe(data, { resources: wantResources = true } = {}) {
  if (!isPe(data)) throw new Error('not a PE file');
  const coff = data.readUInt32LE(0x3c) + 4;
  const machine = data.readUInt16LE(coff);
  const sectionCount = data.readUInt16LE(coff + 2);
  const optionalSize = data.readUInt16LE(coff + 16);
  const characteristics = data.readUInt16LE(coff + 18);
  const optional = coff + 20;
  const is64 = data.readUInt16LE(optional) === 0x20b;
  const dllCharacteristics = data.readUInt16LE(optional + 70);
  const dirCount = data.readUInt32LE(optional + (is64 ? 108 : 92));
  const dirsAt = optional + (is64 ? 112 : 96);
  const dirs = [];
  for (let i = 0; i < Math.min(dirCount, 16); i++) dirs.push([data.readUInt32LE(dirsAt + i * 8), data.readUInt32LE(dirsAt + i * 8 + 4)]);
  const sections = [];
  const sectionsAt = optional + optionalSize;
  for (let i = 0; i < sectionCount; i++) {
    const at = sectionsAt + i * 40;
    if (at + 40 > data.length) break;
    sections.push({ name: data.subarray(at, at + 8).toString('latin1').replace(/\0+$/, ''), virtualSize: data.readUInt32LE(at + 8),
      virtualAddress: data.readUInt32LE(at + 12), rawSize: data.readUInt32LE(at + 16), rawPointer: data.readUInt32LE(at + 20) });
  }
  const info = {
    machine: MACHINES[machine] || `0x${machine.toString(16)}`, is64, isDll: !!(characteristics & 0x2000), dllCharacteristics,
    aslr: !!(dllCharacteristics & 0x40), highEntropyVa: !!(dllCharacteristics & 0x20), dep: !!(dllCharacteristics & 0x100), cfg: !!(dllCharacteristics & 0x4000),
    sections, securityOffset: 0, securitySize: 0, resources: [], versionInfo: {},
  };
  // the certificate table's "RVA" is a file offset
  if (dirs.length > 4 && dirs[4][0] && dirs[4][1] && dirs[4][0] + dirs[4][1] <= data.length) [info.securityOffset, info.securitySize] = dirs[4];
  info.signed = info.securitySize > 0;
  if (wantResources && dirs.length > 2 && dirs[2][0]) {
    try {
      parseResources(data, info, dirs[2][0]);
    } catch {
      // a damaged resource tree
    }
    const version = findResources(info, RT_VERSION)[0];
    if (version) {
      try {
        parseVersion(data.subarray(version.offset, version.offset + version.size), info);
      } catch {
        // a damaged version block
      }
    }
  }
  return info;
}

export function rvaToOffset(info, rva) {
  for (const s of info.sections) if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) return rva - s.virtualAddress + s.rawPointer;
  return undefined;
}

const same = (a, b) => typeof a === 'string' && typeof b === 'string' ? a.toUpperCase() === b.toUpperCase() : a === b;
export const findResources = (info, type, name) => info.resources.filter(r => same(r.type, type) && (name === undefined || same(r.name, name)));

function parseResources(data, info, rsrcRva) {
  const base = rvaToOffset(info, rsrcRva);
  if (base === undefined) return;
  const readName = (offset) => {
    const length = data.readUInt16LE(base + offset);
    return data.subarray(base + offset + 2, base + offset + 2 + length * 2).toString('utf16le');
  };
  const walk = (dirOffset, level, path) => {
    if (level > 3 || info.resources.length > 20000) return;
    const named = data.readUInt16LE(base + dirOffset + 12);
    const ids = data.readUInt16LE(base + dirOffset + 14);
    for (let i = 0; i < named + ids; i++) {
      const entry = base + dirOffset + 16 + i * 8;
      const nameField = data.readUInt32LE(entry);
      const offsetField = data.readUInt32LE(entry + 4);
      const ident = nameField & 0x80000000 ? readName(nameField & 0x7fffffff) : nameField;
      if (offsetField & 0x80000000) walk(offsetField & 0x7fffffff, level + 1, [...path, ident]);
      else {
        const rva = data.readUInt32LE(base + offsetField);
        const size = data.readUInt32LE(base + offsetField + 4);
        const offset = rvaToOffset(info, rva);
        if (offset === undefined) continue;
        const [type, name] = [...path, ident];
        info.resources.push({ type, name, offset, size });
      }
    }
  };
  walk(0, 0, []);
}

// VS_VERSIONINFO: StringFileInfo key/values (ProductName, CompanyName, FileVersion, ...)
function parseVersion(blob, info) {
  const align = (x) => (x + 3) & ~3;
  const block = (at) => {
    const length = blob.readUInt16LE(at);
    const valueLength = blob.readUInt16LE(at + 2);
    let end = at + 6;
    while (end + 1 < blob.length && (blob[end] || blob[end + 1])) end += 2;
    return { length, valueLength, key: blob.subarray(at + 6, end).toString('utf16le'), value: align(end + 2) };
  };
  const root = block(0);
  if (root.key !== 'VS_VERSION_INFO') return;
  let child = align(root.value + root.valueLength);
  const end = Math.min(root.length, blob.length);
  while (child < end) {
    const c = block(child);
    if (c.length === 0) break;
    if (c.key === 'StringFileInfo') {
      for (let t = c.value; t < child + c.length;) {
        const table = block(t);
        if (table.length === 0) break;
        for (let s = table.value; s < t + table.length;) {
          const entry = block(s);
          if (entry.length === 0) break;
          const value = blob.subarray(entry.value, entry.value + entry.valueLength * 2).toString('utf16le').split('\0')[0];
          if (!(entry.key in info.versionInfo)) info.versionInfo[entry.key] = value;
          s = align(s + entry.length);
        }
        t = align(t + table.length);
      }
    }
    child = align(child + c.length);
  }
}

/** The PKCS#7 SignedData of the Authenticode signature, or undefined. */
export function certificateBlob(data, info) {
  if (!info.signed) return undefined;
  const length = data.readUInt32LE(info.securityOffset);
  const type = data.readUInt16LE(info.securityOffset + 6);
  if (type !== 0x0002) return undefined; // WIN_CERT_TYPE_PKCS_SIGNED_DATA
  return data.subarray(info.securityOffset + 8, info.securityOffset + Math.min(length, info.securitySize));
}
