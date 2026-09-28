// ELF (Linux) exploit mitigations: position-independent executable (ASLR for the main binary), a non-executable
// stack (PT_GNU_STACK without PF_X) and RELRO (PT_GNU_RELRO).
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

/** { pie, nxStack, relro, is64 } or undefined when the data is not an ELF file. */
export function elfInfo(data) {
  if (data.length < 64 || data.readUInt32BE(0) !== 0x7f454c46) return undefined;
  const is64 = data[4] === 2;
  const little = data[5] === 1;
  const u16 = (at) => little ? data.readUInt16LE(at) : data.readUInt16BE(at);
  const u32 = (at) => little ? data.readUInt32LE(at) : data.readUInt32BE(at);
  const addr = (at) => is64 ? Number(little ? data.readBigUInt64LE(at) : data.readBigUInt64BE(at)) : u32(at);
  const type = u16(16);
  const phoff = addr(is64 ? 32 : 28);
  const phentsize = u16(is64 ? 54 : 42);
  const phnum = u16(is64 ? 56 : 44);
  let nxStack = false;
  let stackSeen = false;
  let relro = false;
  for (let i = 0; i < phnum; i++) {
    const at = phoff + i * phentsize;
    if (at + phentsize > data.length) break;
    const pType = u32(at);
    const pFlags = u32(is64 ? at + 4 : at + 24);
    if (pType === PT_GNU_STACK) {
      stackSeen = true;
      nxStack = !(pFlags & 1);
    }
    if (pType === PT_GNU_RELRO) relro = true;
  }
  // without PT_GNU_STACK the loader assumes an executable stack
  return { pie: type === 3, nxStack: stackSeen && nxStack, relro, is64 };
}
