// Mach-O (macOS) headers: whether the binary carries a code signature (LC_CODE_SIGNATURE) and is position-independent.
// Universal ("fat") binaries are read through their first architecture.
const LC_CODE_SIGNATURE = 0x1d;
const MH_PIE = 0x200000;

/** { codeSignature, pie, is64 } or undefined when the data is not a Mach-O file. */
export function machoInfo(data) {
  if (data.length < 32) return undefined;
  let base = 0;
  if (data.readUInt32BE(0) === 0xcafebabe || data.readUInt32BE(0) === 0xcafebabf) {
    const is64Fat = data.readUInt32BE(0) === 0xcafebabf;
    if (data.readUInt32BE(4) === 0) return undefined;
    base = is64Fat ? Number(data.readBigUInt64BE(8 + 8)) : data.readUInt32BE(8 + 8); // first fat_arch's offset
    if (base + 32 > data.length) return undefined;
  }
  const magic = data.readUInt32LE(base);
  const is64 = magic === 0xfeedfacf;
  if (!is64 && magic !== 0xfeedface) return undefined;
  const commands = data.readUInt32LE(base + 16);
  const flags = data.readUInt32LE(base + 24);
  let at = base + (is64 ? 32 : 28);
  let codeSignature = false;
  for (let i = 0; i < commands && at + 8 <= data.length; i++) {
    const cmd = data.readUInt32LE(at);
    const size = data.readUInt32LE(at + 4);
    if (cmd === LC_CODE_SIGNATURE) codeSignature = true;
    if (size < 8) break;
    at += size;
  }
  return { codeSignature, pie: !!(flags & MH_PIE), is64 };
}
