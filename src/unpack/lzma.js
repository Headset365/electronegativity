// Pure JavaScript LZMA, LZMA2 and x86 BCJ decoders, for the 7z archives electron-builder puts in NSIS installers
// (Node has no LZMA). Decode-only; written from the LZMA specification (LzmaSpec) and xz's simple x86 filter.
import { MAX_STREAM, limitMessage } from './limits.js';

const kNumStates = 12;
const kMatchMinLen = 2;
const kEndPosModelIndex = 14;
const kNumFullDistances = 1 << (kEndPosModelIndex >>> 1);
const kNumAlignBits = 4;
const kNumLenToPosStates = 4;
const PROB_INIT = 1024;

export class LzmaError extends Error {}

class RangeDecoder {
  constructor(input, pos, end) {
    this.input = input;
    this.pos = pos;
    this.end = end;
    this.range = 0xffffffff;
    this.code = 0;
    if (this.byte() !== 0) throw new LzmaError('bad range coder start');
    for (let i = 0; i < 4; i++) this.code = ((this.code << 8) | this.byte()) >>> 0;
    if (this.code === this.range) throw new LzmaError('bad range coder start');
  }

  byte() {
    // past the end of the input: zeros (a truncated stream then fails its size or end-marker check)
    return this.pos < this.end ? this.input[this.pos++] : (this.pos++, 0);
  }

  normalize() {
    if (this.range < 0x1000000) {
      this.range = (this.range << 8) >>> 0;
      this.code = ((this.code << 8) | this.byte()) >>> 0;
    }
  }

  bit(probs, index) {
    const p = probs[index];
    const bound = (this.range >>> 11) * p;
    let bit;
    if (this.code < bound) {
      this.range = bound;
      probs[index] = p + ((2048 - p) >>> 5);
      bit = 0;
    } else {
      this.range -= bound;
      this.code -= bound;
      probs[index] = p - (p >>> 5);
      bit = 1;
    }
    this.normalize();
    return bit;
  }

  direct(count) {
    let result = 0;
    for (let i = 0; i < count; i++) {
      this.range = this.range >>> 1;
      let bit = 0;
      if (this.code >= this.range) {
        this.code -= this.range;
        bit = 1;
      }
      result = ((result << 1) | bit) >>> 0;
      this.normalize();
    }
    return result;
  }

  tree(probs, base, bits) {
    let m = 1;
    for (let i = 0; i < bits; i++) m = (m << 1) | this.bit(probs, base + m);
    return m - (1 << bits);
  }

  reverseTree(probs, base, bits) {
    let m = 1;
    let symbol = 0;
    for (let i = 0; i < bits; i++) {
      const bit = this.bit(probs, base + m);
      m = (m << 1) | bit;
      symbol |= bit << i;
    }
    return symbol;
  }
}

class LenDecoder {
  constructor() {
    this.choice = new Uint16Array(2);
    this.low = new Uint16Array(16 << 3);
    this.mid = new Uint16Array(16 << 3);
    this.high = new Uint16Array(256);
    this.reset();
  }

  reset() {
    for (const probs of [this.choice, this.low, this.mid, this.high]) probs.fill(PROB_INIT);
  }

  decode(rc, posState) {
    if (rc.bit(this.choice, 0) === 0) return rc.tree(this.low, posState << 3, 3);
    if (rc.bit(this.choice, 1) === 0) return 8 + rc.tree(this.mid, posState << 3, 3);
    return 16 + rc.tree(this.high, 0, 8);
  }
}

// an output buffer that grows when the unpacked size isn't known in advance
class Output {
  constructor(size, limit) {
    this.known = size !== undefined;
    // the declared size comes from the archive: it is checked before anything is allocated
    if (this.known && size > MAX_STREAM) throw new LzmaError(limitMessage('LZMA stream', size));
    this.buffer = Buffer.alloc(this.known ? size : Math.min(1 << 20, limit ?? MAX_STREAM));
    this.pos = 0;
    // where decoding stops, and (a match can run past that point) the size it may never exceed
    this.limit = this.known ? size : Math.min(limit ?? MAX_STREAM, MAX_STREAM);
    this.cap = this.known ? size : this.limit + (1 << 16);
  }

  ensure(extra) {
    const need = this.pos + extra;
    if (need <= this.buffer.length) return;
    if (this.known) throw new LzmaError('data longer than its declared size');
    if (need > this.cap) throw new LzmaError(limitMessage('LZMA stream', need));
    let length = Math.max(this.buffer.length, 1);
    while (length < need) length *= 2;
    length = Math.min(length, this.cap);
    const grown = Buffer.alloc(length);
    this.buffer.copy(grown, 0, 0, this.pos);
    this.buffer = grown;
  }

  result() {
    return this.buffer.subarray(0, this.pos);
  }
}

/** The LZMA decoder state; LZMA2 keeps it (and the dictionary, which is the output itself) across chunks. */
export class LzmaDecoder {
  constructor(output) {
    this.out = output;
    this.lenDecoder = new LenDecoder();
    this.repLenDecoder = new LenDecoder();
    this.isMatch = new Uint16Array(kNumStates << 4);
    this.isRep = new Uint16Array(kNumStates);
    this.isRepG0 = new Uint16Array(kNumStates);
    this.isRepG1 = new Uint16Array(kNumStates);
    this.isRepG2 = new Uint16Array(kNumStates);
    this.isRep0Long = new Uint16Array(kNumStates << 4);
    this.posSlot = new Uint16Array(kNumLenToPosStates << 6);
    this.posDecoders = new Uint16Array(1 + kNumFullDistances - kEndPosModelIndex);
    this.align = new Uint16Array(1 << kNumAlignBits);
    this.literal = new Uint16Array(0);
    this.dictStart = 0;
  }

  setProperties(lc, lp, pb) {
    if (lc > 8 || lp > 4 || pb > 4) throw new LzmaError('bad LZMA properties');
    this.lc = lc;
    this.lp = lp;
    this.pb = pb;
    if (this.literal.length !== 0x300 << (lc + lp)) this.literal = new Uint16Array(0x300 << (lc + lp));
  }

  /** props byte: (pb * 5 + lp) * 9 + lc */
  setPropertiesByte(byte) {
    if (byte >= 9 * 5 * 5) throw new LzmaError('bad LZMA properties');
    const lc = byte % 9;
    const rest = Math.floor(byte / 9);
    this.setProperties(lc, rest % 5, Math.floor(rest / 5));
  }

  resetState() {
    for (const probs of [this.isMatch, this.isRep, this.isRepG0, this.isRepG1, this.isRepG2, this.isRep0Long, this.posSlot, this.posDecoders, this.align, this.literal]) probs.fill(PROB_INIT);
    this.lenDecoder.reset();
    this.repLenDecoder.reset();
    this.state = 0;
    this.rep0 = this.rep1 = this.rep2 = this.rep3 = 0;
  }

  resetDictionary() {
    this.dictStart = this.out.pos;
  }

  distance(len) {
    const lenState = Math.min(len, kNumLenToPosStates - 1);
    const posSlot = this.rc.tree(this.posSlot, lenState << 6, 6);
    if (posSlot < 4) return posSlot;
    const numDirectBits = (posSlot >>> 1) - 1;
    let dist = ((2 | (posSlot & 1)) * 2 ** numDirectBits) >>> 0;
    if (posSlot < kEndPosModelIndex) return (dist + this.rc.reverseTree(this.posDecoders, dist - posSlot, numDirectBits)) >>> 0;
    dist = (dist + this.rc.direct(numDirectBits - kNumAlignBits) * 16) >>> 0;
    return (dist + this.rc.reverseTree(this.align, 0, kNumAlignBits)) >>> 0;
  }

  /**
   * Decodes from input[pos, end) until `size` more bytes are written, or (size undefined) the end marker or the end of
   * the input. Returns the input position reached.
   */
  decode(input, pos, end, size, { allowEndMarker = true } = {}) {
    const out = this.out;
    this.rc = new RangeDecoder(input, pos, end);
    const rc = this.rc;
    const stop = size === undefined ? out.limit : out.pos + size;
    if (size !== undefined) out.ensure(size);
    const pbMask = (1 << this.pb) - 1;
    const lpMask = (1 << this.lp) - 1;
    const lc = this.lc;
    while (out.pos < stop) {
      if (size === undefined) {
        if (rc.pos > end + 4) break; // ran out of input without an end marker
        out.ensure(273);
      }
      const buffer = out.buffer;
      const posState = out.pos & pbMask;
      let state = this.state;
      if (rc.bit(this.isMatch, (state << 4) + posState) === 0) {
        const prev = out.pos > this.dictStart ? buffer[out.pos - 1] : 0;
        const base = 0x300 * (((out.pos & lpMask) << lc) + (prev >>> (8 - lc)));
        let symbol = 1;
        if (state >= 7) {
          if (this.rep0 >= out.pos - this.dictStart) throw new LzmaError('distance beyond the data');
          let matchByte = buffer[out.pos - this.rep0 - 1];
          do {
            const matchBit = (matchByte >>> 7) & 1;
            matchByte <<= 1;
            const bit = rc.bit(this.literal, base + ((1 + matchBit) << 8) + symbol);
            symbol = (symbol << 1) | bit;
            if (matchBit !== bit) break;
          } while (symbol < 0x100);
        }
        while (symbol < 0x100) symbol = (symbol << 1) | rc.bit(this.literal, base + symbol);
        buffer[out.pos++] = symbol & 0xff;
        this.state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
        continue;
      }
      let len;
      if (rc.bit(this.isRep, state) !== 0) {
        if (out.pos === this.dictStart) throw new LzmaError('repeat match with an empty dictionary');
        if (rc.bit(this.isRepG0, state) === 0) {
          if (rc.bit(this.isRep0Long, (state << 4) + posState) === 0) {
            this.state = state < 7 ? 9 : 11;
            buffer[out.pos] = buffer[out.pos - this.rep0 - 1];
            out.pos++;
            continue;
          }
        } else {
          let dist;
          if (rc.bit(this.isRepG1, state) === 0) dist = this.rep1;
          else {
            if (rc.bit(this.isRepG2, state) === 0) dist = this.rep2;
            else {
              dist = this.rep3;
              this.rep3 = this.rep2;
            }
            this.rep2 = this.rep1;
          }
          this.rep1 = this.rep0;
          this.rep0 = dist;
        }
        len = this.repLenDecoder.decode(rc, posState);
        this.state = state < 7 ? 8 : 11;
      } else {
        this.rep3 = this.rep2;
        this.rep2 = this.rep1;
        this.rep1 = this.rep0;
        len = this.lenDecoder.decode(rc, posState);
        this.state = state < 7 ? 7 : 10;
        this.rep0 = this.distance(len);
        if (this.rep0 === 0xffffffff) {
          if (!allowEndMarker) throw new LzmaError('unexpected end marker');
          return rc.pos; // end marker
        }
        if (this.rep0 >= out.pos - this.dictStart) throw new LzmaError('distance beyond the data');
      }
      len += kMatchMinLen;
      if (out.pos + len > stop) {
        if (size !== undefined) throw new LzmaError('match past the declared size');
        len = stop - out.pos;
      }
      let from = out.pos - this.rep0 - 1;
      for (let i = 0; i < len; i++) buffer[out.pos++] = buffer[from++];
    }
    return rc.pos;
  }
}

/** Raw LZMA (a 7z coder): 5 property bytes (props byte, dictionary size) and the unpacked size. */
export function decodeLzma(properties, input, size) {
  if (properties.length < 5) throw new LzmaError('bad LZMA properties');
  const decoder = new LzmaDecoder(new Output(size));
  decoder.setPropertiesByte(properties[0]);
  decoder.resetState();
  decoder.decode(input, 0, input.length, size);
  return decoder.out.result();
}

/**
 * An LZMA stream as NSIS stores it: 5 property bytes then the data, with no size (it ends with an end marker or at the
 * end of the input). `limit` caps the output.
 */
export function decodeLzmaStream(input, { limit } = {}) {
  const decoder = new LzmaDecoder(new Output(undefined, limit));
  decoder.setPropertiesByte(input[0]);
  decoder.resetState();
  try {
    decoder.decode(input, 5, input.length, undefined);
  } catch (error) {
    // data past the end of the stream: keep what decoded cleanly
    if (decoder.out.pos === 0) throw error;
  }
  return decoder.out.result();
}

/** LZMA2 (a 7z coder): chunks of LZMA and stored data. */
export function decodeLzma2(input, size) {
  const out = new Output(size);
  const decoder = new LzmaDecoder(out);
  let pos = 0;
  let needProps = true;
  while (pos < input.length) {
    const control = input[pos++];
    if (control === 0) break;
    if (control === 1 || control === 2) { // stored chunk (1: dictionary reset)
      const length = input.readUInt16BE(pos) + 1;
      pos += 2;
      if (control === 1) decoder.resetDictionary();
      out.ensure(length);
      input.copy(out.buffer, out.pos, pos, pos + length);
      out.pos += length;
      pos += length;
      continue;
    }
    if (control < 0x80) throw new LzmaError('bad LZMA2 chunk');
    const unpacked = ((control & 0x1f) << 16) + input.readUInt16BE(pos) + 1;
    const packed = input.readUInt16BE(pos + 2) + 1;
    pos += 4;
    const reset = (control >>> 5) & 3;
    if (reset === 3) decoder.resetDictionary();
    if (reset >= 2) {
      decoder.setPropertiesByte(input[pos++]);
      needProps = false;
    } else if (needProps) throw new LzmaError('LZMA2 chunk without properties');
    if (reset >= 1) decoder.resetState();
    decoder.decode(input, pos, pos + packed, unpacked, { allowEndMarker: false });
    pos += packed;
  }
  if (size !== undefined && out.pos < size) throw new LzmaError(`LZMA2: short output (${out.pos} < ${size})`);
  return out.result();
}

const allowed = [true, true, true, false, true, false, false, false];
const bitNumber = [0, 1, 2, 2, 3, 3, 3, 3];
const msByte = (b) => b === 0 || b === 0xff;

/** Undoes the x86 BCJ filter in place (xz's simple x86 decoder) and returns the buffer. */
export function bcjX86Decode(buffer) {
  let prevMask = 0;
  let prevPos = -5;
  const limit = buffer.length - 5;
  let i = 0;
  while (i <= limit) {
    let b = buffer[i];
    if (b !== 0xe8 && b !== 0xe9) {
      i++;
      continue;
    }
    const offset = i - prevPos;
    prevPos = i;
    if (offset > 5) prevMask = 0;
    else for (let k = 0; k < offset; k++) prevMask = (prevMask & 0x77) << 1;
    b = buffer[i + 4];
    if (msByte(b) && allowed[(prevMask >>> 1) & 7] && (prevMask >>> 1) < 0x10) {
      let src = ((b << 24) | (buffer[i + 3] << 16) | (buffer[i + 2] << 8) | buffer[i + 1]) >>> 0;
      let dest;
      for (;;) {
        dest = (src - (i + 5)) >>> 0;
        if (prevMask === 0) break;
        const index = bitNumber[prevMask >>> 1];
        b = (dest >>> (24 - index * 8)) & 0xff;
        if (!msByte(b)) break;
        src = (dest ^ ((2 ** (32 - index * 8)) - 1)) >>> 0;
      }
      buffer[i + 4] = ((dest >>> 24) & 1) ? 0xff : 0;
      buffer[i + 3] = (dest >>> 16) & 0xff;
      buffer[i + 2] = (dest >>> 8) & 0xff;
      buffer[i + 1] = dest & 0xff;
      i += 5;
      prevMask = 0;
    } else {
      i++;
      prevMask |= 1;
      if (msByte(b)) prevMask |= 0x10;
    }
  }
  return buffer;
}
