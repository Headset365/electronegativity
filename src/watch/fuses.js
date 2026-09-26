// Reads the Electron "fuse wire" embedded in a packaged binary. The static FUSES_* checks read @electron/fuses calls
// and packager configuration; this reads the states actually written into the shipped executable, so changes made by
// the build pipeline (and not by code the scan can see) are caught. Format written by @electron/fuses:
//   <sentinel><schema version byte><fuse count byte><one state byte per fuse>
// each state byte is '0' (disabled), '1' (enabled), 'r' (removed) or 'i' (inherit / left at Electron's default).
import fs from 'node:fs';
import path from 'node:path';
import { FUSES, evaluateFuses } from '../finder/checks/fuses.js';
import { severity, confidence } from '../finder/attributes.js';

const SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
const DOCS = 'https://www.electronjs.org/docs/latest/tutorial/fuses';
// Position of each fuse on the wire (the FuseV1Options enum order). Index 6 (V8 snapshot) is not a security fuse.
const FUSE_ORDER = ['RunAsNode', 'EnableCookieEncryption', 'EnableNodeOptionsEnvironmentVariable', 'EnableNodeCliInspectArguments',
  'EnableEmbeddedAsarIntegrityValidation', 'OnlyLoadAppFromAsar', 'LoadBrowserProcessSpecificV8Snapshot', 'GrantFileProtocolExtraPrivileges'];
const ENABLE = '1'.charCodeAt(0);
const DISABLE = '0'.charCodeAt(0);

/**
 * Scans a binary for the fuse sentinel and reads the wire that follows it.
 * @returns {{ version:number, config:Object, states:Object }} or undefined when there is no fuse wire.
 */
export function readFuseWire(binaryPath) {
  let fd;
  try {
    fd = fs.openSync(binaryPath, 'r');
  } catch {
    return undefined;
  }
  try {
    const CHUNK = 1 << 20;
    const TAIL = SENTINEL.length + 2 + FUSE_ORDER.length + 8; // enough to hold a sentinel + full wire spanning a boundary
    const buffer = Buffer.alloc(CHUNK);
    let carry = Buffer.alloc(0);
    let position = 0;
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, CHUNK, position);
      if (bytes <= 0) break;
      const hay = carry.length ? Buffer.concat([carry, buffer.subarray(0, bytes)]) : buffer.subarray(0, bytes);
      const index = hay.indexOf(SENTINEL);
      if (index !== -1) {
        const start = index + SENTINEL.length;
        // need the version byte, the count byte and every state byte present in this window
        if (start + 2 <= hay.length) {
          const count = hay[start + 1];
          if (start + 2 + count <= hay.length) return parseWire(hay, start, count);
        }
      }
      carry = Buffer.from(hay.subarray(Math.max(0, hay.length - TAIL)));
      position += bytes;
      if (bytes < CHUNK) break;
    }
    return undefined;
  } finally {
    fs.closeSync(fd);
  }
}

function parseWire(hay, start, count) {
  const version = hay[start];
  const states = {};
  const config = {};
  for (let i = 0; i < count; i++) {
    const name = FUSE_ORDER[i] || `fuse${i}`;
    const byte = hay[start + 2 + i];
    const state = byte === ENABLE ? 'enabled' : byte === DISABLE ? 'disabled' : String.fromCharCode(byte) === 'r' ? 'removed' : 'inherit';
    states[name] = state;
    // only fuses actually pinned on the wire feed the evaluation; inherit/removed fall back to the Electron default
    if (state === 'enabled') config[name] = true;
    else if (state === 'disabled') config[name] = false;
  }
  return { version, config, states };
}

const runtimeIssue = (id, file, sev, conf, description, properties) => ({
  file: file || 'runtime', sample: '', location: { line: 0, column: 0 }, id, description, properties, shortenedURL: DOCS,
  severity: sev, confidence: conf, manualReview: false,
  visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime'
});

/**
 * The file that holds the fuse wire of a packaged app. On macOS it is the Electron Framework inside the bundle, not the
 * app's executable in Contents/MacOS (the same file @electron/fuses reads).
 */
export function fuseBinaryFor(executable) {
  const resolved = path.resolve(executable);
  const macos = resolved.match(/^(.*\.app)[\\/]Contents[\\/]MacOS[\\/][^\\/]+$/);
  if (macos) return path.join(macos[1], 'Contents', 'Frameworks', 'Electron Framework.framework', 'Electron Framework');
  return resolved;
}

/**
 * The executable of a packaged app, from its scanned resources (resources/app.asar or resources/app): the file holding
 * the fuse wire, or undefined when the input isn't inside a packaged app.
 */
export function packagedBinaryFor(input) {
  const resolved = path.resolve(input);
  const mac = resolved.match(/^(.*\.app)[\\/]Contents[\\/]Resources[\\/]app(\.asar)?$/);
  if (mac) {
    const framework = path.join(mac[1], 'Contents', 'Frameworks', 'Electron Framework.framework', 'Electron Framework');
    return fs.existsSync(framework) ? framework : undefined;
  }
  if (!/[\\/]resources[\\/]app(\.asar)?$/i.test(resolved)) return undefined;
  const appDir = path.dirname(path.dirname(resolved));
  let entries;
  try {
    entries = fs.readdirSync(appDir, { withFileTypes: true });
  } catch {
    return undefined;
  }
  // the app's executable: an .exe on Windows, an executable file without extension elsewhere; helpers are skipped
  const HELPERS = /^(chrome-sandbox|chrome_crashpad_handler|crashpad_handler|uninstall.*|squirrel\.exe|update\.exe|elevate\.exe)$/i;
  const candidates = entries.filter(e => e.isFile() && !HELPERS.test(e.name)).map(e => path.join(appDir, e.name)).filter(file => {
    if (/\.exe$/i.test(file)) return true;
    if (path.extname(file)) return false;
    try {
      return (fs.statSync(file).mode & 0o111) !== 0;
    } catch {
      return false;
    }
  });
  return candidates.find(file => readFuseWire(file));
}

/**
 * Reads the fuses from a packaged binary and turns the insecure ones into findings, in the same shape as the other
 * runtime findings. @returns {{ read:boolean, issues:Array, states?:Object }}
 */
export function analyzePackagedFuses(executable) {
  const binaryPath = fuseBinaryFor(executable);
  const wire = readFuseWire(binaryPath);
  if (!wire) return { read: false, issues: [], binary: binaryPath };
  const { insecure, unset } = evaluateFuses(wire.config);
  const issues = [];
  for (const { fuse, value } of insecure) {
    const rule = FUSES[fuse];
    issues.push(runtimeIssue('PACKAGED_FUSES', binaryPath, rule.severity, confidence.CERTAIN,
      `Fuse ${fuse} is set to the insecure value in the packaged binary (${value}): ${rule.risk}`, { fuse, value, source: 'binary' }));
  }
  for (const fuse of unset) {
    const rule = FUSES[fuse];
    issues.push(runtimeIssue('PACKAGED_FUSES', binaryPath, rule.severity, confidence.FIRM,
      `Fuse ${fuse} is left at Electron's insecure default in the packaged binary: ${rule.risk}`, { fuse, value: 'inherit', source: 'binary' }));
  }
  if (issues.length === 0)
    issues.push(runtimeIssue('PACKAGED_FUSES', binaryPath, severity.INFORMATIONAL, confidence.CERTAIN,
      'The packaged binary pins every security fuse to a safe value', { states: wire.states, source: 'binary' }));
  return { read: true, issues, states: wire.states };
}
