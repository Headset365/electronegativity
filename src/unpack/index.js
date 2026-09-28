// Turns an installer or package into an app folder to scan: electron-builder NSIS installers and portable executables
// (their embedded app-*.7z), Squirrel.Windows Setup.exe (the .nupkg inside), .7z, .zip and .nupkg packages. NSIS web
// installers download the app at install time: they are recognized and reported, with the package URL. Everything is
// read in JavaScript, on any host. A port of Electron-Dynamic's loader.py.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { isPe, parsePe } from '../binary/pe.js';
import { SevenZipArchive, SIGNATURE as SEVEN_ZIP, findEmbedded } from './sevenzip.js';
import { parseNsis, findFirstHeader, registryClasses, packageUrls } from './nsis.js';
import { isZip, extractZip } from './zip.js';

const FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'latin1');
const HELPERS = new Set(['uninstall', 'update', 'squirrel', 'elevate', 'crashpad_handler', 'notification_helper', 'createdump', '7za', '7z']);
const LINUX_HELPERS = new Set(['chrome-sandbox', 'chrome_crashpad_handler', 'crashpad_handler', 'chrome_sandbox']);

export class UnpackError extends Error {}

const read = (file) => {
  try {
    return fs.readFileSync(file);
  } catch {
    return undefined;
  }
};
const looksElectron = (file) => {
  const data = read(file);
  return !!data && (data.includes(FUSE_SENTINEL) || data.includes(Buffer.from('Electron/')));
};

/** The app's main executable in an installed folder: a Windows .exe, or an extensionless ELF (Linux builds). */
export function findMainExecutable(root) {
  let names;
  try {
    names = fs.readdirSync(root);
  } catch {
    return undefined;
  }
  const files = names.map(name => path.join(root, name)).filter(file => {
    try {
      return fs.statSync(file).isFile();
    } catch {
      return false;
    }
  });
  let exes = files.filter(file => /\.exe$/i.test(file));
  if (exes.length === 0) exes = files.filter(file => !path.extname(file) && !LINUX_HELPERS.has(path.basename(file)) && (read(file) || Buffer.alloc(0)).subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])));
  const candidates = exes.filter(file => {
    const stem = path.basename(file).replace(/\.exe$/i, '').toLowerCase();
    return !HELPERS.has(stem.split(' ')[0]) && !stem.startsWith('uninstall');
  }).sort((a, b) => fs.statSync(b).size - fs.statSync(a).size);
  return candidates.find(looksElectron) || candidates[0];
}

// the folder holding resources/app.asar (or resources/app) inside what was extracted
function layoutOf(root) {
  const resources = fs.existsSync(path.join(root, 'resources')) ? path.join(root, 'resources') : root;
  const archive = path.join(resources, 'app.asar');
  const folder = path.join(resources, 'app');
  const code = fs.existsSync(archive) ? archive : fs.existsSync(folder) ? folder : undefined;
  return { root, code, mainExe: findMainExecutable(root) };
}

function sha256(file) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.alloc(1 << 20);
    for (let n; (n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0;) hash.update(buffer.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

/** Whether this file is something unpackTarget handles (rather than an app folder, app.asar or an app's own executable). */
export function isPackage(file) {
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    return false;
  }
  if (!stat.isFile() || /\.asar$/i.test(file)) return false;
  const fd = fs.openSync(file, 'r');
  const head = Buffer.alloc(8);
  try {
    fs.readSync(fd, head, 0, 8, 0);
  } finally {
    fs.closeSync(fd);
  }
  if (head.subarray(0, 6).equals(SEVEN_ZIP) || head.readUInt32LE(0) === 0x04034b50) return true;
  if (head[0] !== 0x4d || head[1] !== 0x5a) return false;
  const data = read(file);
  return findFirstHeader(data) >= 0 || squirrelZips(data).length > 0;
}

function squirrelZips(data) {
  if (!isPe(data)) return [];
  let info;
  try {
    info = parsePe(data);
  } catch {
    return [];
  }
  return info.resources.map(r => data.subarray(r.offset, r.offset + r.size)).filter(blob => blob.length > 64 * 1024 && isZip(blob));
}

function extract7z(source, dest, base = 0) {
  const archive = Buffer.isBuffer(source) ? new SevenZipArchive(source, base) : SevenZipArchive.open(source, base);
  archive.extractAll(dest);
  return archive;
}

/**
 * Unpacks `target` into a temporary folder. @returns {{ kind, root, code, mainExe, installer, warnings, workDir, cleanup() }}
 *   code: the app's resources/app.asar (or resources/app) to scan; installer: what the package said about itself
 * @throws UnpackError for web installers, unsupported or damaged packages
 */
export function unpackTarget(target, { workDir } = {}) {
  const file = path.resolve(target);
  const work = workDir || fs.mkdtempSync(path.join(os.tmpdir(), 'electronegativity-unpack-'));
  const result = { target: file, kind: 'unknown', warnings: [], workDir: work, installer: { file, size: fs.statSync(file).size, sha256: sha256(file) },
    cleanup: () => { if (!workDir) fs.rmSync(work, { recursive: true, force: true }); } };
  const data = read(file);
  const finish = (root, kind) => {
    Object.assign(result, layoutOf(root), { kind });
    if (!result.code) result.warnings.push('no resources/app.asar or resources/app found in the package: is it an Electron app?');
    return result;
  };
  try {
    if (data.subarray(0, 6).equals(SEVEN_ZIP)) {
      const dest = path.join(work, 'app');
      const archive = extract7z(data, dest);
      result.installer.sevenZip = { methods: archive.methods() };
      return finish(dest, '7z-package');
    }
    if (isZip(data)) {
      const dest = path.join(work, 'app');
      extractZip(data, dest);
      const lib = path.join(dest, 'lib');
      const frameworks = fs.existsSync(lib) ? fs.readdirSync(lib).map(n => path.join(lib, n)).filter(p => fs.statSync(p).isDirectory()) : [];
      const inner = fs.readdirSync(dest).map(n => path.join(dest, n)).filter(p => fs.statSync(p).isDirectory());
      const root = frameworks[0] || (inner.length === 1 && !fs.existsSync(path.join(dest, 'resources')) ? inner[0] : dest);
      return finish(root, /\.nupkg$/i.test(file) ? 'nupkg' : 'zip-package');
    }
    if (!isPe(data)) throw new UnpackError('unrecognized package: expected an installer .exe, a .7z, .zip or .nupkg');
    const pe = parsePe(data);
    result.installer.pe = { machine: pe.machine, signed: pe.signed, versionInfo: pe.versionInfo };
    if (findFirstHeader(data) >= 0) return unpackNsis(result, data, work, finish);
    const zips = squirrelZips(data);
    if (zips.length > 0) {
      const dest = path.join(work, 'squirrel');
      extractZip(zips.sort((a, b) => b.length - a.length)[0], dest);
      const nupkgs = fs.readdirSync(dest, { recursive: true }).filter(n => /\.nupkg$/i.test(n)).map(n => path.join(dest, n))
        .sort((a, b) => fs.statSync(b).size - fs.statSync(a).size);
      let libRoot = dest;
      if (nupkgs.length > 0) {
        libRoot = path.join(work, 'nupkg');
        extractZip(fs.readFileSync(nupkgs[0]), libRoot);
      }
      const lib = path.join(libRoot, 'lib');
      const frameworks = fs.existsSync(lib) ? fs.readdirSync(lib).map(n => path.join(lib, n)).filter(p => fs.statSync(p).isDirectory()) : [];
      result.installer.squirrel = { nupkg: nupkgs[0] ? path.basename(nupkgs[0]) : undefined };
      return finish(frameworks[0] || libRoot, 'squirrel-installer');
    }
    throw new UnpackError('unrecognized Windows executable: not an NSIS or Squirrel installer');
  } catch (error) {
    result.cleanup();
    throw error instanceof UnpackError ? error : new UnpackError(`${path.basename(file)}: ${error.message}`);
  }
}

function unpackNsis(result, data, work, finish) {
  const info = parseNsis(data);
  const classes = registryClasses(info.strings);
  const urls = packageUrls(info.strings);
  result.installer.nsis = { compression: info.compression, solid: info.solid, payloads: info.payloads.length, protocols: classes.protocols,
    extensions: classes.extensions, urls: urls.slice(0, 50), portable: info.strings.some(s => s.includes('PORTABLE_EXECUTABLE')) };
  result.warnings.push(...info.warnings);
  if (info.payloads.length === 0) {
    // last resort: a CRC-valid 7z header anywhere in the file
    const hit = findEmbedded(data)[0];
    if (hit !== undefined) info.payloads.push({ kind: '7z', offset: hit });
  }
  if (info.payloads.length === 0) {
    const packages = urls.filter(u => /\.nsis\.7z$|\.7z$/i.test(u));
    if (packages.length > 0 || info.strings.some(s => /nsis-web|app-64\.7z/i.test(s))) {
      result.kind = 'nsis-web-installer';
      result.installer.nsis.packageUrls = packages;
      throw new UnpackError(`NSIS web installer: the app package is downloaded at install time (${packages.join(', ') || 'URL not found'}). Scan the installed app folder or the downloaded .nsis.7z instead.`);
    }
    throw new UnpackError('NSIS installer without an embedded 7z app package (not built by electron-builder?)');
  }
  // multi-architecture installers carry one package per architecture: prefer x64
  const arches = [];
  let chosen;
  let chosenArch;
  info.payloads.forEach((payload, i) => {
    if (chosenArch === 'x64') return;
    const dest = path.join(work, i === 0 ? 'app' : `app-${i}`);
    if (payload.kind === '7z') extract7z(data, dest, payload.offset);
    else extract7z(payload.data, dest);
    const exe = findMainExecutable(dest);
    let arch = 'unknown';
    try {
      if (exe) arch = parsePe(fs.readFileSync(exe), { resources: false }).machine;
    } catch {
      // not a PE
    }
    arches.push(arch);
    if (!chosen || arch === 'x64') {
      if (chosen) fs.rmSync(chosen, { recursive: true, force: true });
      chosen = dest;
      chosenArch = arch;
    } else fs.rmSync(dest, { recursive: true, force: true });
  });
  result.installer.nsis.arches = arches;
  if (info.payloads.length > 1) result.warnings.push(`the installer carries ${info.payloads.length} app packages (one per architecture); the ${chosenArch} one was scanned`);
  return finish(chosen, result.installer.nsis.portable ? 'nsis-portable' : 'nsis-installer');
}
