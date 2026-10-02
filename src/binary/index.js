// Checks on a packaged app's executable: does app.asar still match the integrity hash embedded at build time, is the
// executable code-signed (and, on Windows and macOS, does the OS accept the signature), and was it built with the usual
// exploit mitigations.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as asar from '@electron/asar';
import { severity, confidence } from '../finder/attributes.js';
import { packagedBinaryFor, readFuseWire, fuseBinaryFor } from '../watch/fuses.js';
import { parsePe, findResources, isPe } from './pe.js';
import { machoInfo } from './macho.js';
import { elfInfo } from './elf.js';
import { verifySignature, inconclusiveSignature, VALID, NOT_SIGNED } from './signature.js';

const INTEGRITY_DOCS = 'https://www.electronjs.org/docs/latest/tutorial/asar-integrity';
const SIGNING_DOCS = 'https://www.electronjs.org/docs/latest/tutorial/code-signing';

const issue = (id, file, sev, conf, description, properties, reference) => ({
  file, sample: '', location: { line: 0, column: 0 }, id, description, properties, shortenedURL: reference, severity: sev, confidence: conf,
  manualReview: false, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime',
});

/** The app's executable for a scanned app.asar / resources/app: the .exe or ELF next to resources, or Contents/MacOS/<name>. */
export function appExecutableFor(input) {
  const resolved = path.resolve(input);
  const mac = resolved.match(/^(.*\.app)[\\/]Contents[\\/]Resources[\\/]app(\.asar)?$/);
  if (mac) {
    const dir = path.join(mac[1], 'Contents', 'MacOS');
    try {
      const name = fs.readdirSync(dir).find(f => fs.statSync(path.join(dir, f)).isFile());
      return name ? path.join(dir, name) : undefined;
    } catch {
      return undefined;
    }
  }
  return packagedBinaryFor(resolved);
}

/** SHA-256 of app.asar's header, which is what Electron's integrity check compares. */
export function asarHeaderHash(archive) {
  const { headerString } = asar.getRawHeader(archive);
  return crypto.createHash('sha256').update(headerString).digest('hex');
}

/** The integrity hash embedded for app.asar: { alg, value, source } or undefined. */
export function embeddedIntegrity(executable) {
  const mac = executable.match(/^(.*\.app)[\\/]Contents[\\/]MacOS[\\/][^\\/]+$/);
  if (mac) {
    let plist;
    try {
      plist = fs.readFileSync(path.join(mac[1], 'Contents', 'Info.plist'), 'utf8');
    } catch {
      return undefined;
    }
    const block = plist.match(/<key>ElectronAsarIntegrity<\/key>\s*<dict>([\s\S]*?)<\/dict>\s*<\/dict>/);
    const entry = block && block[1].match(/<key>Resources\/app\.asar<\/key>\s*<dict>([\s\S]*)/);
    if (!entry) return undefined;
    const field = (name) => (entry[1].match(new RegExp(`<key>${name}</key>\\s*<string>([^<]*)</string>`)) || [])[1];
    return { alg: (field('algorithm') || 'SHA256').toUpperCase(), value: (field('hash') || '').toLowerCase(), source: 'Info.plist ElectronAsarIntegrity' };
  }
  let data;
  try {
    data = fs.readFileSync(executable);
  } catch {
    return undefined;
  }
  if (!isPe(data)) return undefined;
  const info = parsePe(data);
  const resource = findResources(info, 'INTEGRITY', 'ELECTRONASAR')[0];
  if (!resource) return undefined;
  try {
    const entries = JSON.parse(data.subarray(resource.offset, resource.offset + resource.size).toString('utf8'));
    const entry = (Array.isArray(entries) ? entries : []).find(e => e && /app\.asar$/i.test(String(e.file || '').replace(/\\/g, '/')));
    return entry ? { alg: String(entry.alg || 'SHA256').toUpperCase(), value: String(entry.value || '').toLowerCase(), source: 'INTEGRITY/ELECTRONASAR resource' } : undefined;
  } catch {
    return undefined;
  }
}

/** Exploit mitigations the executable lacks: { format, missing: [...] } */
export function mitigations(executable) {
  let data;
  try {
    data = fs.readFileSync(executable);
  } catch {
    return undefined;
  }
  if (isPe(data)) {
    const info = parsePe(data, { resources: false });
    return { format: 'PE', missing: [['ASLR', info.aslr], ['DEP', info.dep], ['CFG', info.cfg], ...(info.is64 ? [['high-entropy ASLR', info.highEntropyVa]] : [])].filter(([, on]) => !on).map(([name]) => name) };
  }
  const elf = elfInfo(data);
  if (elf) return { format: 'ELF', missing: [['PIE', elf.pie], ['non-executable stack', elf.nxStack], ['RELRO', elf.relro]].filter(([, on]) => !on).map(([name]) => name) };
  const macho = machoInfo(data);
  if (macho) return { format: 'Mach-O', missing: macho.pie ? [] : ['PIE'] };
  return undefined;
}

/**
 * The binary checks for a scanned app (its app.asar or resources/app), or for an executable given directly.
 * @returns {{ issues: Array, summary: Object }} summary: { executable, integrity, signing, mitigations }
 */
export function analyzeBinary(input, { executable = appExecutableFor(input), platform = process.platform, run } = {}) {
  const issues = [];
  const summary = { executable };
  if (!executable) return { issues, summary };
  const name = path.basename(executable);
  const archive = /\.asar$/i.test(input) ? path.resolve(input) : undefined;

  // --- asar integrity ---
  const wire = readFuseWire(fuseBinaryFor(executable));
  const fuse = wire && wire.states ? wire.states.EnableEmbeddedAsarIntegrityValidation : undefined;
  const expected = embeddedIntegrity(executable);
  if (archive && expected && expected.alg === 'SHA256' && expected.value) {
    let actual;
    try {
      actual = asarHeaderHash(archive);
    } catch {
      actual = undefined;
    }
    const enforced = fuse === 'enabled';
    if (actual && actual !== expected.value) {
      issues.push(issue('ASAR_INTEGRITY', archive, severity.HIGH, confidence.CERTAIN,
        `The SHA-256 of app.asar's header (${actual.slice(0, 16)}…) differs from the hash embedded in ${name} (${expected.value.slice(0, 16)}…): app.asar was changed after the app was built. ${enforced ? 'Electron refuses to load it.' : 'The EnableEmbeddedAsarIntegrityValidation fuse is off, so the modified code runs.'}`,
        { expected: expected.value, actual, enforced, source: expected.source }, INTEGRITY_DOCS));
      summary.integrity = 'mismatch';
    } else if (actual) {
      summary.integrity = enforced ? 'verified' : 'verified (not enforced)';
      issues.push(issue('ASAR_INTEGRITY', archive, severity.INFORMATIONAL, confidence.CERTAIN,
        `app.asar matches the integrity hash embedded in ${name}${enforced ? ', and the EnableEmbeddedAsarIntegrityValidation fuse enforces it' : ', but the EnableEmbeddedAsarIntegrityValidation fuse is not on, so nothing enforces it'}`,
        { expected: expected.value, enforced, source: expected.source }, INTEGRITY_DOCS));
    }
  } else if (fuse === 'enabled' && !expected) {
    issues.push(issue('ASAR_INTEGRITY', executable, severity.MEDIUM, confidence.CERTAIN,
      `The EnableEmbeddedAsarIntegrityValidation fuse is on, but ${name} carries no integrity hash for app.asar, so the validation cannot work as intended`, { fuse }, INTEGRITY_DOCS));
    summary.integrity = 'missing';
  }

  // --- code signing (Windows and macOS executables; Linux has no platform code signing) ---
  const signature = verifySignature(executable, { platform, run });
  if (signature.format) {
    summary.signing = signature;
    if (signature.status === NOT_SIGNED)
      issues.push(issue('CODE_SIGNING', executable, severity.MEDIUM, confidence.CERTAIN,
        `${name} is not code-signed (${signature.message}): users and the OS cannot tell a genuine copy from a modified one, and SmartScreen / Gatekeeper warn`, { status: signature.status }, SIGNING_DOCS));
    else if (inconclusiveSignature(signature))
      issues.push(issue('CODE_SIGNING', executable, severity.INFORMATIONAL, confidence.TENTATIVE,
        `${name} carries a signature${signature.signer ? ` by ${signature.signer}` : ''}, but the operating system could not finish verifying it (${signature.status}${signature.message ? `: ${signature.message}` : ''}); this is often an offline or locked-down machine. Verify the signature on a connected workstation`,
        { status: signature.status, signer: signature.signer, verifiedBy: signature.verifiedBy, inconclusive: true }, SIGNING_DOCS));
    else if (signature.verifiedBy !== 'none' && signature.status !== VALID) {
      const tampered = signature.status === 'HashMismatch' || /modified|invalid/i.test(signature.message);
      issues.push(issue('CODE_SIGNING', executable, tampered ? severity.HIGH : severity.MEDIUM, confidence.CERTAIN,
        `${name}: the operating system reports the signature as ${signature.status}${tampered ? ' (the file was modified after it was signed)' : ''}${signature.message ? `: ${signature.message}` : ''}`,
        { status: signature.status, signer: signature.signer, verifiedBy: signature.verifiedBy }, SIGNING_DOCS));
    } else
      issues.push(issue('CODE_SIGNING', executable, severity.INFORMATIONAL, signature.verifiedBy === 'none' ? confidence.FIRM : confidence.CERTAIN,
        `${name} is signed${signature.signer ? ` by ${signature.signer}` : ''}: ${signature.verifiedBy === 'none' ? signature.message : `the operating system reports ${signature.status}`}`,
        { status: signature.status, signer: signature.signer, verifiedBy: signature.verifiedBy }, SIGNING_DOCS));
  }

  // --- the updater configuration shipped next to the app (electron-updater's resources/app-update.yml) ---
  issues.push(...updateConfigIssues(path.dirname(archive || path.resolve(input)), { signed: signature.status !== NOT_SIGNED && !!signature.format }));

  // --- exploit mitigations ---
  const built = mitigations(executable);
  if (built) {
    summary.mitigations = built;
    if (built.missing.length > 0)
      issues.push(issue('BINARY_HARDENING', executable, severity.LOW, confidence.CERTAIN, `${name} (${built.format}) is built without: ${built.missing.join(', ')}`,
        { format: built.format, missing: built.missing }, 'https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization'));
  }
  return { issues, summary };
}

/**
 * resources/app-update.yml, which electron-updater reads: a feed over plain http, and no publisherName while the app is
 * unsigned (nothing to check a downloaded update's signature against on Windows).
 */
export function updateConfigIssues(resources, { signed = false } = {}) {
  const file = path.join(resources, 'app-update.yml');
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  const out = [];
  const url = (text.match(/^\s*url:\s*['"]?(\S+?)['"]?\s*$/m) || [])[1];
  const lineOf = (pattern) => text.split('\n').findIndex(line => pattern.test(line)) + 1;
  const reference = 'https://www.electron.build/auto-update';
  if (url && /^http:/i.test(url)) {
    const entry = issue('UPDATE_SECURITY_PACKAGED', file, severity.HIGH, confidence.CERTAIN,
      `The app looks for updates over unencrypted http (${url}): someone on the network path can serve a malicious update`, { url }, reference);
    entry.location = { line: lineOf(/^\s*url:/), column: 0 };
    entry.sample = `url: ${url}`;
    out.push(entry);
  }
  // electron-updater on Windows checks a downloaded installer's signature against publisherName from this file, and
  // skips the check when it is missing, whether or not the app itself is signed (a custom signing script leaves it out)
  const provider = (text.match(/^\s*provider:\s*['"]?([\w-]+)/m) || [])[1];
  if (!/^\s*publisherName:/m.test(text))
    out.push(issue('UPDATE_SECURITY_PACKAGED', file, severity.MEDIUM, confidence.FIRM,
      signed ? 'app-update.yml names no publisherName: electron-updater does not check the signature of the installers it downloads on Windows (the app itself is signed, but nothing ties an update to that signer); only the hash from the same update feed protects them'
        : 'app-update.yml names no publisherName and the app is not signed: electron-updater has no signer to check downloaded updates against', { provider, signed }, reference));
  return out;
}
