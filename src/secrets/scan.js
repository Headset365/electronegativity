// Hard-coded secrets in what the app ships: provider keys and tokens (AWS, Google, GitHub, Slack, Stripe, OpenAI,
// Anthropic, Twilio, SendGrid, npm, private keys, JWTs, connection strings, credentials in URLs) and secret-named
// assignments in code and JSON; in configuration files (.env, .ini, .yml, ...) also unquoted values and an entropy check
// on any key; native modules (*.node), helper binaries and app.asar.unpacked are searched for the provider patterns.
// Anyone who downloads the app can extract these. Values are always redacted in findings.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import * as asar from '@electron/asar';
import { severity, confidence } from '../finder/attributes.js';
import { isNonAppFile } from '../util/file.js';

const require = createRequire(import.meta.url);
const { findSecrets, redact, redactText, looksRandomSecret } = require('../traffic/secrets.cjs');

const CODE = /\.([cm]?[jt]sx?|html?|vue|svelte)$/i;
const CONFIG = /(^\.env(\..*)?$|\.(env|ini|ya?ml|properties|toml|conf|cfg|config|json|plist|xml)$)/i;
const LOCKFILES = /^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock)$/i;
const BINARY = /\.(node|dll|so|dylib|exe|bin)$/i;
// Electron's and Chromium's own files next to the app's executable: they hold no app secrets and are large
const RUNTIME_FILES = /^(ffmpeg|libEGL|libGLESv2|libvulkan|vk_swiftshader|vulkan-1|d3dcompiler_47|chrome_(100|200)_percent|chrome-sandbox|chrome_crashpad_handler|crashpad_handler|libffmpeg|snapshot_blob|v8_context_snapshot|icudtl|resources|LICENSE.*|Squirrel|Update|elevate)\b/i;
const MAX_TEXT = 8 * 1024 * 1024;
const MAX_BINARY = 64 * 1024 * 1024;
const MAX_FINDINGS = 500;

// printable ASCII and UTF-16LE strings in a binary, with their offsets
function binaryStrings(data) {
  const out = [];
  const text = data.toString('latin1');
  for (const m of text.matchAll(/[\x20-\x7e]{16,}/g)) out.push([m[0], m.index]);
  const utf16 = /(?:[\x20-\x7e]\x00){16,}/g; // eslint-disable-line no-control-regex
  for (const m of text.matchAll(utf16)) out.push([Buffer.from(m[0], 'latin1').toString('utf16le'), m.index]);
  return out;
}

const isFile = (file) => {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
};

export function walk(dir, { skip = () => false } = {}) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { recursive: true, withFileTypes: true });
  } catch {
    return [];
  }
  return entries.filter(e => e.isFile()).map(e => path.join(e.parentPath, e.name)).filter(file => !skip(path.relative(dir, file)));
}

/**
 * The text and binary files to search, as [{ label, read(): Buffer, kind: 'code'|'config'|'binary' }].
 * @param {string} input the scanned folder or app.asar
 * @param {string[]} codeFiles the code files the scan loaded (already filtered for tests and vendored libraries)
 * @param {Function} readLoaded reads one of them
 */
export function secretSources(input, codeFiles, readLoaded, { allFiles = false } = {}) {
  const sources = [];
  const seen = new Set();
  const add = (label, read, kind) => {
    if (seen.has(label)) return;
    seen.add(label);
    sources.push({ label, read, kind });
  };
  for (const file of codeFiles) {
    const base = path.basename(file);
    if (LOCKFILES.test(base)) continue;
    add(file, () => readLoaded(file), CODE.test(file) ? 'code' : 'config');
  }
  const resolved = path.resolve(input);
  const inNodeModules = (rel) => rel.split(/[\\/]/).includes('node_modules');
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch {
    return sources;
  }
  if (stat.isDirectory()) {
    for (const file of walk(resolved, { skip: rel => rel.split(/[\\/]/).includes('.git') })) {
      const rel = path.relative(resolved, file);
      const base = path.basename(file);
      if (BINARY.test(base) && !RUNTIME_FILES.test(base)) add(file, () => fs.readFileSync(file), 'binary'); // native modules, node_modules included
      else if (CONFIG.test(base) && !LOCKFILES.test(base) && !inNodeModules(rel) && (allFiles || !isNonAppFile(rel, { packaged: /[\\/]resources[\\/]app$/i.test(resolved) })))
        add(file, () => fs.readFileSync(file), 'config');
    }
  } else if (/\.asar$/i.test(resolved)) {
    let files = [];
    try {
      files = asar.listPackage(resolved, { isPack: false }).map(f => f.replace(/^[\\/]/, ''));
    } catch {
      // not a readable archive
    }
    for (const rel of files) {
      const base = path.basename(rel);
      const label = path.join(resolved, rel);
      const read = () => asar.extractFile(resolved, rel);
      if (CONFIG.test(base) && !LOCKFILES.test(base) && !inNodeModules(rel) && (allFiles || !isNonAppFile(rel, { packaged: true }))) add(label, read, 'config');
    }
  }
  // a packaged app: what ships next to its code (app.asar.unpacked, config files in resources/, helper binaries)
  const resources = /[\\/]resources[\\/]app(\.asar)?$/i.test(resolved) ? path.dirname(resolved) : undefined;
  if (resources) {
    const unpacked = path.join(resources, 'app.asar.unpacked');
    for (const file of walk(unpacked)) add(file, () => fs.readFileSync(file), BINARY.test(file) ? 'binary' : CONFIG.test(file) || CODE.test(file) ? 'config' : 'binary');
    for (const name of fs.readdirSync(resources)) {
      const file = path.join(resources, name);
      if (isFile(file) && CONFIG.test(name)) add(file, () => fs.readFileSync(file), 'config');
    }
    const appDir = path.dirname(resources);
    let entries = [];
    try {
      entries = fs.readdirSync(appDir);
    } catch {
      // no install folder
    }
    for (const name of entries) {
      const file = path.join(appDir, name);
      if (isFile(file) && BINARY.test(name) && !RUNTIME_FILES.test(name) && !/\.exe$/i.test(name)) add(file, () => fs.readFileSync(file), 'binary');
    }
  }
  return sources;
}

/**
 * A line of code shown around a finding, with the secrets in it redacted as everywhere else in the reports: provider
 * patterns, secret-named assignments, and string literals that look like random keys or tokens.
 */
export function redactCodeLine(line) {
  let out = redactText(String(line));
  for (const hit of findSecrets(out)) out = out.split(hit.value).join(redact(hit.value));
  return out.replace(/(['"`])([^'"`\s]{24,})\1/g, (match, quote, value) => looksRandomSecret(value) ? `${quote}${redact(value)}${quote}` : match);
}

/**
 * Searches the sources for hard-coded secrets. @returns issues (HARDCODED_SECRET), each value redacted.
 */
export function scanSecrets(sources) {
  const issues = [];
  const seenValues = new Set();
  const push = (file, line, kind, value, sample, extra = {}) => {
    if (seenValues.has(value) || issues.length >= MAX_FINDINGS) return;
    seenValues.add(value);
    const generic = kind.startsWith('Hard-coded');
    const entropy = kind.startsWith('High-entropy');
    const sev = entropy ? severity.LOW : generic ? severity.MEDIUM : severity.HIGH;
    const conf = entropy ? confidence.TENTATIVE : generic ? confidence.TENTATIVE : confidence.FIRM;
    issues.push({ file, sample, location: { line, column: 0 }, id: 'HARDCODED_SECRET',
      description: `${kind} in the app package${extra.offset !== undefined ? ` (at offset 0x${extra.offset.toString(16)})` : ''}, value ${redact(value)}: anyone who downloads the app can extract it${entropy ? '. Found by randomness alone: check whether it is a credential' : ''}`,
      properties: { kind, source: extra.binary ? 'binary' : 'file', offset: extra.offset }, severity: sev, confidence: conf, manualReview: conf !== confidence.CERTAIN,
      shortenedURL: 'https://cwe.mitre.org/data/definitions/798.html',
      visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'HardcodedSecrets' });
  };
  for (const source of sources) {
    let data;
    try {
      data = source.read();
    } catch {
      continue;
    }
    if (!data) continue;
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    if (source.kind === 'binary') {
      if (buffer.length > MAX_BINARY) continue;
      for (const [text, offset] of binaryStrings(buffer))
        for (const hit of findSecrets(text, { patternsOnly: true })) push(source.label, 0, hit.kind, hit.value, `${hit.kind}: ${redact(hit.value)}`, { binary: true, offset: offset + hit.offset });
      continue;
    }
    if (buffer.length > MAX_TEXT || buffer.includes(0)) continue;
    const text = buffer.toString('utf8');
    const lines = text.split('\n');
    for (const hit of findSecrets(text, { config: source.kind === 'config' })) {
      const line = text.slice(0, hit.offset).split('\n').length;
      const code = (lines[line - 1] || '').trim().slice(0, 300).split(hit.value).join(redact(hit.value));
      push(source.label, line, hit.kind, hit.value, code);
    }
  }
  return issues;
}
