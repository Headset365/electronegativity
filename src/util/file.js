import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import pkg from '../../package.json' with { type: 'json' };
import { sourceExtensions } from '../parser/types.js';
import { renderHtmlReport } from './report_html.js';
import { detectLibraries } from './libraries.js';
import { consequenceOf, validationHint } from '../finder/consequences.js';

const VER = pkg.version;
const MANIFEST_FILES = ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'electron-builder.json', 'electron-builder.yml', 'electron-builder.yaml'];

export function is_directory(input){
  return fs.statSync(input).isDirectory();
}

export function getSample(fileLines, index) {
  let sample = fileLines[index] ?? "";
  // Also removes the \r leftover from split('\n') on Windows
  // Using split('\n') in checkers however is OK, because file ending depends on Git settings and *may* be just '\n' even on Windows
  sample = sample.trim();

  return sample;
}

export function getRelativePath(targetFolder, filePath) {
  // "N/A", and files served remotely, which are reported by URL
  if (filePath === "N/A" || /^[a-z][a-z0-9+.-]*:\/\//i.test(filePath))
    return filePath;
  if (is_directory(targetFolder))
    return path.relative(targetFolder, filePath);
  else //if (extension(targetFolder) === 'asar')
    return path.relative(path.dirname(targetFolder), filePath);
}

export function input_exists(input) {
  try {
    return fs.lstatSync(input);
  } catch (err) {
    return false;
  }
}

export function read_file(file) {
  return fs.readFileSync(file, 'utf8');
}

export function extension(file) {
  return file.slice((file.lastIndexOf('.') - 1 >>> 0) + 2).toLowerCase();
}

export function isManifestFile(file) {
  return MANIFEST_FILES.includes(path.basename(file).toLowerCase());
}

export function isScannableFile(file) {
  const ext = extension(file);
  return (ext !== 'json' && ext in sourceExtensions) || isManifestFile(file);
}

// Tests, mocks, fixtures and vendored third-party code don't ship as part of the app, and scanning them mostly adds noise
const NON_APP_DIRECTORIES = new Set(['test', 'tests', '__tests__', '__mocks__', '__fixtures__', 'fixtures', 'spec', 'specs', 'e2e', 'vendor', 'third_party', 'third-party', 'coverage', '.git', 'script', 'scripts', 'tools', 'docs', '.github', '.circleci', 'benchmark', 'benchmarks', 'examples']);
// tests, stories, minified files and vendored package manager releases (yarn-4.10.3.cjs, yarn-standalone.js)
const NON_APP_FILES = /\.(test|spec|stories|e2e)\.[cm]?[jt]sx?$|[.-]min\.js$|^(yarn|pnpm|npm)-[\w.-]+\.c?js$|-standalone\.c?js$/i;

// What ships in a packaged app (app.asar, resources/app) or is served to it is all app code: its scripts/ folder and
// .min.js bundles included (the usual AngularJS build output). Only tests are left out there.
const PACKAGED_NON_APP_DIRECTORIES = new Set(['test', 'tests', '__tests__', '__mocks__', 'spec', 'specs', 'e2e', '.git']);
const PACKAGED_NON_APP_FILES = /\.(test|spec|stories|e2e)\.[cm]?[jt]sx?$/i;

// relativePath is relative to the scanned folder, so scanning a folder inside a `test` directory still works
export function isNonAppFile(relativePath, { packaged = false } = {}) {
  const parts = relativePath.split(/[\\/]/);
  if (packaged) return parts.slice(0, -1).some(part => PACKAGED_NON_APP_DIRECTORIES.has(part.toLowerCase())) || PACKAGED_NON_APP_FILES.test(parts[parts.length - 1]);
  // dot-directories hold tooling: .yarn/releases, .husky, .vscode, ...
  return parts.slice(0, -1).some(part => NON_APP_DIRECTORIES.has(part.toLowerCase()) || (part.startsWith('.') && part !== '.' && part !== '..')) ||
    NON_APP_FILES.test(parts[parts.length - 1]);
}

export async function list_files(input, { allFiles = false, packaged = false } = {}) {
  const entries = await fs.promises.readdir(input, { recursive: true, withFileTypes: true });
  const files = entries
    .filter(entry => entry.isFile())
    .map(entry => path.join(entry.parentPath, entry.name))
    .filter(file => !file.split(path.sep).includes('node_modules') && isScannableFile(file));
  // a packaged app has no lockfile: the packages it ships are listed from node_modules/<name>/package.json
  const installed = packaged ? installedPackages(entries.filter(e => e.isFile() && e.name === 'package.json').map(e => path.join(e.parentPath, e.name)),
    (file) => fs.readFileSync(file, 'utf8')) : [];
  if (allFiles) {
    files.installedPackages = installed;
    return files;
  }
  const vendoredDirs = vendoredDirectories(input, entries);
  // skipped copies of libraries are still listed, so their versions can be checked for advisories
  const libraries = [];
  const skipped = { nonAppFiles: 0, vendoredDirectories: 0, vendoredLibraries: 0 };
  const kept = files.filter(file => {
    if (isNonAppFile(path.relative(input, file), { packaged })) {
      skipped.nonAppFiles++;
      return false;
    }
    const inVendoredDir = vendoredDirs.some(dir => file.startsWith(dir + path.sep));
    const library = vendoredLibrary(file);
    if (library) libraries.push({ ...library, file });
    if (library) skipped.vendoredLibraries++;
    else if (inVendoredDir) skipped.vendoredDirectories++;
    return !library && !inVendoredDir;
  });
  kept.skipped = skipped;
  // packages bower installed record their name and version in .bower.json
  for (const entry of entries) {
    if (!entry.isFile() || entry.name !== '.bower.json') continue;
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(entry.parentPath, entry.name), 'utf8'));
      if (manifest.name && manifest.version) libraries.push({ name: manifest.name.toLowerCase(), version: manifest.version, file: path.join(entry.parentPath, entry.name) });
    } catch {
      // unreadable manifest
    }
  }
  kept.vendoredLibraries = libraries;
  kept.installedPackages = installed;
  return kept;
}

/**
 * Packages installed in a packaged app: { name, version, file } for each node_modules/<name>/package.json and
 * node_modules/@scope/<name>/package.json (nested installs included). `read` returns a file's text.
 */
export function installedPackages(manifests, read) {
  const found = [];
  const seen = new Set();
  for (const file of manifests) {
    const parts = file.split(/[\\/]/);
    const at = parts.lastIndexOf('node_modules');
    // node_modules/<name>/package.json or node_modules/@scope/<name>/package.json, not files deeper in a package
    const depth = parts.length - 1 - at;
    if (at === -1 || !(depth === 2 || (depth === 3 && parts[at + 1].startsWith('@')))) continue;
    try {
      const manifest = JSON.parse(read(file));
      if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string') continue;
      const key = `${manifest.name}@${manifest.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ name: manifest.name, version: manifest.version, file });
    } catch {
      // unreadable manifest
    }
  }
  return found;
}

// Folders package managers other than npm install into: bower (.bowerrc "directory", bower_components, and any package
// it installed, which gets a .bower.json), jspm
function vendoredDirectories(input, entries) {
  const directories = new Set(['bower_components', 'jspm_packages'].map(name => path.join(input, name)));
  try {
    const bowerrc = JSON.parse(fs.readFileSync(path.join(input, '.bowerrc'), 'utf8'));
    if (typeof bowerrc.directory === 'string') directories.add(path.resolve(input, bowerrc.directory));
  } catch {
    // no .bowerrc
  }
  for (const entry of entries) if (entry.isFile() && entry.name === '.bower.json') directories.add(entry.parentPath);
  return [...directories].map(dir => dir.replace(/[\\/]+$/, ''));
}

const normalize = (text) => text.toLowerCase().replace(/[^a-z0-9]/g, '');
// file names of bundles that hold third-party libraries rather than app code
const BUNDLE_NAMES = new Set(['vendor', 'vendors', 'lib', 'libs', 'libraries', 'thirdparty', 'polyfills', 'chunkvendors', 'vendorbundle', 'externals', 'deps', 'dependencies']);
// banner names that differ from the npm package name
const LIBRARY_ALIASES = { angularjs: 'angular', 'jquery ui': 'jquery-ui', 'underscore.js': 'underscore', 'vue.js': 'vue', 'chart.js': 'chart.js' };

/**
 * A copy of a third-party library, e.g. js/jquery.js starting with "jQuery JavaScript Library v2.1.1 ... MIT license":
 * the header comment names the file itself and carries a version and a license or copyright. App bundles with their
 * own banner (main.js, "MyApp v1.0.0") don't match, as the banner doesn't name the file.
 * Returns { name, version } (name as the npm package is usually called) or undefined.
 */
export function vendoredLibrary(file, head) {
  if (!/\.[cm]?js$/i.test(file)) return undefined;
  // _0123abcd: the query string of a script captured from a server (angular.min_0123abcd.js)
  const stem = path.basename(file).replace(/\.[cm]?js$/i, '').replace(/_[0-9a-f]{8}$/, '').replace(/([.-](min|umd|bundle|dist|debug|prod|production|slim))+$/i, '').replace(/[.-]v?\d+(\.\d+)*$/, '');
  const name = normalize(stem);
  if (name.length < 3) return undefined;
  try {
    head ??= readHead(file);
  } catch {
    return undefined;
  }
  const header = (head.match(/^[\s;]*((?:\/\*[\s\S]*?\*\/|\/\/[^\n]*)\s*)+/) || [''])[0];
  if (!/\bv?\d+\.\d+/.test(header) || !/(copyright|\(c\)|©|licen[cs]e)/i.test(header)) return undefined;
  // a bundle of third-party libraries (vendor.min.js, chunk-vendors.js) starting with a library's banner: named after it
  if (BUNDLE_NAMES.has(name)) {
    const banner = header.match(/(?:\/\*!?|\/\/!?)[\s*]*(?:@license\s+)?(@?[A-Za-z][\w.@/-]*)\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
    if (!banner) return undefined;
    const library = banner[1].toLowerCase();
    return { name: LIBRARY_ALIASES[library] || library, version: banner[2], bundle: true };
  }
  if (!normalize(header).includes(name)) return undefined;
  // the banner or version string of a known library names it the way npm does (purify.js is dompurify) and carries the
  // right version (lodash's banner also credits Underscore.js 1.8.3)
  const known = detectLibraries(head);
  if (known.length === 1) return known[0];
  const version = (header.match(/\bv?(\d+\.\d+\.\d+(?:-[\w.]+)?)\b/) || header.match(/\bv?(\d+\.\d+)\b/) || [])[1];
  return { name: stem.toLowerCase(), version };
}

export function isVendoredLibrary(file, head) {
  return !!vendoredLibrary(file, head);
}

function readHead(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.alloc(16384);
    return buffer.toString('utf8', 0, fs.readSync(fd, buffer, 0, buffer.length, 0));
  } finally {
    fs.closeSync(fd);
  }
}

export const OUTPUT_FORMATS = ['csv', 'sarif', 'html', 'htm', 'json'];

export function outputFormat(filename, isSarif) {
  if (isSarif) return 'sarif';
  const ext = extension(filename);
  if (ext === 'htm') return 'html';
  return OUTPUT_FORMATS.includes(ext) ? ext : 'csv';
}

// Large internal data (e.g. the lockfile inventory) isn't useful in reports
function reportProperties(properties) {
  if (!properties) return undefined;
  const rest = Object.fromEntries(Object.entries(properties).filter(([key]) => key !== 'packages'));
  return Object.keys(rest).length > 0 ? rest : undefined;
}

function jsonReport(result, meta) {
  const summary = {};
  for (const issue of result) summary[issue.severity.name] = (summary[issue.severity.name] || 0) + 1;
  return JSON.stringify({
    tool: 'Electronegativity',
    ...meta,
    summary,
    issues: result.map(issue => ({
      id: issue.id,
      severity: issue.severity.name,
      confidence: issue.confidence.name,
      manualReview: !!issue.manualReview,
      file: issue.file,
      line: issue.location ? issue.location.line : undefined,
      column: issue.location ? issue.location.column : undefined,
      sample: issue.sample,
      description: issue.description,
      exploitableBy: consequenceOf(issue.id)?.label,
      consequence: consequenceOf(issue.id)?.text,
      validation: issue.validation,
      howToValidate: issue.manualReview && !issue.validation ? validationHint(issue.id) : undefined,
      reference: issue.shortenedURL,
      properties: reportProperties(issue.properties)
    }))
  }, null, 2);
}

export function writeIssues(root, isRelative, filename, result, isSarif, meta = {}){
  let output = '';
  const format = outputFormat(filename, isSarif);
  meta = { version: VER, generatedAt: new Date().toISOString(), input: root, ...meta };

  if (format === 'html') {
    fs.writeFileSync(filename, renderHtmlReport(result, meta));
    return;
  }
  if (format === 'json') {
    fs.writeFileSync(filename, jsonReport(result, { ...meta, errors: (meta.errors || []).map(({ file, message, tolerable }) => ({ file, message, tolerable })) }));
    return;
  }
  isSarif = format === 'sarif';

  if (isSarif) {
    let issues =
    {
      $schema: "http://json.schemastore.org/sarif-2.1.0",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              version: `${VER}`,
              informationUri: "https://github.com/doyensec/electronegativity",
              name: "Electronegativity",
              fullName: "Electronegativity is a tool to identify misconfigurations and security anti-patterns in Electron applications",
              rules: []
            }
          },
          results: []
        }
      ]
    };

    if (isRelative) {
      issues.runs[0].invocations = [
        {
          workingDirectory: {
            uri: pathToFileURL(root).href
          },
          executionSuccessful: true
        },
      ];
    }

    const seenRules = new Set();
    result.forEach(issue => {
      if (!seenRules.has(issue.id)) {
        issues.runs[0].tool.driver.rules.push({
          id: issue.id,
          fullDescription: {
            text: issue.description
          },
          properties: {
            category: "Security"
          },
          helpUri: issue.shortenedURL,
          help: {
            text: issue.shortenedURL
          }
        });
        seenRules.add(issue.id);
      }

      let result = {
        ruleId: issue.id,
        level: `${issue.manualReview ? 'note' : 'warning'}`,
        message: {
          text: issue.description
        }
      };

      result.locations = [
        {
          physicalLocation: {
            artifactLocation: {
              uri: issue.file !== "N/A" ? issue.file : "file:///"
            },
            region: {
              startLine: issue.location && issue.location.line !== undefined ? (issue.location.line === 0 ? 1 : issue.location.line) : 1, // This is odd, VS and VS Code highlight the line correctly, but min value is 1
              startColumn: issue.location && issue.location.column !== undefined ? issue.location.column + 1 : 1, // sarif columns start from 1
              charLength: issue.sample ? issue.sample.length : 0
            }
          }
        }
      ];

      issues.runs[0].results.push(result);
    });

    output = JSON.stringify(issues, null, 2);
  }
  else{
    output = csvHeader();
    result.forEach(issue => {
      output += [
        issue.id,
        escapeCsv(issue.severity.name),
        escapeCsv(issue.confidence.name),
        escapeCsv(issue.file),
        escapeCsv(`${issue.location.line}:${issue.location.column}`),
        escapeCsv(issue.sample),
        escapeCsv(issue.description),
        escapeCsv(issue.shortenedURL || '')
      ].toString();
      output += os.EOL;
    });
  }

  fs.writeFileSync(filename, output);
}

function escapeCsv(val) {
  return val != null ? '"' + val.replace(/"/g, '""') + '"' : "N/A";
}

function csvHeader() {
  return `issue, severity, confidence, filename, location, sample, description, url${os.EOL}`;
}

export function writeCsvHeader(filename){
  fs.writeFileSync(filename, csvHeader());
}
