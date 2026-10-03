import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import pkg from '../../package.json' with { type: 'json' };
import { sourceExtensions } from '../parser/types.js';
import { renderHtmlReport } from './report_html.js';
import { detectLibraries } from './libraries.js';
import { consequenceOf, validationHint, interactionOf } from '../finder/consequences.js';
import { remediationOf } from '../finder/remediation.js';
import { cycloneDx } from '../report/cyclonedx.js';
import { renderDocx } from '../report/docx.js';
import { writeClientMarkdown, findingFingerprints, MARKDOWN_FOLDER, TESTER_NOTES_FOLDER } from '../report/markdown.js';
import { COMPONENTS_SHEET } from '../report/markdown_outdated.js';
import { renderComponentsXlsx } from '../report/xlsx.js';
import { scores } from '../report/scores.js';
import { fingerprints } from './baseline.js';

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

// how much of a minified line is kept before and after the finding's column (about one printed line in all), and how long
// a line of context may be
const EXCERPT = 150;
const EXCERPT_BEFORE = 40;
const EXCERPT_AFTER = 100;
const CONTEXT_LINE = 200;
/**
 * The code around a finding, for its evidence: { start, lines } with start the number of the first line, and two lines
 * either side. On a minified line (longer than a screen), an excerpt around the
 * column instead: { start, lines: [excerpt], excerpt: true }.
 */
export function getContext(fileLines, index, column = 0) {
  const line = String(fileLines[index] ?? '').replace(/\r$/, '');
  if (!line.trim()) return undefined;
  if (line.length > 2 * EXCERPT) {
    const from = Math.max(0, column - EXCERPT_BEFORE);
    const to = Math.min(line.length, column + EXCERPT_AFTER);
    return { start: index + 1, lines: [`${from > 0 ? '…' : ''}${line.slice(from, to).trim()}${to < line.length ? '…' : ''}`], excerpt: true };
  }
  const first = Math.max(0, index - 2);
  const lines = fileLines.slice(first, index + 3).map(l => String(l).replace(/\r$/, '').trimEnd())
    .map(l => l.length > CONTEXT_LINE ? `${l.slice(0, CONTEXT_LINE)}…` : l);
  return { start: first + 1, lines };
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
// skipped files that are still checked for library copies (vendor/jquery.min.js), unless they are tests or documentation
const NOT_SHIPPED_DIRECTORIES = new Set(['test', 'tests', '__tests__', '__mocks__', '__fixtures__', 'fixtures', 'spec', 'specs', 'e2e', 'coverage', 'docs', 'examples', 'benchmark', 'benchmarks']);

export function isSourceBuildTooling(relativePath) {
  return /^build[\\/](vite|bin|webpack|rollup)[\\/]/i.test(relativePath) && !isManifestFile(relativePath);
}

// relativePath is relative to the scanned folder, so scanning a folder inside a `test` directory still works
export function isNonAppFile(relativePath, { packaged = false } = {}) {
  const parts = relativePath.split(/[\\/]/);
  if (packaged) return parts.slice(0, -1).some(part => PACKAGED_NON_APP_DIRECTORIES.has(part.toLowerCase())) || PACKAGED_NON_APP_FILES.test(parts[parts.length - 1]);
  // Source tooling under build/ is distinct from built app code in dist/. Keep electron-builder manifests.
  if (isSourceBuildTooling(relativePath)) return true;
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
    const relative = path.relative(input, file);
    if (isNonAppFile(relative, { packaged })) {
      skipped.nonAppFiles++;
      // a minified or vendor copy of a library is not scanned, but it is one of the app's components
      const parts = relative.split(/[\\/]/).slice(0, -1);
      if (!parts.some(part => NOT_SHIPPED_DIRECTORIES.has(part.toLowerCase()) || part.startsWith('.'))) {
        const library = vendoredLibrary(file);
        if (library) libraries.push({ ...library, file });
      }
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

export const OUTPUT_FORMATS = ['csv', 'sarif', 'html', 'htm', 'json', 'docx', 'md', 'xlsx'];

export function outputFormat(filename, isSarif) {
  if (isSarif) return 'sarif';
  if (/\.cdx\.json$/i.test(String(filename))) return 'cyclonedx';
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

// one finding as the JSON report stores it: everything the reports are written from, so they can be written again later
// (--rerender) from this file alone
const issueEntry = (issue, fingerprint) => ({
  fingerprint,
  comparison: issue.comparison,
  id: issue.id,
  severity: issue.severity.name,
  confidence: issue.confidence.name,
  manualReview: !!issue.manualReview,
  file: issue.file,
  line: issue.location ? issue.location.line : undefined,
  column: issue.location ? issue.location.column : undefined,
  sample: issue.sample,
  context: issue.context,
  description: issue.description,
  // the watch session a runtime finding came from (validation results carry their own)
  session: issue.session,
  exploitableBy: consequenceOf(issue.id)?.label,
  consequence: consequenceOf(issue.id)?.text,
  interaction: interactionOf(issue.id),
  validation: issue.validation,
  howToValidate: issue.manualReview && !issue.validation ? validationHint(issue.id) : undefined,
  remediation: remediationOf(issue.id, issue)?.fix,
  remediationExample: remediationOf(issue.id, issue)?.example,
  notes: issue.notes,
  reference: issue.shortenedURL,
  properties: reportProperties(issue.properties)
});

// an accepted risk: the finding in full, and why it is accepted (also flattened, as earlier reports had it)
const suppressedEntry = (issue, fingerprint) => ({ ...issueEntry(issue, fingerprint), ...issue.suppression, suppression: issue.suppression });

function jsonReport(result, meta) {
  const summary = {};
  for (const issue of result) summary[issue.severity.name] = (summary[issue.severity.name] || 0) + 1;
  const prints = fingerprints(result, meta.input);
  const suppressed = meta.suppressed || [];
  const suppressedPrints = fingerprints(suppressed, meta.input);
  return JSON.stringify({
    tool: 'Electronegativity',
    ...meta,
    summary,
    scores: scores(result),
    suppressed: suppressed.map((issue, i) => suppressedEntry(issue, suppressedPrints[i].fingerprint)),
    issues: result.map((issue, i) => issueEntry(issue, prints[i].fingerprint)),
  }, null, 2);
}

/**
 * The client deliverables of a run in <base>/reports: one Markdown file per finding and the components workbook
 * (components.xlsx) the outdated components finding refers to. Returns { dir, findings, sheet }.
 */
export function writeReports(base, result, meta = {}, subfolder = MARKDOWN_FOLDER, notesSubfolder = TESTER_NOTES_FOLDER) {
  const dir = path.join(path.resolve(base), subfolder);
  const findings = writeClientMarkdown(path.resolve(base), result, meta, subfolder, notesSubfolder);
  const sheet = path.join(dir, COMPONENTS_SHEET);
  fs.writeFileSync(sheet, renderComponentsXlsx(meta.dependencies, { appName: meta.app?.name, changes: meta.workbookChanges }));
  // what was written, section by section: kept in report.json, so a later --rerender can tell the tester's edits apart
  const markdown = { version: VER, findings: Object.fromEntries(findings.map(file => [path.basename(file), findingFingerprints(fs.readFileSync(file, 'utf8'))])) };
  return { dir, findings, sheet, markdown };
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
  if (format === 'cyclonedx') {
    fs.writeFileSync(filename, JSON.stringify(cycloneDx(meta), null, 2));
    return;
  }
  if (format === 'docx') {
    fs.writeFileSync(filename, renderDocx(result, meta));
    return;
  }
  // client findings: one file per finding, with the components workbook, in a reports folder where the .md file was asked for
  if (format === 'md') {
    writeReports(path.dirname(path.resolve(filename)), result, { ...meta, root });
    return;
  }
  if (format === 'xlsx') {
    fs.writeFileSync(filename, renderComponentsXlsx(meta.dependencies, { appName: meta.app?.name }));
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
              informationUri: "https://github.com/Headset365/electronegativity",
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
    const prints = fingerprints(result, root);
    const suppressedIssues = meta.suppressed || [];
    const suppressedPrints = fingerprints(suppressedIssues, root);
    const BASELINE_STATE = { new: 'new', unchanged: 'unchanged', changed: 'updated' };
    const reportedCount = result.length;
    [...result, ...suppressedIssues].forEach((issue, index) => {
      const suppressedIssue = index >= reportedCount;
      const fingerprint = suppressedIssue ? suppressedPrints[index - reportedCount].fingerprint : prints[index].fingerprint;
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
        },
        partialFingerprints: { 'electronegativity/v1': fingerprint },
      };
      if (!suppressedIssue && issue.comparison) result.baselineState = BASELINE_STATE[issue.comparison];
      if (suppressedIssue) result.suppressions = [{ kind: 'external', status: 'accepted', justification: [issue.suppression.reason, issue.suppression.owner && `owner: ${issue.suppression.owner}`, issue.suppression.expires && `until ${issue.suppression.expires}`].filter(Boolean).join('; ') }];

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

const OUTPUT_EXTENSION = /\.(html?|json|sarif|csv|docx|md|xlsx)$/i;

/**
 * The files of -o: comma-separated, and also space-separated when every part is an output file name. PowerShell turns
 * an unquoted `-o a.html,b.json` into the single argument "a.html b.json"; a lone name with spaces ("my report.html")
 * stays as it is.
 */
export function splitOutputs(value) {
  return [].concat(value || []).flatMap(v => String(v).split(',')).map(o => o.trim()).filter(Boolean)
    .flatMap(o => {
      const parts = o.split(/\s+/);
      return parts.length > 1 && parts.every(part => OUTPUT_EXTENSION.test(part)) ? parts : [o];
    });
}

/** The first output whose folder can't be written to, with the reason, or undefined: checked before a long scan. */
export function unwritableOutput(outputs) {
  for (const output of outputs) {
    const dir = path.dirname(path.resolve(output));
    const probe = path.join(dir, `.electronegativity-write-test-${process.pid}`);
    try {
      fs.writeFileSync(probe, '');
      fs.unlinkSync(probe);
    } catch (error) {
      return { output: path.resolve(output), dir, reason: error.code || error.message };
    }
  }
  return undefined;
}
