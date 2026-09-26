import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import pkg from '../../package.json' with { type: 'json' };
import { sourceExtensions } from '../parser/types.js';
import { renderHtmlReport } from './report_html.js';

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
  if (filePath === "N/A")
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

// relativePath is relative to the scanned folder, so scanning a folder inside a `test` directory still works
export function isNonAppFile(relativePath) {
  const parts = relativePath.split(/[\\/]/);
  // dot-directories hold tooling: .yarn/releases, .husky, .vscode, ...
  return parts.slice(0, -1).some(part => NON_APP_DIRECTORIES.has(part.toLowerCase()) || (part.startsWith('.') && part !== '.' && part !== '..')) ||
    NON_APP_FILES.test(parts[parts.length - 1]);
}

export async function list_files(input, { allFiles = false } = {}) {
  const entries = await fs.promises.readdir(input, { recursive: true, withFileTypes: true });
  const files = entries
    .filter(entry => entry.isFile())
    .map(entry => path.join(entry.parentPath, entry.name))
    .filter(file => !file.split(path.sep).includes('node_modules') && isScannableFile(file));
  if (allFiles) return files;
  const vendored = vendoredDirectories(input, entries);
  return files.filter(file => !isNonAppFile(path.relative(input, file)) &&
    !vendored.some(dir => file.startsWith(dir + path.sep)) && !isVendoredLibrary(file));
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

/**
 * A copy of a third-party library, e.g. js/jquery.js starting with "jQuery JavaScript Library v2.1.1 ... MIT license":
 * the header comment names the file itself and carries a version and a license or copyright. App bundles with their
 * own banner (main.js, "MyApp v1.0.0") don't match, as the banner doesn't name the file.
 */
export function isVendoredLibrary(file, head) {
  if (!/\.[cm]?js$/i.test(file)) return false;
  const name = normalize(path.basename(file).replace(/\.[cm]?js$/i, '').replace(/([.-](min|umd|bundle|dist|debug|prod|production|slim))+$/i, '').replace(/[.-]v?\d+(\.\d+)*$/, ''));
  if (name.length < 3) return false;
  try {
    head ??= readHead(file);
  } catch {
    return false;
  }
  const header = (head.match(/^[\s;]*((?:\/\*[\s\S]*?\*\/|\/\/[^\n]*)\s*)+/) || [''])[0];
  return /\bv?\d+\.\d+/.test(header) && /(copyright|\(c\)|©|licen[cs]e)/i.test(header) && normalize(header).includes(name);
}

function readHead(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.alloc(2048);
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
