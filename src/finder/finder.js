import { CHECKS } from './checks/AtomicChecks/index.js';
import { sourceTypes } from '../parser/types.js';
import { severity } from "./attributes.js";
import { ELECTRON_ATOMIC_UPGRADE_CHECKS } from './checks/AtomicChecks/ElectronAtomicUpgradeChecks.js';
import { isDisabledByInlineComment } from "../util/exceptions.js";
import { getSample, getContext } from "../util/file.js";

// The whole line a finding was matched on, for its baseline fingerprint: the sample shown in reports is an excerpt of a
// long (minified) line, and fingerprints made before excerpts existed hashed the whole line. Not enumerable, so it never
// reaches a report.
// window settings whose risk depends on what the window shows
const WINDOW_SETTINGS = new Set(['CONTEXT_ISOLATION_JS_CHECK', 'NODE_INTEGRATION_JS_CHECK', 'SANDBOX_JS_CHECK']);
// a hidden window that only loads the application's own local page (a settings migration, a print helper) is rated LOW,
// a visible one one step lower than its setting alone; the local page still needs a look for remote scripts
function lowerForLocalWindow(issue, { hidden, loads }) {
  const order = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH'];
  const current = order.indexOf(issue.severity?.name);
  if (current < 1) return;
  const lowered = hidden ? 1 : Math.max(1, current - 1);
  if (lowered >= current) return;
  issue.severity = severity[order[lowered]];
  issue.properties = { ...issue.properties, localOnly: true, hidden, loads };
  issue.description = `${issue.description}; the window${hidden ? ' is hidden and' : ''} only loads the application's own local ${loads.length === 1 ? 'page' : 'pages'} (${loads.join(', ')}), so the setting matters if that page loads remote content or runs untrusted data`;
}

function keepFingerprintLine(issue, line) {
  if (line !== issue.sample) Object.defineProperty(issue, 'fingerprintSample', { value: line, enumerable: false, configurable: true, writable: true });
}
import { gte, compare, coerce } from 'semver';
import { setAnalysisContext, platformGuard, localWindowContent } from './checks/analysis.js';
import { Parser } from '../parser/parser.js';
import { diagnostics } from '../util/diagnostics.js';

const SAMPLE = 32;
import all_defaults from '../../defaults.json' with { type: 'json' };

export class Finder {
  constructor(customScan, excludeFromScan, electronUpgrade) {
    this.checkErrors = []; // checks that crashed on a file: { file, check, message }
    let candidateChecks = Array.from(CHECKS);

    // init electron-upgrade specific checks given user-provided version numbers
    if (electronUpgrade) {
      const [currentVersion, targetVersion] = electronUpgrade.split('..');
      if (currentVersion && targetVersion) {
        Object.keys(ELECTRON_ATOMIC_UPGRADE_CHECKS).forEach(versionToCheck => {
          if (Number(versionToCheck) > Number(currentVersion) && Number(versionToCheck) <= Number(targetVersion)) {
            candidateChecks = candidateChecks.concat(ELECTRON_ATOMIC_UPGRADE_CHECKS[versionToCheck]);
          }
        });
      } else {
        throw new Error('When specifying the upgrade options please specify your current version and target version like this: x..y (eg 7..8)');
      }
    }

    // if the user is trying to start a custom check scan, we first load all the available checks (candidateChecks) and then we splice those who don't match the user-provided list
    this._enabled_checks = Object.assign(Object.create(candidateChecks), candidateChecks);
    if (customScan && customScan.length > 0) {
      var checksNames = this._enabled_checks.map(check => check.name.toLowerCase());
      if (!customScan.every(r => checksNames.includes(r))) {
        throw new Error('You have an error in your custom checks list. Maybe you misspelt some check names?');
      } else {
        for (let i = this._enabled_checks.length - 1; i >= 0; i--)
          if (!customScan.includes(this._enabled_checks[i].name.toLowerCase()))
            this._enabled_checks.splice(i, 1);
      }
    }

    // the exclusion list has the last word over the list of loaded checks
    if (excludeFromScan && excludeFromScan.length > 0) {
      checksNames = candidateChecks.map(check => check.name.toLowerCase());
      if (!excludeFromScan.every(r => checksNames.includes(r))) {
        throw new Error('You have an error in your custom checks list. Maybe you misspelt some check names?');
      } else {
        for (let i = this._enabled_checks.length - 1; i >= 0; i--)
          if (excludeFromScan.includes(this._enabled_checks[i].name.toLowerCase()))
            this._enabled_checks.splice(i, 1);
      }
    }

    this._checks_by_type = new Map();
    this.init_checks_list();
  }

  get enabled_checks() { return this._enabled_checks; }

  get checks_by_type() { return this._checks_by_type; }

  init_checks_list() {
    for (const type of Object.keys(sourceTypes)) {
      this._checks_by_type.set(sourceTypes[type], []);
    }
    for (const check of this.enabled_checks) {
      const checkInstance = new check();
      this._checks_by_type.get(checkInstance.type).push(checkInstance);
    }
  }

  // Runs one check, isolating its failures: a crash is recorded in checkErrors instead of losing the whole file
  runCheck(check, file, failed, fn) {
    // with --diagnostics, 1 call in SAMPLE is timed and scaled up: timing every call on every node costs a third of
    // the scan time, sampling finds the slow checks all the same
    const collector = diagnostics();
    // counted per check: a shared counter would sample some checks more than others, or never
    const timed = collector && (check.sampleTick = (check.sampleTick || 0) + 1) % SAMPLE === 0;
    const start = timed ? performance.now() : 0;
    try {
      const result = fn();
      if (timed) collector.checkRun(check.constructor.name, (performance.now() - start) * SAMPLE, undefined, undefined, SAMPLE);
      return result;
    } catch (error) {
      this.recordCheckError(check, file, failed, error, collector, start);
      return null;
    }
  }

  async runCheckAsync(check, file, failed, fn) {
    const collector = diagnostics();
    const start = collector ? performance.now() : 0;
    try {
      const result = await fn();
      if (collector) collector.checkRun(check.constructor.name, performance.now() - start);
      return result;
    } catch (error) {
      this.recordCheckError(check, file, failed, error, collector, start);
      return null;
    }
  }

  recordCheckError(check, file, failed, error, collector, start) {
    failed.add(check);
    this.checkErrors.push({ file, check: check.id || check.constructor.name, message: `${check.id || check.constructor.name} failed: ${error && error.message}`, tolerable: false });
    if (collector) collector.checkRun(check.constructor.name, performance.now() - start, error, file);
  }

  async find(file, data, type, content, use_only_checks = null, electronVersion = null) {
    // If the loader didn't detect the Electron version, assume the first one. Not knowing the version, we have to assume the worst (i.e.
    // all options defaulting to insecure values). By always setting the version here, the code in the checkers is simplified as they now
    // don't have to handle the case of unknown versions.
    electronVersion = (electronVersion && coerce(electronVersion)?.version) || '0.1.0';

    const version_of_last_default_change = Object.keys(all_defaults).sort((a, b) => compare(a, b)).reverse().find(current_version => gte(electronVersion, current_version));
    const defaults = all_defaults[version_of_last_default_change];

    const checks = this._checks_by_type.get(type).filter((check) => {
      if (use_only_checks && !use_only_checks.includes(check.id)) {
        return false;
      }
      return true;
    });
    const fileLines = content.toString().split('\n');
    const issues = [];
    // checks that failed on this file: recorded once, then skipped for the rest of the file so the others still run
    const failed = new Set();
    const rootData = data;

    switch (type) {
      case sourceTypes.JAVASCRIPT:
      {
        // nodes enclosing the current one, outermost first, so checks can reason about the surrounding code
        const ancestors = [];
        this.reachability?.collect(file, data, content);
        const context = { ancestors, file, sourceTooling: this.sourceToolingFiles?.has(file) || false };
        setAnalysisContext({ file, program: data.type === 'File' ? data.program : data, index: this.projectIndex, ancestors, propertyName: data.astParser.PropertyName });
        data.astParser.traverseTree(data, {
          enter: (node) => {
            const astNode = rootData.astParser.getNode(node);
            rootData.Scope.updateFunctionScope(astNode, "enter");
            for (const check of checks) {
              if (failed.has(check)) continue;
              const matches = this.runCheck(check, file, failed, () => check.match(astNode, rootData.astParser, rootData.Scope, defaults, electronVersion, context));
              if (matches) {
                // code that runs on one operating system only (if (process.platform === 'darwin'), openOnMac)
                const platform = matches.length ? platformGuard(ancestors, astNode) : undefined;
                // a window that only ever shows the application's own local files: its settings matter less
                const local = matches.length && astNode.type === 'NewExpression' && matches.some(m => WINDOW_SETTINGS.has(m.id)) ? localWindowContent(astNode, ancestors) : undefined;
                for(const m of matches) {
                  const firstLineSample = getSample(fileLines, 0);
                  const matchedLineSample = getSample(fileLines, m.line - 1);
                  const visibility = isDisabledByInlineComment(firstLineSample, matchedLineSample, check, sourceTypes.JAVASCRIPT);
                  const issue = { file, sample: getSample(fileLines, m.line - 1, m.column), context: getContext(fileLines, m.line - 1, m.column), location: {line: m.line, column: m.column}, id: m.id, description: m.description, properties: m.properties, severity: m.severity, confidence: m.confidence, manualReview: m.manualReview, shortenedURL: m.shortenedURL, visibility: visibility, constructorName: check.constructor.name };
                  keepFingerprintLine(issue, matchedLineSample);
                  if (platform && !issue.properties?.platform) issue.properties = { ...issue.properties, platform };
                  if (local && WINDOW_SETTINGS.has(issue.id)) lowerForLocalWindow(issue, local);
                  this.reachability?.anchor(issue, file, astNode);
                  issues.push(issue);
                }
              }
            }
            ancestors.push(astNode);
          },
          leave: (node) => {
            ancestors.pop();
            rootData.Scope.updateFunctionScope(rootData.astParser.getNode(node), "leave");
          }
        });

        break;
      }
      case sourceTypes.HTML:
        // inline <script> blocks go through the JavaScript checks, at their position in the HTML file
        for (const script of inlineScripts(content.toString())) {
          let scriptData;
          try {
            this.scriptParser ??= new Parser(false, true);
            [, scriptData] = this.scriptParser.parse(`${file}.inline.js`, script);
          } catch {
            continue; // templates ({{ }}, <%= %>) and other non-JavaScript content
          }
          if (scriptData) issues.push(...await this.find(file, scriptData, sourceTypes.JAVASCRIPT, content, use_only_checks, electronVersion));
        }
        for (const check of checks) {
          const matches = this.runCheck(check, file, failed, () => check.match(data, content, defaults, electronVersion));
          if(matches){
            for(const m of matches) {
              const firstLineSample = getSample(fileLines, 0);
              const matchedLineSample = getSample(fileLines, m.line - 1);
              const visibility = isDisabledByInlineComment(firstLineSample, matchedLineSample, check, sourceTypes.HTML);
              const issue = {file, sample: getSample(fileLines, m.line - 1, m.column), context: getContext(fileLines, m.line - 1, m.column), location: {line: m.line, column: m.column}, id: m.id, description: m.description, properties: m.properties, severity: m.severity, confidence: m.confidence, manualReview: m.manualReview, shortenedURL: m.shortenedURL, visibility: visibility, constructorName: check.constructor.name };
              keepFingerprintLine(issue, matchedLineSample);
              issues.push(issue);
            }
          }
        }
        break;
      case sourceTypes.JSON:
      case sourceTypes.LOCKFILE:
        for (const check of checks) {
          const matches = await this.runCheckAsync(check, file, failed, () => check.match(data, defaults, electronVersion));
          if (matches) {
            for(const m of matches) {
              const sample = getSample(fileLines, m.line - 1, m.column);
              const issue = {file, sample, context: getContext(fileLines, m.line - 1, m.column), location: {line: m.line, column: m.column}, id: m.id, description: m.description, properties: m.properties, severity: m.severity, confidence: m.confidence, manualReview: m.manualReview, shortenedURL: m.shortenedURL, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: check.constructor.name };
              keepFingerprintLine(issue, getSample(fileLines, m.line - 1));
              issues.push(issue);
            }
          }
        }
    }

    return issues;
  }
}

const JAVASCRIPT_TYPES = /^(|text\/javascript|application\/javascript|module|text\/ecmascript|application\/ecmascript)$/i;

/**
 * The inline scripts of an HTML document, each as a copy of the document where everything but the script is blanked
 * out (newlines kept), so line and column numbers of findings point into the HTML file.
 */
export function inlineScripts(html) {
  const scripts = [];
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    const attributes = match[1];
    if (/\bsrc\s*=/i.test(attributes)) continue;
    const type = (attributes.match(/\btype\s*=\s*["']?([^"'\s>]*)/i) || [])[1] || '';
    if (!JAVASCRIPT_TYPES.test(type.trim()) || !match[2].trim()) continue;
    const start = match.index + match[0].indexOf('>') + 1;
    const end = start + match[2].length;
    const blank = (text) => text.replace(/[^\n]/g, ' ');
    scripts.push(blank(html.slice(0, start)) + html.slice(start, end) + blank(html.slice(end)));
  }
  return scripts;
}
