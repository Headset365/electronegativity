import { CHECKS } from './checks/AtomicChecks/index.js';
import { sourceTypes } from '../parser/types.js';
import { ELECTRON_ATOMIC_UPGRADE_CHECKS } from './checks/AtomicChecks/ElectronAtomicUpgradeChecks.js';
import { isDisabledByInlineComment } from "../util/exceptions.js";
import { getSample } from "../util/file.js";
import chalk from 'chalk';
import { gte, compare, coerce } from 'semver';
import { setAnalysisContext } from './checks/analysis.js';
import all_defaults from '../../defaults.json' with { type: 'json' };

export class Finder {
  constructor(customScan, excludeFromScan, electronUpgrade) {
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
        console.error(chalk.red(`When specifying the upgrade options please specify your current version and target version like this: x..y (eg 7..8)`));
        process.exit(1);
      }
    }

    // if the user is trying to start a custom check scan, we first load all the available checks (candidateChecks) and then we splice those who don't match the user-provided list
    this._enabled_checks = Object.assign(Object.create(candidateChecks), candidateChecks);
    if (customScan && customScan.length > 0) {
      var checksNames = this._enabled_checks.map(check => check.name.toLowerCase());
      if (!customScan.every(r => checksNames.includes(r))) {
        console.error(chalk.red(`You have an error in your custom checks list. Maybe you misspelt some check names?`));
        process.exit(1);
      } else {
        for (let i = this._enabled_checks.length - 1; i >= 0; i--)
          if (!customScan.includes(this._enabled_checks[i].name.toLowerCase()))
            this._enabled_checks.splice(i, 1);
      }
    }

    // the exclusion list has the last word over the list of loaded checks
    if (excludeFromScan && excludeFromScan.length > 0) {
      checksNames = this._enabled_checks.map(check => check.name.toLowerCase());
      if (!excludeFromScan.every(r => checksNames.includes(r))) {
        console.error(chalk.red(`You have an error in your custom checks list. Maybe you misspelt some check names?`));
        process.exit(1);
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
    const rootData = data;

    switch (type) {
      case sourceTypes.JAVASCRIPT:
      {
        // nodes enclosing the current one, outermost first, so checks can reason about the surrounding code
        const ancestors = [];
        const context = { ancestors, file };
        setAnalysisContext({ file, program: data.type === 'File' ? data.program : data, index: this.projectIndex, ancestors });
        data.astParser.traverseTree(data, {
          enter: (node) => {
            const astNode = rootData.astParser.getNode(node);
            rootData.Scope.updateFunctionScope(astNode, "enter");
            for (const check of checks) {
              const matches = check.match(astNode, rootData.astParser, rootData.Scope, defaults, electronVersion, context);
              if (matches) {
                for(const m of matches) {
                  const firstLineSample = getSample(fileLines, 0);
                  const matchedLineSample = getSample(fileLines, m.line - 1);
                  const visibility = isDisabledByInlineComment(firstLineSample, matchedLineSample, check, sourceTypes.JAVASCRIPT);
                  const issue = { file, sample: matchedLineSample, location: {line: m.line, column: m.column}, id: m.id, description: m.description, properties: m.properties, severity: m.severity, confidence: m.confidence, manualReview: m.manualReview, shortenedURL: m.shortenedURL, visibility: visibility, constructorName: check.constructor.name };
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
        for (const check of checks) {
          const matches = check.match(data, content, defaults, electronVersion);
          if(matches){
            for(const m of matches) {
              const firstLineSample = getSample(fileLines, 0);
              const matchedLineSample = getSample(fileLines, m.line - 1);
              const visibility = isDisabledByInlineComment(firstLineSample, matchedLineSample, check, sourceTypes.HTML);
              const issue = {file, sample: matchedLineSample, location: {line: m.line, column: m.column}, id: m.id, description: m.description, properties: m.properties, severity: m.severity, confidence: m.confidence, manualReview: m.manualReview, shortenedURL: m.shortenedURL, visibility: visibility, constructorName: check.constructor.name };
              issues.push(issue);
            }
          }
        }
        break;
      case sourceTypes.JSON:
      case sourceTypes.LOCKFILE:
        for (const check of checks) {
          const matches = await check.match(data, defaults, electronVersion);
          if (matches) {
            for(const m of matches) {
              const sample = getSample(fileLines, m.line - 1);
              const issue = {file, sample, location: {line: m.line, column: m.column}, id: m.id, description: m.description, properties: m.properties, severity: m.severity, confidence: m.confidence, manualReview: m.manualReview, shortenedURL: m.shortenedURL, visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: check.constructor.name };
              issues.push(issue);
            }
          }
        }
    }

    return issues;
  }
}
