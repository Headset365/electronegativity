import { valid, coerce } from 'semver';
import chalk from 'chalk';
import { severity, confidence } from '../../attributes.js';
import { queryNpmAdvisories } from '../../../util/osv.js';

// Electron's own release feed (github.com/electron/releases) stopped being updated in 2022, so known vulnerabilities are
// looked up in the OSV database (https://osv.dev), which mirrors the GitHub Security Advisories published for the `electron` npm package.
const MAX_LISTED_ADVISORIES = 5;

export default class AvailableSecurityFixesGlobalCheck {

  constructor() {
    this.id = "AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK";
    this.description = { SECURITY_ISSUES : __('AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK_SECURITY_ISSUES'),
      OUTDATED_VERSION :  __('AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK_OUTDATED_VERSION')};
    this.depends = ["ElectronVersionJSONCheck"];
    this.shortenedURL = "https://github.com/electron/electron/security/advisories";
  }

  async perform(issues, output) {
    const versionCheckIssues = issues.filter(e => e.id === 'ELECTRON_VERSION_JSON_CHECK');
    const otherIssues = issues.filter(e => e.id !== 'ELECTRON_VERSION_JSON_CHECK');

    if (versionCheckIssues.length === 0) return otherIssues;

    const versions = [...new Set(versionCheckIssues.map(issue => this.normalizeVersion(issue.properties.versionNumber)).filter(Boolean))];
    const advisories = await this.fetchAdvisories(versions, output);
    if (!advisories) return otherIssues;

    for (const issue of versionCheckIssues) {
      const ids = advisories.get(this.normalizeVersion(issue.properties.versionNumber));
      if (!ids || ids.length === 0) continue;

      const listed = ids.slice(0, MAX_LISTED_ADVISORIES).join(', ') + (ids.length > MAX_LISTED_ADVISORIES ? ', ...' : '');
      otherIssues.push({
        file: issue.file,
        location: { line: 0, column: 0 },
        id: this.id,
        description: `${this.description.SECURITY_ISSUES} (${ids.length}: ${listed})`,
        properties: { versionNumber: issue.properties.versionNumber, advisories: ids },
        shortenedURL: this.shortenedURL,
        // Electron is usually a devDependency, as packagers bundle it into the app, so both are equally relevant
        severity: severity.HIGH,
        confidence: confidence.CERTAIN,
        manualReview: issue.manualReview
      });
    }

    return otherIssues;
  }

  normalizeVersion(version) {
    if (valid(version)) return version;
    const coerced = coerce(version);
    return coerced ? coerced.version : undefined;
  }

  // Returns a Map version -> [advisory ids], or undefined if the lookup failed
  async fetchAdvisories(versions, output) {
    if (versions.length === 0) return new Map();
    try {
      const results = await queryNpmAdvisories(versions.map(version => ({ name: 'electron', version })), { timeout: 15000 });
      return new Map(versions.map((version, i) => [version, results[i]]));
    } catch (e) {
      if (!output && !e.offline)
        console.log(chalk.yellow(`Something went wrong while fetching Electron's security advisories (${e.message}). No connectivity?`));
      return undefined;
    }
  }
}
