import chalk from 'chalk';
import { severity, confidence } from '../../attributes.js';
import { queryNpmAdvisories } from '../../../util/osv.js';

const MAX_LISTED_ADVISORIES = 5;

// Known vulnerabilities in the npm packages locked by the application (Electron itself is covered by AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK)
export default class DependencyVulnerabilitiesGlobalCheck {
  constructor() {
    this.id = "DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK";
    this.description = __("DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK");
    this.depends = ["DependencyInventoryLockCheck"];
    this.shortenedURL = "https://osv.dev";
  }

  async perform(issues, output) {
    const byKey = new Map();
    for (const issue of issues) {
      for (const pkg of (issue.properties && issue.properties.packages) || []) {
        if (pkg.name === 'electron') continue;
        const key = `${pkg.name}@${pkg.version}`;
        if (!byKey.has(key)) byKey.set(key, { ...pkg, file: issue.file });
      }
    }
    const packages = [...byKey.values()];
    if (packages.length === 0) return [];

    let advisories;
    try {
      advisories = await queryNpmAdvisories(packages);
    } catch (e) {
      if (!output && !e.offline) console.log(chalk.yellow(`Something went wrong while fetching dependency advisories (${e.message}). No connectivity?`));
      return [];
    }

    const results = [];
    packages.forEach((pkg, i) => {
      const ids = advisories[i];
      if (ids.length === 0) return;
      const listed = ids.slice(0, MAX_LISTED_ADVISORIES).join(', ') + (ids.length > MAX_LISTED_ADVISORIES ? ', ...' : '');
      results.push({
        file: pkg.file,
        location: { line: pkg.line || 1, column: 0 },
        id: this.id,
        description: `${this.description}: ${pkg.name}@${pkg.version}${pkg.dev ? ' (dev)' : ''} (${ids.length}: ${listed})`,
        properties: { package: pkg.name, version: pkg.version, dev: !!pkg.dev, advisories: ids },
        shortenedURL: `https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(pkg.name)}`,
        severity: pkg.dev ? severity.LOW : severity.MEDIUM,
        confidence: confidence.CERTAIN,
        manualReview: false
      });
    });
    return results;
  }
}
