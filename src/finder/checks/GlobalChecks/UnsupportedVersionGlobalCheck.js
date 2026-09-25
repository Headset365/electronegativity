import chalk from 'chalk';
import { major, coerce, valid, gt } from 'semver';
import { severity, confidence } from '../../attributes.js';
import { getStableReleases, supportedMajors } from '../../../util/electron_releases.js';

// Electron only ships security fixes for its latest three stable major versions
export default class UnsupportedVersionGlobalCheck {
  constructor() {
    this.id = "UNSUPPORTED_VERSION_GLOBAL_CHECK";
    this.description = { END_OF_LIFE: __("UNSUPPORTED_VERSION_GLOBAL_CHECK_END_OF_LIFE"), PATCH_AVAILABLE: __("AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK_OUTDATED_VERSION") };
    this.depends = ["ElectronVersionJSONCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/electron-timelines";
  }

  // stable Electron versions, newest first (overridable in tests)
  getReleases() {
    return getStableReleases();
  }

  async perform(issues, output) {
    const versionIssues = issues.filter(e => e.id === 'ELECTRON_VERSION_JSON_CHECK');
    if (versionIssues.length === 0) return [];

    let releases;
    try {
      releases = await this.getReleases();
    } catch (e) {
      if (!output && !e.offline) console.log(chalk.yellow(`Something went wrong while fetching Electron's releases (${e.message}). No connectivity?`));
      return [];
    }
    const supported = supportedMajors(releases);
    const oldestSupported = Math.min(...supported);

    const results = [];
    for (const issue of versionIssues) {
      const version = coerce(issue.properties.versionNumber);
      if (!version) continue;
      const base = { file: issue.file, location: { line: 0, column: 0 }, id: this.id, shortenedURL: this.shortenedURL, confidence: confidence.CERTAIN, manualReview: issue.manualReview };

      if (major(version) < oldestSupported) {
        results.push({ ...base, severity: severity.HIGH,
          description: `${this.description.END_OF_LIFE}: Electron ${major(version)} (supported: ${supported.join(', ')})`,
          properties: { versionNumber: version.version, supported } });
        continue;
      }

      // a newer patch only matters when the version is pinned, a range picks it up on install
      const spec = issue.properties.versionSpec;
      if (spec && valid(spec)) {
        const latestPatch = releases.find(v => major(v) === major(version));
        if (latestPatch && gt(latestPatch, version)) {
          results.push({ ...base, severity: severity.LOW,
            description: `${this.description.PATCH_AVAILABLE}: ${version.version} -> ${latestPatch}`,
            properties: { versionNumber: version.version, latest: latestPatch } });
        }
      }
    }
    return results;
  }
}
