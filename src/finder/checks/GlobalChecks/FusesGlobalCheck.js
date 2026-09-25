import { severity, confidence } from '../../attributes.js';

export default class FusesGlobalCheck {
  constructor() {
    this.id = "FUSES_GLOBAL_CHECK";
    this.description = __("FUSES_GLOBAL_CHECK");
    this.depends = ["FusesJSCheck", "FusesJSONCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/fuses";
  }

  async perform(issues) {
    const isMarker = (issue) => issue.properties && (issue.properties.fusesConfigured || issue.properties.packagerConfig);
    const configured = issues.some(issue => issue.properties && issue.properties.fusesConfigured);
    if (!configured) {
      const packagers = issues.filter(issue => issue.properties && issue.properties.packagerConfig);
      if (packagers.length > 0) {
        // the packaging configuration was analyzed and doesn't flip any fuse
        return [{ file: packagers[0].file, location: { line: 1, column: 0 }, id: this.id, description: `${this.description} (${packagers[0].properties.packagerConfig})`, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: false }];
      }
      // no packaging configuration found: fuses may be flipped by a script that isn't analyzed
      return [{ file: "N/A", location: { line: 0, column: 0 }, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
    }
    // only the actual problems, the markers are not interesting on their own
    return issues.filter(issue => !isMarker(issue));
  }
}
