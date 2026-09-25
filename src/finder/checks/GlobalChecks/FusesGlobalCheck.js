import { severity, confidence } from '../../attributes.js';

export default class FusesGlobalCheck {
  constructor() {
    this.id = "FUSES_GLOBAL_CHECK";
    this.description = __("FUSES_GLOBAL_CHECK");
    this.depends = ["FusesJSCheck", "FusesJSONCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/fuses";
  }

  async perform(issues) {
    const configured = issues.some(issue => issue.properties && issue.properties.fusesConfigured);
    if (!configured) {
      // fuses may also be flipped by a script or a YAML config that isn't analyzed, hence the manual review
      return [{ file: "N/A", location: { line: 0, column: 0 }, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
    }
    // only the actual problems, the "configured" markers are not interesting on their own
    return issues.filter(issue => !(issue.properties && issue.properties.fusesConfigured));
  }
}
