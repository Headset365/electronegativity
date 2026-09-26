import { severity, confidence } from '../../attributes.js';

export default class PermissionRequestHandlerGlobalCheck {

  constructor() {
    this.id = "PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK";
    this.description = { NONE_FOUND: __('PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK')};
    this.depends = ["PermissionRequestHandlerJSCheck"];
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK";
  }

  async perform(issues) {

    if (issues.length === 0) {
      return [{ file: "N/A", location: {line: 0, column: 0}, id: this.id, description: this.description.NONE_FOUND, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: false }];
    } else {
      // a handler exists: only keep what the handler analysis found worth reporting
      issues.filter(e => !(e.properties && e.properties.assessed) || e.severity.value === severity.INFORMATIONAL.value)
        .forEach(e => e.visibility.globalCheckDisabled = true);
      return issues;
    }
  }
}
