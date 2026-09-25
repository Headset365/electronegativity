import { severity, confidence } from '../../attributes.js';

export default class WebviewGlobalCheck {
  constructor() {
    this.id = "WEBVIEW_GLOBAL_CHECK";
    this.description = __("WEBVIEW_GLOBAL_CHECK");
    this.depends = ["WebviewTagJSCheck"];
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#12-verify-webview-options-before-creation";
  }

  async perform(issues) {
    const enabled = issues.filter(issue => issue.properties && issue.properties.event === 'webviewTag');
    const hardened = issues.filter(issue => issue.properties && issue.properties.event === 'will-attach-webview');
    if (enabled.length === 0) return []; // <webview> is disabled, will-attach-webview handlers are irrelevant

    if (hardened.length === 0) {
      return [...enabled, { file: enabled[0].file, location: enabled[0].location, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false }];
    }
    return [...enabled, ...hardened];
  }
}
