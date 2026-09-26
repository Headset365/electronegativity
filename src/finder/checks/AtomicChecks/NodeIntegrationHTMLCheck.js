import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class NodeIntegrationHTMLCheck {
  constructor() {
    this.id = "NODE_INTEGRATION_HTML_CHECK";
    this.description = __("NODE_INTEGRATION_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#2-do-not-enable-nodejs-integration-for-remote-content";
  }

  match(cheerioObj, content) {
    const loc = [];
    const webviews = cheerioObj('webview');
    const self = this;
    webviews.each(function (i, elem) {
      const nodeintegration = cheerioObj(this).attr('nodeintegration');
      const nodeintegrationInSubframes = cheerioObj(this).attr('nodeintegrationinsubframes');

      if (nodeintegration !== undefined || nodeintegrationInSubframes !== undefined) {
        loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false });
      }
    });
    return loc;
  }
}
