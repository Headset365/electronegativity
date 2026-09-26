import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class AllowPopupsHTMLCheck {
  constructor() {
    this.id = "ALLOWPOPUPS_HTML_CHECK";
    this.description = __("ALLOWPOPUPS_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#11-do-not-use-allowpopups-for-webviews";
  }

  match(cheerioObj, content) {
    const loc = [];
    const webviews = cheerioObj('webview');
    const self = this;
    webviews.each(function (i, elem) {
      const allowpopups = cheerioObj(this).attr('allowpopups');
      if (allowpopups !== undefined) {
        loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: false });
      }

    });
    return loc;
  }
}
