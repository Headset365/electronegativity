import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { parseWebPreferencesFeaturesString } from '../../../util/index.js';

export default class InsecureContentHTMLCheck {
  constructor() {
    this.id = "INSECURE_CONTENT_HTML_CHECK";
    this.description = __("INSECURE_CONTENT_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#8-do-not-enable-allowrunninginsecurecontent";
  }

  match(cheerioObj, content) {
    const loc = [];
    const webviews = cheerioObj('webview');
    const self = this;
    webviews.each(function (i, elem) {
      let wp = cheerioObj(this).attr('webpreferences');
      if (wp) {
        let features = parseWebPreferencesFeaturesString(wp);
        if (features['allowRunningInsecureContent'] === true)
          loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: false });
      }

    });
    return loc;
  }
}
