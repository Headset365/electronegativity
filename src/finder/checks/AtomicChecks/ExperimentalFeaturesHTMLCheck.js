import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { parseWebPreferencesFeaturesString } from '../../../util/index.js';

export default class ExperimentalFeaturesHTMLCheck {
  constructor() {
    this.id = "EXPERIMENTAL_FEATURES_HTML_CHECK";
    this.description = __("EXPERIMENTAL_FEATURES_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#9-do-not-enable-experimental-features";
  }

  match(cheerioObj, content) {
    const loc = [];
    const webviews = cheerioObj('webview');
    const self = this;
    webviews.each(function (i, elem) {
      let wp = cheerioObj(this).attr('webpreferences');
      if (wp) {
        let features = parseWebPreferencesFeaturesString(wp);
        if (features['experimentalFeatures'] === true || features['experimentalCanvasFeatures'] === true)
          loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: false });
      }

    });
    return loc;
  }
}
