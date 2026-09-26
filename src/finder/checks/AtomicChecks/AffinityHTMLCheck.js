import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { electronAtLeast, ELECTRON_CHANGES } from '../versions.js';
import { parseWebPreferencesFeaturesString } from '../../../util/index.js';

export default class AffinityHTMLCheck {
  constructor() {
    this.id = "AFFINITY_HTML_CHECK";
    this.description = __("AFFINITY_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/breaking-changes#removed-browser-window-affinity";
  }

  match(cheerioObj, content, defaults, electronVersion) {
    // the affinity option was removed in Electron 14
    if (electronAtLeast(electronVersion, ELECTRON_CHANGES.AFFINITY_REMOVED)) return null;
    const loc = [];
    const webviews = cheerioObj('webview');
    const self = this;
    webviews.each(function (i, elem) {
      let wp = cheerioObj(this).attr('webpreferences');
      if (wp) {
        let features = parseWebPreferencesFeaturesString(wp);
        if (features['affinity'] !== undefined)
          loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, properties: { "AffinityString": features['affinity']}, manualReview: true });
      }

    });
    return loc;
  }
}