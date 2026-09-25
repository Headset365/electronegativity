import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class HTTPResourcesHTMLCheck {
  constructor() {
    this.id = "HTTP_RESOURCES_HTML_CHECK";
    this.description = __("HTTP_RESOURCES_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://git.io/JeuMt";
  }

  match(cheerioObj, content) {
    const loc = [];
    const self = this;
    // elements loading active content (scripts, styles, frames, plugins) and where they take the URL from
    const sources = [['webview', 'src'], ['script', 'src'], ['iframe', 'src'], ['frame', 'src'], ['embed', 'src'], ['object', 'data'], ['link', 'href']];
    for (const [tag, attribute] of sources) {
      cheerioObj(tag).each(function (i, elem) {
        const url = cheerioObj(this).attr(attribute);
        if (tag === 'link' && !/(^|\s)(stylesheet|preload|modulepreload|import|prefetch)(\s|$)/i.test(cheerioObj(this).attr('rel') || '')) return;
        if (url && url.trim().toUpperCase().startsWith("HTTP://")) {
          loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: `${self.description} (<${tag}> ${url.trim()})`, shortenedURL: self.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: false });
        }
      });
    }
    return loc;
  }
}
