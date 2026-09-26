import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class CSPHTMLCheck {
  constructor() {
    this.id = "CSP_HTML_CHECK";
    this.description = __("CSP_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/CSP_HTML_CHECK";
  }

  match(cheerioObj, content) {
    const loc = [];
    const metaTags = cheerioObj('meta');
    const self = this;
    metaTags.each(function (i, elem) {  
      const httpEquiv = cheerioObj(this).attr('http-equiv');
      const cspContent = cheerioObj(this).attr('content');
      if (httpEquiv && httpEquiv.toLowerCase() === "Content-Security-Policy".toLowerCase()) {
        loc.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.INFORMATIONAL, confidence: confidence.TENTATIVE, properties: { "CSPstring": cspContent }, manualReview: true });
      }
    });
    return loc;
  }
}
