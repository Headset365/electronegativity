import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { finding } from '../helpers.js';
import { constantValue } from '../analysis.js';

const URL = "https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#sandbox";

// With both flags the framed page can remove its own sandbox, so it is as good as none
const isEffective = (sandbox) => !(/\ballow-scripts\b/i.test(sandbox) && /\ballow-same-origin\b/i.test(sandbox));

// Frames showing documents or user content without the sandbox attribute can script the embedding page, and through it
// reach preload APIs or, with nodeIntegration, Node.js itself (e.g. Joplin's note viewer, CVE-2022-35131)
function assess(sandbox) {
  if (sandbox === undefined) return 'the iframe has no sandbox attribute';
  if (typeof sandbox === 'string' && !isEffective(sandbox)) return 'sandbox allows both allow-scripts and allow-same-origin, which lets the frame remove it';
  return undefined;
}

export class IframeSandboxHTMLCheck {
  constructor() {
    this.id = "IFRAME_SANDBOX_HTML_CHECK";
    this.description = __("IFRAME_SANDBOX_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = URL;
  }

  match(cheerioObj, content) {
    const locations = [];
    const self = this;
    cheerioObj('iframe').each(function (i, elem) {
      const problem = assess(cheerioObj(this).attr('sandbox'));
      if (problem) locations.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: `${self.description} (${problem})`,
        shortenedURL: self.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true });
    });
    return locations;
  }
}

// <iframe src={...} /> in React and other JSX renderers
export class IframeSandboxJSCheck {
  constructor() {
    this.id = "IFRAME_SANDBOX_JS_CHECK";
    this.description = __("IFRAME_SANDBOX_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = URL;
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'JSXOpeningElement' || !astNode.name || astNode.name.name !== 'iframe') return null;
    // {...props} may carry the attribute
    if (astNode.attributes.some(a => a.type === 'JSXSpreadAttribute')) return null;
    const attribute = astNode.attributes.find(a => a.name && a.name.name === 'sandbox');
    let sandbox;
    if (attribute) {
      const value = attribute.value && (attribute.value.type === 'JSXExpressionContainer' ? attribute.value.expression : attribute.value);
      sandbox = value ? constantValue(value, scope) : '';
      if (sandbox === undefined) return null; // dynamic, can't tell
    }
    const problem = assess(sandbox);
    return problem ? [finding(this, astNode, { severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true, description: `${this.description} (${problem})` })] : null;
  }
}
