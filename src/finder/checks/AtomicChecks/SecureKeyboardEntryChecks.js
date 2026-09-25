import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue, finding } from '../helpers.js';

// macOS Secure Keyboard Entry keeps other processes from intercepting keystrokes (e.g. passwords typed into the app)
export class SecureKeyboardEntryJSCheck {
  constructor() {
    this.id = "SECUREKEYBOARDENTRY_JS_CHECK";
    this.description = __("SECUREKEYBOARDENTRY_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/app#appsetsecurekeyboardentryenabledenabled-macos";
  }

  match(astNode) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (memberName(astNode.callee) !== 'setSecureKeyboardEntryEnabled') return null;
    const enabled = literalValue(astNode.arguments[0]);
    return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: enabled !== true,
      properties: { secureKeyboardEntry: enabled } })];
  }
}

export class SecureKeyboardEntryHTMLCheck {
  constructor() {
    this.id = "SECUREKEYBOARDENTRY_HTML_CHECK";
    this.description = __("SECUREKEYBOARDENTRY_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/app#appsetsecurekeyboardentryenabledenabled-macos";
  }

  match(cheerioObj, content) {
    const issues = [];
    const self = this;
    cheerioObj('input[type="password" i]').each(function (i, elem) {
      issues.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: false, properties: { passwordField: true } });
    });
    return issues;
  }
}
