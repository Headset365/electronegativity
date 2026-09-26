import { sourceTypes } from '../../../../parser/types.js';
import { severity, confidence } from '../../../attributes.js';
import { isWindowConstructor } from '../../helpers.js';

export default class BrowserWindowWebPreferences {
  constructor() {
    this.id = "BROWSER_WINDOW_WEB_PREFERENCES_DEPRECATION";
    this.description = __("BROWSER_WINDOW_WEB_PREFERENCES_DEPRECATION");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/breaking-changes';
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'NewExpression') return null;
    if (!isWindowConstructor(astNode)) return null; // also new electron.BrowserWindow() and minified new o.BrowserWindow()
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
  }
}