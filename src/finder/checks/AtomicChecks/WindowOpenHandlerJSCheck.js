import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, isFunction, resolveIdentifier, findProperty, literalValue, visit, finding } from '../helpers.js';

// webPreferences that must not be relaxed for windows opened by web content
const INSECURE_OVERRIDES = { nodeIntegration: true, nodeIntegrationInSubFrames: true, sandbox: false, contextIsolation: false, webSecurity: false, allowRunningInsecureContent: true, webviewTag: true };

// Electron security checklist #14: disable or limit creation of new windows
export default class WindowOpenHandlerJSCheck {
  constructor() {
    this.id = "WINDOW_OPEN_HANDLER_JS_CHECK";
    this.description = __("WINDOW_OPEN_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#14-disable-or-limit-creation-of-new-windows";
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (memberName(astNode.callee) !== 'setWindowOpenHandler' || astNode.arguments.length === 0) return null;

    const handler = resolveIdentifier(astNode.arguments[0], scope);
    if (!isFunction(handler)) return null;

    const issues = [];
    visit(handler.body || handler, (node) => {
      if (node.type !== 'ObjectExpression') return true;
      const action = findProperty(node, 'action');
      if (!action || literalValue(action[1]) !== 'allow') return true;

      const overrides = findProperty(node, 'overrideBrowserWindowOptions');
      const prefs = overrides && findProperty(resolveIdentifier(overrides[1], scope), 'webPreferences');
      const relaxed = prefs ? Object.entries(INSECURE_OVERRIDES)
        .filter(([key, bad]) => { const p = findProperty(resolveIdentifier(prefs[1], scope), key); return p && literalValue(p[1]) === bad; })
        .map(([key, bad]) => `${key}: ${bad}`) : [];

      if (relaxed.length > 0) {
        issues.push(finding(this, node, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false,
          description: `${this.description} (new windows are created with ${relaxed.join(', ')})`, properties: { relaxed } }));
      } else {
        issues.push(finding(this, node, { severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }));
      }
      return false;
    });
    return issues;
  }
}
