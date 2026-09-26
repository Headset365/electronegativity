import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, resolveIdentifier, findProperty, literalValue, visit, finding } from '../helpers.js';
import { isConditional, hasUrlValidation, handlerFunction } from '../analysis.js';

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

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (memberName(astNode.callee) !== 'setWindowOpenHandler' || astNode.arguments.length === 0) return null;

    const handler = handlerFunction(astNode.arguments[0], scope, context.ancestors);
    if (!handler) return null;

    const issues = [];
    // arrow functions returning the object directly: () => ({ action: 'allow' })
    visit(handler.body || handler, (node, parents) => {
      if (node.type !== 'ObjectExpression') return true;
      const ancestors = [handler, ...parents];
      const action = findProperty(node, 'action');
      if (!action || literalValue(action[1]) !== 'allow') return true;

      const overrides = findProperty(node, 'overrideBrowserWindowOptions');
      const prefs = overrides && findProperty(resolveIdentifier(overrides[1], scope), 'webPreferences');
      const relaxed = prefs ? Object.entries(INSECURE_OVERRIDES)
        .filter(([key, bad]) => { const p = findProperty(resolveIdentifier(prefs[1], scope), key); return p && literalValue(p[1]) === bad; })
        .map(([key, bad]) => `${key}: ${bad}`) : [];

      if (relaxed.length > 0) {
        issues.push(finding(this, node, { severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false,
          description: `${this.description} (new windows are created with ${relaxed.join(', ')})`, properties: { relaxed } }));
      } else if (!isConditional(node, ancestors, handler)) {
        issues.push(finding(this, node, { severity: severity.HIGH, confidence: confidence.CERTAIN, manualReview: false,
          description: `${this.description} (every URL is allowed to open a new window)` }));
      } else if (hasUrlValidation(handler)) {
        issues.push(finding(this, node, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
          description: `${this.description} (allowed after checking the URL; review the allowlist)` }));
      } else {
        issues.push(finding(this, node, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
          description: `${this.description} (allowed under a condition that doesn't inspect the URL)` }));
      }
      return false;
    });
    return issues;
  }
}
