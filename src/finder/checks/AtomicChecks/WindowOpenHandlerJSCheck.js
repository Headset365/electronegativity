import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, resolveIdentifier, findProperty, literalValue, visit, finding } from '../helpers.js';
import { isConditional, hasUrlValidation, handlerFunction, currentAnalysisContext } from '../analysis.js';

// webPreferences that must not be relaxed for windows opened by web content
const INSECURE_OVERRIDES = { nodeIntegration: true, nodeIntegrationInSubFrames: true, sandbox: false, contextIsolation: false, webSecurity: false, allowRunningInsecureContent: true, webviewTag: true };

// a handler that decides through a helper: isAllowedUrl(url) ? { action: 'allow' } : { action: 'deny' }
function handlerChecksUrl(handler) {
  let found = false;
  visit(handler.body || handler, (node) => {
    if ((node.type === 'CallExpression' || node.type === 'OptionalCallExpression') && node.callee.type === 'Identifier' && /allow|trust|valid|safe|check|permit|whitelist|allowlist/i.test(node.callee.name)) found = true;
    return !found;
  });
  return found;
}

// whether the app gives any window a preload script (which windows it opens then inherit)
function appUsesPreload() {
  const { index, program } = currentAnalysisContext();
  if (index && typeof index.filesMentioning === 'function') return index.filesMentioning('preload').length > 0;
  let found = false;
  visit(program, (node) => { if (!found && (node.type === 'ObjectProperty' || node.type === 'Property') && (node.key.name === 'preload' || node.key.value === 'preload')) found = true; return !found; });
  return found;
}

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
      } else if (hasUrlValidation(handler) || handlerChecksUrl(handler)) {
        // an allowed window is created with the opener's webPreferences, its preload script included: every API the
        // preload exposes (credentials, file access) reaches the new page unless overrideBrowserWindowOptions says otherwise
        const inherits = !overrides && appUsesPreload();
        issues.push(finding(this, node, { severity: inherits ? severity.MEDIUM : severity.LOW, confidence: confidence.FIRM, manualReview: true,
          properties: { inheritsPreload: inherits },
          description: `${this.description} (allowed after checking the URL; review the allowlist${inherits ? '. Allowed windows inherit the opening window\'s preload script and the APIs it exposes, as no overrideBrowserWindowOptions replaces it' : ''})` }));
      } else {
        issues.push(finding(this, node, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
          description: `${this.description} (allowed under a condition that doesn't inspect the URL)` }));
      }
      return false;
    });
    return issues;
  }
}
