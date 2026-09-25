import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { handlerFunction, callbackAnswers, returnedValues, constantValue, isConditional, hasUrlValidation, visit, isMember } from '../analysis.js';

// Handlers deciding permissions for web content, and where they receive the decision
const HANDLERS = {
  setPermissionRequestHandler: { callbackIndex: 2 },   // (webContents, permission, callback, details)
  setPermissionCheckHandler: { returns: true },        // (webContents, permission, requestingOrigin, details) => boolean
  setDevicePermissionHandler: { returns: true },       // (details) => boolean
};

// References that show the handler looks at who is asking
const ORIGIN_REFERENCES = /^(getURL|requestingUrl|requestingOrigin|securityOrigin|origin|embeddingOrigin|url)$/;

// Electron security checklist #5: handle session permission requests from remote content
export default class PermissionRequestHandlerJSCheck {
  constructor() {
    this.id = "PERMISSION_REQUEST_HANDLER_JS_CHECK";
    this.description = __("PERMISSION_REQUEST_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#5-handle-session-permission-requests-from-remote-content";
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    const method = memberName(astNode.callee);
    const spec = HANDLERS[method];
    if (!spec) return null;

    const properties = { handler: method, assessed: true };
    const report = (sev, conf, reason, manualReview = true) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, description: `${this.description}: ${method} ${reason}`, properties })];

    if (astNode.arguments.length === 0 || astNode.arguments[0].type === 'NullLiteral' || constantValue(astNode.arguments[0], scope) === null) {
      return report(severity.INFORMATIONAL, confidence.CERTAIN, 'resets the handler to the default', false);
    }
    const fn = handlerFunction(astNode.arguments[0], scope);
    if (!fn) {
      properties.assessed = false;
      return report(severity.MEDIUM, confidence.TENTATIVE, 'uses a handler defined elsewhere; review it');
    }

    const grant = spec.returns ? returnAnswers(fn, scope) : callbackAnswers(fn, spec.callbackIndex, true, scope);
    if (grant.always) return report(severity.HIGH, confidence.CERTAIN, 'grants every permission to every origin', false);
    if (grant.never) return report(severity.INFORMATIONAL, confidence.CERTAIN, 'denies every permission', false);
    if (checksOrigin(fn)) return report(severity.LOW, confidence.FIRM, 'grants some permissions after checking the requesting origin; review the allowlist');
    return report(severity.MEDIUM, confidence.FIRM, 'grants permissions without checking the requesting origin');
  }
}

function returnAnswers(fn, scope) {
  const values = returnedValues(fn);
  const truthy = values.filter(({ value }) => constantValue(value, scope) === true);
  const dynamic = values.filter(({ value }) => constantValue(value, scope) === undefined);
  const unconditional = truthy.filter(({ value, ancestors }) => !isConditional(value, ancestors, fn));
  return { always: unconditional.length > 0, never: truthy.length === 0 && dynamic.length === 0 };
}

function checksOrigin(fn) {
  let found = false;
  visit(fn.body, (n) => {
    if (found) return false;
    if (isMember(n) && ORIGIN_REFERENCES.test(memberName(n) || '')) found = true;
    return true;
  });
  // requestingOrigin is also passed as a plain parameter to permission check handlers
  const params = (fn.params || []).map(p => p.name);
  return found || hasUrlValidation(fn) || params.some(p => /origin|url/i.test(p || '') && fnUses(fn, p));
}

function fnUses(fn, name) {
  let used = false;
  visit(fn.body, (n) => { if (n.type === 'Identifier' && n.name === name) used = true; return !used; });
  return used;
}
