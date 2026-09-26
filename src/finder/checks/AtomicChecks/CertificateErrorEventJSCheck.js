import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, calleeObjectName, literalValue, finding } from '../helpers.js';
import { handlerFunction, callbackAnswers, callsIn, paramNames } from '../analysis.js';

// 'certificate-error' handlers that call callback(true) (after event.preventDefault()) accept invalid TLS certificates
export default class CertificateErrorEventJSCheck {
  constructor() {
    this.id = "CERTIFICATE_ERROR_EVENT_JS_CHECK";
    this.description = __("CERTIFICATE_ERROR_EVENT_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/app#event-certificate-error";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' || !['on', 'once'].includes(memberName(astNode.callee))) return null;
    if (literalValue(astNode.arguments[0]) !== 'certificate-error' || astNode.arguments.length < 2) return null;

    const report = (sev, conf, reason, manualReview = true) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, description: `${this.description} (${reason})` })];

    const fn = handlerFunction(astNode.arguments[1], scope, context.ancestors);
    if (!fn) return report(severity.MEDIUM, confidence.TENTATIVE, 'the handler is defined elsewhere; review it');

    // app: (event, webContents, url, error, certificate, callback, isMainFrame), webContents: (event, url, error, certificate, callback, isMainFrame)
    const names = paramNames(fn);
    let callbackIndex = names.findIndex(n => /^(callback|cb|done|next)$/i.test(n));
    if (callbackIndex < 0) callbackIndex = calleeObjectName(astNode.callee) === 'app' ? 5 : 4;

    const answer = callbackAnswers(fn, callbackIndex, true, scope);
    const overrides = callsIn(fn, (call, name) => name === 'preventDefault').length > 0;
    if (answer.never) return null; // the default behavior rejects invalid certificates
    // without event.preventDefault() Electron ignores callback(true), but the intent to bypass validation is there
    if (!overrides) return report(severity.LOW, confidence.FIRM, 'callback(true) is called without event.preventDefault(), which currently has no effect but is one change away from accepting invalid certificates');
    if (answer.always) return report(severity.HIGH, confidence.CERTAIN, 'every invalid certificate is accepted', false);
    return report(severity.MEDIUM, confidence.FIRM, 'some invalid certificates are accepted; review the condition');
  }
}
