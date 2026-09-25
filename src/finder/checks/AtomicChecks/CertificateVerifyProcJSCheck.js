import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { handlerFunction, callbackAnswers } from '../analysis.js';

// session.setCertificateVerifyProc: callback(0) accepts a certificate, -2 rejects it, -3 uses Chromium's verification
export default class CertificateVerifyProcJSCheck {
  constructor() {
    this.id = "CERTIFICATE_VERIFY_PROC_JS_CHECK";
    this.description = __("CERTIFICATE_VERIFY_PROC_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/session#sessetcertificateverifyprocproc";
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'CallExpression') return null;
    const method = memberName(astNode.callee) || (astNode.callee.type === 'Identifier' ? astNode.callee.name : undefined);
    const report = (sev, conf, reason, manualReview = true, properties = {}) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, description: `${this.description} (${reason})`,
        properties: { verifyProc: method === 'setCertificateVerifyProc', ...properties } })];

    if (method === 'importCertificate')
      return report(severity.MEDIUM, confidence.FIRM, 'a certificate is imported into the platform certificate store');
    if (method !== 'setCertificateVerifyProc' || astNode.arguments.length === 0) return null;

    const fn = handlerFunction(astNode.arguments[0], scope);
    if (!fn) return report(severity.MEDIUM, confidence.TENTATIVE, 'the verification procedure is defined elsewhere; review it');

    const accepts = callbackAnswers(fn, 1, (value) => value === 0, scope);
    if (accepts.always) return report(severity.HIGH, confidence.CERTAIN, 'every certificate is accepted, TLS validation is disabled', false);
    // custom verification that never overrides Chromium's result is how certificate pinning is done
    if (accepts.never) return report(severity.INFORMATIONAL, confidence.CERTAIN, 'certificates are only ever rejected or checked by Chromium (pinning)', false, { pinning: true });
    return report(severity.MEDIUM, confidence.FIRM, 'some certificates are accepted regardless of Chromium\'s verification; review the condition');
  }
}
