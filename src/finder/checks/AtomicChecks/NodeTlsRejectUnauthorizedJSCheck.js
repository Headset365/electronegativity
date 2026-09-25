import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, isProperty, literalValue, finding } from '../helpers.js';

// Disabling TLS certificate validation for Node.js networking (process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0', rejectUnauthorized: false)
export default class NodeTlsRejectUnauthorizedJSCheck {
  constructor() {
    this.id = "NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK";
    this.description = __("NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://nodejs.org/api/cli.html#node_tls_reject_unauthorized";
  }

  match(astNode) {
    // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    if (astNode.type === 'AssignmentExpression' && memberName(astNode.left) === 'NODE_TLS_REJECT_UNAUTHORIZED') {
      const value = literalValue(astNode.right);
      if (value === '0' || value === 0 || value === false || value === undefined)
        return [finding(this, astNode, { severity: severity.HIGH, confidence: value === undefined ? confidence.TENTATIVE : confidence.CERTAIN, manualReview: value === undefined })];
    }
    // https.request({ rejectUnauthorized: false }), new https.Agent({ rejectUnauthorized: false }), tls.connect(...)
    if (isProperty(astNode) && !astNode.computed && keyName(astNode.key) === 'rejectUnauthorized' && literalValue(astNode.value) === false) {
      return [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false })];
    }
    return null;
  }
}
