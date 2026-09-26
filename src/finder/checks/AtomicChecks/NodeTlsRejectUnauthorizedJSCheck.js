import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, isProperty, literalValue, finding } from '../helpers.js';
import { constantValue } from '../analysis.js';

// Disabling TLS certificate validation for Node.js networking (process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0', rejectUnauthorized: false)
export default class NodeTlsRejectUnauthorizedJSCheck {
  constructor() {
    this.id = "NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK";
    this.description = __("NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://nodejs.org/api/cli.html#node_tls_reject_unauthorized";
  }

  match(astNode, astHelper, scope) {
    // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    if (astNode.type === 'AssignmentExpression' && memberName(astNode.left) === 'NODE_TLS_REJECT_UNAUTHORIZED') {
      // Node.js only disables validation for the value '0' (environment values are strings)
      const value = constantValue(astNode.right, scope);
      if (value !== undefined && String(value) !== '0') return null;
      return [finding(this, astNode, { severity: severity.HIGH, confidence: value === undefined ? confidence.TENTATIVE : confidence.CERTAIN, manualReview: value === undefined })];
    }
    // https.request({ rejectUnauthorized: false }), new https.Agent({ rejectUnauthorized: false }), tls.connect(...)
    if (isProperty(astNode) && !astNode.computed && keyName(astNode.key) === 'rejectUnauthorized' && literalValue(astNode.value) === false) {
      return [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false })];
    }
    return null;
  }
}
