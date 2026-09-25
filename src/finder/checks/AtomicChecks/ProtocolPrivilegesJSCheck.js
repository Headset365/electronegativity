import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, resolveIdentifier, findProperty, literalValue, finding } from '../helpers.js';

// Privileges granted to custom schemes with protocol.registerSchemesAsPrivileged()
const RISKY_PRIVILEGES = {
  bypassCSP: { severity: severity.HIGH, confidence: confidence.FIRM, reason: 'content served over this scheme ignores the Content Security Policy' },
  corsEnabled: { severity: severity.LOW, confidence: confidence.TENTATIVE, reason: 'the scheme can be used for cross-origin requests' },
  allowServiceWorkers: { severity: severity.LOW, confidence: confidence.TENTATIVE, reason: 'pages on this scheme can register service workers' },
};

export default class ProtocolPrivilegesJSCheck {
  constructor() {
    this.id = "PROTOCOL_PRIVILEGES_JS_CHECK";
    this.description = __("PROTOCOL_PRIVILEGES_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/protocol#protocolregisterschemesasprivilegedcustomschemes";
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (memberName(astNode.callee) !== 'registerSchemesAsPrivileged' || astNode.arguments.length === 0) return null;

    const schemes = resolveIdentifier(astNode.arguments[0], scope);
    if (!schemes || schemes.type !== 'ArrayExpression') return null;

    const issues = [];
    for (const element of schemes.elements) {
      const scheme = resolveIdentifier(element, scope);
      const name = findProperty(scheme, 'scheme');
      const privileges = findProperty(scheme, 'privileges');
      if (!privileges) continue;
      for (const [privilege, rule] of Object.entries(RISKY_PRIVILEGES)) {
        const p = findProperty(resolveIdentifier(privileges[1], scope), privilege);
        if (p && literalValue(p[1]) === true) {
          issues.push(finding(this, p[2], { severity: rule.severity, confidence: rule.confidence, manualReview: true,
            description: `${this.description}: ${name ? literalValue(name[1]) + ' ' : ''}${privilege} (${rule.reason})`, properties: { privilege } }));
        }
      }
    }
    return issues;
  }
}
