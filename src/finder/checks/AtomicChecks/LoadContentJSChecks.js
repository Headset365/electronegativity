import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { constantPrefix, enclosingFunction, untrustedSource, dependsOnParams, hasUrlValidation, isConditional } from '../analysis.js';

// Electron security checklist #18: avoid the file:// protocol, prefer custom protocols
export class FileProtocolJSCheck {
  constructor() {
    this.id = "FILE_PROTOCOL_JS_CHECK";
    this.description = __("FILE_PROTOCOL_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols";
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    const method = memberName(astNode.callee);
    if (method === 'loadFile' && astNode.arguments.length > 0)
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: false })];
    if (method === 'loadURL' && /^file:/i.test(constantPrefix(astNode.arguments[0], scope) || ''))
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: false })];
    return null;
  }
}

// Loading a URL chosen by web content, a deep link or another renderer into an app window
export class UntrustedLoadUrlJSCheck {
  constructor() {
    this.id = "UNTRUSTED_LOAD_URL_JS_CHECK";
    this.description = __("UNTRUSTED_LOAD_URL_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#13-disable-or-limit-navigation";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (memberName(astNode.callee) !== 'loadURL' || astNode.arguments.length === 0) return null;
    const fn = enclosingFunction(context.ancestors);
    const source = fn && untrustedSource(context.ancestors, fn);
    if (!source || !dependsOnParams(astNode.arguments[0], fn)) return null;
    if (/^https:\/\/[^/]+\//i.test(constantPrefix(astNode.arguments[0], scope) || '')) return null; // fixed origin
    const validated = hasUrlValidation(fn) && isConditional(astNode, context.ancestors, fn);
    return [finding(this, astNode, validated
      ? { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true, description: `${this.description} (${source}, validated first; review the allowlist)` }
      : { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false, description: `${this.description} (${source}, not validated)`, properties: { source } })];
  }
}
