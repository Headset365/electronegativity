import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { constantValue, constantPrefix, possibleValues, enclosingFunction, untrustedSource, dependsOnParams, hasUrlValidation, isConditional, onlyConstantCallers } from '../analysis.js';

// Schemes that are fine to hand to the OS: web pages and mail
const SAFE_URL = /^(https:\/\/[^/?#]+[/?#]|https:\/\/[^/?#]+$|mailto:)/i;

// Electron security checklist #15: do not use shell.openExternal with untrusted content
export default class OpenExternalJSCheck {
  constructor() {
    this.id = "OPEN_EXTERNAL_JS_CHECK";
    this.description = __("OPEN_EXTERNAL_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#15-do-not-use-shellopenexternal-with-untrusted-content";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (memberName(astNode.callee) !== 'openExternal' || astNode.arguments.length === 0) return null;
    const result = assessUrlSink(this, astNode, astNode.arguments[0], scope, context.ancestors, SAFE_URL);
    return result ? [result] : null;
  }
}

/**
 * Rates a call that hands a URL/path to the operating system, based on where the value comes from.
 */
export function assessUrlSink(check, call, arg, scope, ancestors, safePattern, { trustPrefix = true } = {}) {
  const describe = (reason) => `${check.description} (${reason})`;
  // every value the argument can take is a known constant: BETA ? 'https://a' : 'https://b'
  const values = possibleValues(arg, scope);
  if (values.length > 1 && values.every(v => typeof v === 'string')) {
    const unsafe = values.filter(v => !safePattern.test(v));
    if (unsafe.length === 0) return null;
    return finding(check, call, { severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true,
      description: describe(`opens the constant "${unsafe[0]}"`), properties: { value: unsafe[0] } });
  }
  const value = constantValue(arg, scope);

  if (typeof value === 'string') {
    if (safePattern.test(value)) return null;
    // a constant is the developer's choice, never attacker-controlled: only worth a look
    return finding(check, call, { severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true,
      description: describe(`opens the constant "${value}"`), properties: { value } });
  }

  // a fixed https://host/ prefix can't be turned into another scheme or host
  const prefix = constantPrefix(arg, scope);
  if (trustPrefix && prefix && safePattern.test(prefix)) return null;

  const fn = enclosingFunction(ancestors);
  const source = fn && untrustedSource(ancestors, fn);
  const validated = fn && hasUrlValidation(fn) && isConditional(call, ancestors, fn);

  if (source && dependsOnParams(arg, fn) && !validated) {
    return finding(check, call, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false,
      description: describe(`the value comes from ${source} and is not validated`), properties: { source } });
  }
  if (validated) {
    return finding(check, call, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
      description: describe('the value is validated first; review the allowlist') });
  }
  // a helper parameter, and every caller in the project passes a constant
  if (!source && dependsOnParams(arg, fn) && onlyConstantCallers(fn)) {
    return finding(check, call, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
      description: describe('the value is a parameter that every caller sets to a constant') });
  }
  return finding(check, call, { severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true,
    description: describe('the origin of the value could not be determined') });
}
