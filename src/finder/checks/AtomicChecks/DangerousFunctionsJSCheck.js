import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { constantValue, resolveLocal } from '../analysis.js';
import { isFunction, memberName } from '../helpers.js';

const ELECTRON_METHODS = ['executeJavaScript', 'executeJavaScriptInIsolatedWorld', 'insertCSS'];
const EXECUTION_FUNCTIONS = ['eval', 'Function'];
const TIMERS = ['setTimeout', 'setInterval', 'setImmediate'];
const GLOBAL_OBJECTS = ['window', 'globalThis', 'self', 'global'];

export default class DangerousFunctionsJSCheck {
  constructor() {
    this.id = "DANGEROUS_FUNCTIONS_JS_CHECK";
    this.description = __("DANGEROUS_FUNCTIONS_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!";
  }

  match(astNode, astHelper, scope) {
    if (!['CallExpression', 'OptionalCallExpression', 'NewExpression'].includes(astNode.type) || !astNode.arguments.length) return null;
    // Follow local aliases without treating a locally declared function as a global execution API.
    let callee = astNode.callee;
    const seen = new Set();
    for (let depth = 0; callee?.type === 'Identifier' && depth < 6 && !seen.has(callee); depth++) {
      seen.add(callee);
      const resolved = resolveLocal(callee, scope);
      if (!resolved || resolved === callee) break;
      callee = resolved;
    }
    if (!callee) return null;
    const name = callee.type === 'Identifier' ? callee.name : memberName(callee);
    const global = callee.type === 'Identifier' || GLOBAL_OBJECTS.includes(callee.object?.name);
    const execution = global && EXECUTION_FUNCTIONS.includes(name);
    const timer = global && TIMERS.includes(name);
    const electron = ELECTRON_METHODS.includes(name);
    if (!execution && !timer && !electron) return null;
    if (astNode.type === 'NewExpression' && !(execution && name === 'Function')) return null;
    const args = name === 'Function' ? astNode.arguments : astNode.arguments.slice(0, 1);
    if (args.every(arg => constantValue(arg, scope) !== undefined)) return null;
    if (timer) {
      let value = astNode.arguments[0];
      const seenValues = new Set();
      for (let depth = 0; value?.type === 'Identifier' && depth < 6 && !seenValues.has(value); depth++) {
        seenValues.add(value);
        const resolved = resolveLocal(value, scope);
        if (!resolved || resolved === value) break;
        value = resolved;
      }
      if (isFunction(value)) return null;
    }
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description,
      shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: true }];
  }
}
