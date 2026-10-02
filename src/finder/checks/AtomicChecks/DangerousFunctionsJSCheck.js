import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { constantValue, resolveLocal } from '../analysis.js';
import { isFunction, memberName } from '../helpers.js';

const ELECTRON_METHODS = ['executeJavaScript', 'executeJavaScriptInIsolatedWorld', 'insertCSS'];
const EXECUTION_FUNCTIONS = ['eval', 'Function'];
const TIMERS = ['setTimeout', 'setInterval', 'setImmediate'];
const GLOBAL_OBJECTS = ['window', 'globalThis', 'self', 'global'];

// a variable whose name says it holds code rather than a callback: setTimeout(code), setInterval(script)
const CODE_NAME = /^(?:code|script|src|source|str|string|expr|expression|js|cmd|command|body|text)(?:[A-Z_]\w*)?$|(?:Code|Script|Source|Expr|Expression|String|Js)$/;

// an expression that produces a string: a template literal, a concatenation with a string part, String(x), x.toString()
function buildsString(node) {
  if (!node) return false;
  if (node.type === 'TemplateLiteral' || node.type === 'StringLiteral' || (node.type === 'Literal' && typeof node.value === 'string')) return true;
  if (node.type === 'BinaryExpression' && node.operator === '+') return buildsString(node.left) || buildsString(node.right);
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'String') return true;
  if (node.type === 'CallExpression' && memberName(node.callee) === 'toString') return true;
  if (node.type === 'ConditionalExpression') return buildsString(node.consequent) || buildsString(node.alternate);
  return false;
}

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
      // a timer only evaluates a string: callbacks, bound methods and parameters (setTimeout(resolve, 0)) are functions in
      // practice; flag the shapes that build code (`…${x}…`, 'a' + x, String(x)) or a value that resolves to one
      if (isFunction(value) || !(buildsString(value) || (value?.type === 'Identifier' && CODE_NAME.test(value.name)))) return null;
    }
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description,
      shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: true }];
  }
}
