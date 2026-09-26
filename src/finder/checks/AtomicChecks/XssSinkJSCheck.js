import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, finding } from '../helpers.js';
import { constantValue, identifiersIn, isCall } from '../analysis.js';

const HTML_PROPERTIES = ['innerHTML', 'outerHTML'];
const JQUERY_INSERTION = ['append', 'prepend', 'before', 'after', 'replaceWith'];
// sanitizers make the value safe to insert
const SANITIZED = /(sanitize|purify|escape|encode|DOMPurify|xss|trustedTypes|createHTML)/i;

// XSS in an Electron renderer can reach IPC, preload APIs and, without isolation, Node.js itself
export default class XssSinkJSCheck {
  constructor() {
    this.id = "XSS_SINK_JS_CHECK";
    this.description = __("XSS_SINK_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#7-define-a-content-security-policy";
  }

  match(astNode, astHelper, scope) {
    let sink;
    let value;
    // el.innerHTML = x, el.outerHTML += x
    if (astNode.type === 'AssignmentExpression' && HTML_PROPERTIES.includes(memberName(astNode.left))) {
      sink = memberName(astNode.left);
      value = astNode.right;
    }
    // el.insertAdjacentHTML(pos, x), document.write(x), document.writeln(x)
    if (isCall(astNode) && astNode.type !== 'NewExpression') {
      const method = memberName(astNode.callee);
      if (method === 'insertAdjacentHTML') { sink = method; value = astNode.arguments[1]; }
      if ((method === 'write' || method === 'writeln') && astNode.callee.object && astNode.callee.object.name === 'document') { sink = `document.${method}`; value = astNode.arguments[0]; }
      // jQuery: $el.html(x); append/prepend/before/after/replaceWith parse strings as HTML too, flag them when given built strings
      if (method === 'html' && astNode.arguments.length === 1) { sink = '.html()'; value = astNode.arguments[0]; }
      if (JQUERY_INSERTION.includes(method) && astNode.arguments.length === 1 && isBuiltString(astNode.arguments[0])) { sink = `.${method}()`; value = astNode.arguments[0]; }
    }
    // <div dangerouslySetInnerHTML={{ __html: x }} />
    if (astNode.type === 'JSXAttribute' && astNode.name && astNode.name.name === 'dangerouslySetInnerHTML') {
      sink = 'dangerouslySetInnerHTML';
      const expression = astNode.value && astNode.value.expression;
      const html = expression && expression.type === 'ObjectExpression' && expression.properties.find(p => keyName(p.key) === '__html');
      value = html ? html.value : expression;
    }
    if (!sink || !value) return null;

    const constant = constantValue(value, scope);
    if (constant !== undefined) return null;
    if (isSanitized(value, scope)) return null;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} (${sink} with a dynamic value)`, properties: { sink } })];
  }
}

// Strings assembled from pieces: `<b>${x}</b>`, '<b>' + x
function isBuiltString(node) {
  return node.type === 'TemplateLiteral' || (node.type === 'BinaryExpression' && node.operator === '+');
}

/**
 * Whether every dynamic part of the HTML goes through a sanitizer. A sanitizer nested deeper doesn't count:
 * in render(escape(text)) the render function can re-introduce markup (Signal Desktop CVE-2018-10994).
 */
function isSanitized(value, scope) {
  if (!value) return false;
  if (constantValue(value, scope) !== undefined) return true;
  switch (value.type) {
    case 'Identifier': return SANITIZED.test(value.name);
    case 'CallExpression':
    case 'OptionalCallExpression': return SANITIZED.test(memberName(value.callee) || (value.callee.type === 'Identifier' ? value.callee.name : ''));
    case 'TemplateLiteral': return value.expressions.every(e => isSanitized(e, scope));
    case 'BinaryExpression': return value.operator === '+' && isSanitized(value.left, scope) && isSanitized(value.right, scope);
    case 'ConditionalExpression': return isSanitized(value.consequent, scope) && isSanitized(value.alternate, scope);
    case 'LogicalExpression': return isSanitized(value.left, scope) && isSanitized(value.right, scope);
    case 'MemberExpression': return SANITIZED.test(memberName(value) || '') || [...identifiersIn(value)].some(name => SANITIZED.test(name));
    case 'AwaitExpression': return isSanitized(value.argument, scope);
    default: return false;
  }
}
