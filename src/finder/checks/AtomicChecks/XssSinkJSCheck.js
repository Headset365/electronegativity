import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, finding } from '../helpers.js';
import { constantValue, identifiersIn, visit, isCall } from '../analysis.js';

const HTML_PROPERTIES = ['innerHTML', 'outerHTML'];
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
    if (isSanitized(value)) return null;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} (${sink} with a dynamic value)`, properties: { sink } })];
  }
}

function isSanitized(value) {
  if ([...identifiersIn(value)].some(name => SANITIZED.test(name))) return true;
  let found = false;
  visit(value, (n) => { if (isCall(n) && SANITIZED.test(memberName(n.callee) || '')) found = true; return !found; });
  return found;
}
