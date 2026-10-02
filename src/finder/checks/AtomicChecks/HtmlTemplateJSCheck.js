import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, finding } from '../helpers.js';
import { onlyConstantParts } from '../analysis.js';

// HTML assembled from a template literal, with values put into element text or attribute values unescaped:
//   `<title>${note.title}</title><meta name="description" content="${note.headline}">`
// Whatever renders the result (innerHTML, an iframe's srcdoc, an exported file opened in the app) runs any markup the
// values carry. Notesnook's PDF export (CVE-2026-42090) built its document this way from note titles and tags.

// an element's opening or closing tag
const TAG = /<\/?[a-z][a-z0-9-]*(?=[\s>/])/gi;
// property and variable names that hold numbers, sizes or identifiers rather than text a person wrote
const NOT_TEXT = /^(?:i|j|k|n|idx|index|count|total|len|length|width|height|size|top|left|right|bottom|x|y|z|id|uid|key|px|em|zIndex|level|depth|page|offset|scale|ratio|opacity|version|year|month|day|hour|minute|second|ms|timestamp|time|date|color|colour|theme|lang|dir)$/i;


// the interpolated values worth flagging: names of the data put into the markup as is
function unescapedValues(expression, scope) {
  if (!expression || onlyConstantParts(expression, scope)) return [];
  switch (expression.type) {
    case 'Identifier':
    // a minified one-letter name says nothing about the value
      return expression.name.length > 2 && !NOT_TEXT.test(expression.name) ? [expression.name] : [];
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const name = memberName(expression);
      return name && !NOT_TEXT.test(name) && !/^\d+$/.test(name) ? [describe(expression)] : [];
    }
    case 'ConditionalExpression':
      return [...unescapedValues(expression.consequent, scope), ...unescapedValues(expression.alternate, scope)];
    case 'LogicalExpression':
      return [...unescapedValues(expression.left, scope), ...unescapedValues(expression.right, scope)];
    case 'CallExpression':
    case 'OptionalCallExpression': {
    // list.join(", ") puts every item in as is; other calls are judged by their name
      const callee = expression.callee;
      const name = callee.type === 'Identifier' ? callee.name : memberName(callee);
      if (name === 'join' && callee.object) return unescapedValues(callee.object, scope).map(value => `${value}.join()`);
      return [];
    }
    default:
      return [];
  }
}

// a short readable name for a member chain: data.title, t.tags
function describe(node) {
  if (node.type === 'Identifier') return node.name;
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return '…';
  const property = keyName(node.property) || '…';
  const object = node.object.type === 'Identifier' || node.object.type === 'MemberExpression' || node.object.type === 'OptionalMemberExpression' ? describe(node.object) : '…';
  return `${object.length > 30 ? '…' : object}.${property}`;
}

// where an interpolation sits in the markup: element text, an attribute value, or somewhere else (a tag name, a script)
function contextOf(before) {
  const text = before.slice(-400);
  if (/=\s*["'][^"']*$/.test(text)) return 'attribute';
  const open = text.lastIndexOf('<');
  const close = text.lastIndexOf('>');
  if (close > open && !/<script\b[^>]*>[^<]*$/i.test(text) && !/<style\b[^>]*>[^<]*$/i.test(text)) return 'text';
  return undefined;
}

export default class HtmlTemplateJSCheck {
  constructor() {
    this.id = "HTML_TEMPLATE_JS_CHECK";
    this.description = __("HTML_TEMPLATE_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context) {
    if (astNode.type !== 'TemplateLiteral' || !astNode.expressions.length) return null;
    // html`…` (lit, htm) and similar tags escape their values; sql`…`, css`…` are not HTML
    const parent = context && context.ancestors && context.ancestors[context.ancestors.length - 1];
    if (parent && parent.type === 'TaggedTemplateExpression' && parent.quasi === astNode) return null;
    const markup = astNode.quasis.map(q => q.value.cooked ?? q.value.raw).join('');
    if (!(markup.match(TAG) || []).length) return null;

    const values = [];
    let before = '';
    astNode.expressions.forEach((expression, index) => {
      before += astNode.quasis[index].value.cooked ?? astNode.quasis[index].value.raw;
      const where = contextOf(before);
      if (where) for (const value of unescapedValues(expression, scope)) values.push(`${value} (${where === 'attribute' ? 'attribute value' : 'element text'})`);
      before += '${}';
    });
    if (!values.length) return null;
    const unique = [...new Set(values)];
    const shown = unique.slice(0, 6).join(', ') + (unique.length > 6 ? `, and ${unique.length - 6} more` : '');
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true,
      description: `${this.description} (values inserted without escaping: ${shown})`, properties: { values: unique } })];
  }
}
