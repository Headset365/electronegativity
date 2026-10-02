import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, finding } from '../helpers.js';
import { onlyConstantParts, visit } from '../analysis.js';

// HTML assembled from a template literal, with values put into element text or attribute values unescaped:
//   `<title>${note.title}</title><meta name="description" content="${note.headline}">`
// Whatever renders the result (innerHTML, an iframe's srcdoc, an exported file opened in the app) runs any markup the
// values carry. Notesnook's PDF export (CVE-2026-42090) built its document this way from note titles and tags.

// an element's opening or closing tag
const TAG = /<\/?[a-z][a-z0-9-]*(?=[\s>/])/gi;
// property and variable names that hold numbers, sizes or identifiers rather than text a person wrote
const NOT_TEXT = /^(?:i|j|k|n|idx|index|count|total|len|length|width|height|size|top|left|right|bottom|x|y|z|id|uid|key|px|em|zIndex|level|depth|page|offset|scale|ratio|opacity|version|year|month|day|hour|minute|second|ms|timestamp|time|date|color|colour|theme|lang|dir)$/i;


const TRANSLATIONS = /(?:^|\.)(?:languages|language|i18n|l10n|lang|locale|locales|translations|translation|messages|strings|texts)\./i;

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
      const described = describe(expression);
      // the app's own translated strings (window.siyuan.languages.title, i18n.messages.save) are not user content
      if (TRANSLATIONS.test(described)) return [];
      return name && !NOT_TEXT.test(name) && !/^\d+$/.test(name) ? [described] : [];
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

// names that say a value holds markup, or a function that produces it
const HTML_NAME = /html|markup|template|tpl|snippet/i;
const RENDER_NAME = /html|markup|template|tpl|render|build|view|toast|tooltip|popup|item|row|cell/i;
const HTML_CALLS = new Set(['html', 'append', 'prepend', 'before', 'after', 'replaceWith', 'insertAdjacentHTML', 'write', 'writeln',
  'createContextualFragment', 'parseFromString', 'setContent', 'setData', 'showError', 'showMessage', 'show', 'toast']);
const DOCUMENT = /<!doctype|<html[\s>]|<body[\s>]|<head[\s>]/i;
const PASS_THROUGH = new Set(['ConditionalExpression', 'LogicalExpression', 'BinaryExpression', 'ParenthesizedExpression', 'TemplateLiteral',
  'SequenceExpression', 'AwaitExpression', 'ArrayExpression', 'SpreadElement', 'TSAsExpression']);

const nameOf = (node) => !node ? undefined : node.type === 'Identifier' ? node.name : (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') ? memberName(node) : keyName(node);

// The function a node is returned from, and that function's name (declared, assigned or a property)
function functionName(fn, parent) {
  if (fn.id && fn.id.name) return fn.id.name;
  if (!parent) return undefined;
  if (parent.type === 'VariableDeclarator') return nameOf(parent.id);
  if (parent.type === 'AssignmentExpression') return nameOf(parent.left);
  if (parent.type === 'ObjectProperty' || parent.type === 'Property' || parent.type === 'ClassMethod' || parent.type === 'MethodDefinition') return nameOf(parent.key);
  return undefined;
}

/**
 * Whether the markup goes somewhere HTML is parsed or built: an HTML sink or a jQuery insertion, a variable or property
 * named for markup (itemHtml, template, html +=), or a value returned by a function that renders (renderItem, toHtml).
 * Markup in message tables, titles and other constants that never reach the DOM as HTML is left out.
 */
function reachesHtml(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const node = ancestors[i];
    if (PASS_THROUGH.has(node.type)) continue;
    if (node.type === 'AssignmentExpression') return HTML_NAME.test(nameOf(node.left) || '') || ['innerHTML', 'outerHTML', 'srcdoc'].includes(nameOf(node.left))
      || (node.left.type === 'Identifier' && markupVariable(node.left.name, ancestors.slice(0, i)));
    if (node.type === 'VariableDeclarator') return HTML_NAME.test(nameOf(node.id) || '') || (node.id.type === 'Identifier' && markupVariable(node.id.name, ancestors.slice(0, i)));
    if (node.type === 'ObjectProperty' || node.type === 'Property') return /html|template|content|body|srcdoc|message/i.test(nameOf(node.key) || '');
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      const callee = node.callee;
      const name = callee.type === 'Identifier' ? callee.name : nameOf(callee);
      return HTML_CALLS.has(name) || name === '$' || name === 'jQuery' || HTML_NAME.test(name || '') || /render/i.test(name || '');
    }
    if (node.type === 'ReturnStatement') continue;
    if (node.type === 'BlockStatement') continue;
    if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression' || node.type === 'FunctionDeclaration' || node.type === 'ObjectMethod' || node.type === 'ClassMethod')
      return RENDER_NAME.test(functionName(node, ancestors[i - 1]) || '');
    return false;
  }
  return false;
}

// whether a value holds markup: a string or template with a tag in it
const holdsMarkup = (node) => !!node && ((node.type === 'TemplateLiteral' && node.quasis.some(q => TAG_ONCE.test(q.value.cooked ?? q.value.raw)))
  || ((node.type === 'StringLiteral' || node.type === 'Literal') && typeof node.value === 'string' && TAG_ONCE.test(node.value)));
const TAG_ONCE = /<\/?[a-z][a-z0-9-]*(?=[\s>/])/i;

/**
 * A variable that builds HTML whatever it is called (minified: u = `<div …>`; u += `<span …>`; return u): two or more
 * pieces of markup put into it, or the variable handed to an HTML sink, in the function that holds it.
 */
function markupVariable(name, ancestors) {
  const scope = [...ancestors].reverse().find(node => /Function|Program/.test(node.type));
  if (!scope) return false;
  let pieces = 0;
  let sink = false;
  visit(scope.body || scope, (node) => {
    if (sink || pieces >= 2) return false;
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && node.left.name === name && holdsMarkup(node.right)) pieces++;
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.id.name === name && holdsMarkup(node.init)) pieces++;
    if ((node.type === 'CallExpression' || node.type === 'OptionalCallExpression') && node.arguments.some(arg => arg.type === 'Identifier' && arg.name === name)) {
      const callee = node.callee.type === 'Identifier' ? node.callee.name : nameOf(node.callee);
      if (HTML_CALLS.has(callee) || callee === '$' || callee === 'jQuery') sink = true;
    }
    if (node.type === 'AssignmentExpression' && ['innerHTML', 'outerHTML'].includes(nameOf(node.left)) && node.right.type === 'Identifier' && node.right.name === name) sink = true;
    return true;
  });
  return sink || pieces >= 2;
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
    // a whole document is HTML wherever it goes; a fragment counts where it is parsed or built as markup
    if (!DOCUMENT.test(markup) && !reachesHtml(context && context.ancestors || [])) return null;

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
