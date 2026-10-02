// SQL assembled from values instead of passed as parameters:
//   dbQuery(`SELECT * FROM tblFiles WHERE FileID = ${fileID};`)
// A local database (SQLite, Access through ADODB, an embedded server) holds the app's data; a value from a renderer,
// a file or the network that reaches the statement can change what it does (DivorceMate's legacy import read the
// matter id a page sent straight into its Access query).
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { finding } from '../helpers.js';
import { onlyConstantParts, untrustedSource, dependsOnParams } from '../analysis.js';

// statement shapes, checked against the constant text only
const SQL = /\b(?:select\b[\s\S]{1,400}?\bfrom|insert\s+into|update\b[\s\S]{1,200}?\bset|delete\s+from|replace\s+into|merge\s+into|drop\s+table|alter\s+table|create\s+table)\b/i;
// tags that build parameterised statements (sql`…`, Prisma.sql, slonik, postgres.js)
const SAFE_TAGS = /^(sql|SQL|Prisma\.sql|raw|unsafe)$/;

// the constant text of a template or a concatenation, and whether any part of it is not constant
function pieces(node, scope, out = { text: '', dynamic: [] }) {
  if (node.type === 'TemplateLiteral') {
    node.quasis.forEach((quasi, i) => {
      out.text += quasi.value.cooked ?? quasi.value.raw;
      const expression = node.expressions[i];
      if (expression) {
        if (onlyConstantParts(expression, scope)) out.text += '0';
        else { out.dynamic.push(expression); out.text += ' ? '; }
      }
    });
  } else if (node.type === 'BinaryExpression' && node.operator === '+') {
    pieces(node.left, scope, out);
    pieces(node.right, scope, out);
  } else if ((node.type === 'StringLiteral' || node.type === 'Literal') && typeof node.value === 'string') out.text += node.value;
  else if (onlyConstantParts(node, scope)) out.text += '0';
  else { out.dynamic.push(node); out.text += ' ? '; }
  return out;
}

export default class SqlInjectionJSCheck {
  constructor() {
    this.id = 'SQL_INJECTION_JS_CHECK';
    this.description = __('SQL_INJECTION_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    const isTemplate = astNode.type === 'TemplateLiteral';
    const isConcat = astNode.type === 'BinaryExpression' && astNode.operator === '+';
    if (!isTemplate && !isConcat) return null;
    const parent = context.ancestors[context.ancestors.length - 1];
    // the whole concatenation once, at its top
    if (isConcat && parent && parent.type === 'BinaryExpression' && parent.operator === '+') return null;
    if (isTemplate && parent && parent.type === 'BinaryExpression' && parent.operator === '+') return null;
    if (isTemplate && parent && parent.type === 'TaggedTemplateExpression') {
      const tag = parent.tag.type === 'Identifier' ? parent.tag.name : parent.tag.type === 'MemberExpression' && parent.tag.property ? `${parent.tag.object.name || ''}.${parent.tag.property.name}` : '';
      if (SAFE_TAGS.test(tag)) return null;
    }
    const { text, dynamic } = pieces(astNode, scope);
    if (!dynamic.length || !SQL.test(text)) return null;
    // values in a statement's text, never its keywords: a table or column name chosen in code is the common, safe case
    if (!/\b(?:where|values|set|having|limit|offset|like|in)\b[\s\S]*\?/i.test(text) && !/=\s*'?\s*\?/.test(text)) return null;

    // the value may be a parameter of an outer function: new Promise(async resolve => query(`… ${id}`)) inside a handler
    let source;
    let fromSource = false;
    for (let i = context.ancestors.length - 1, depth = 0; i >= 0 && depth < 4 && !fromSource; i--) {
      const fn = context.ancestors[i];
      if (!/Function/.test(fn.type)) continue;
      depth++;
      const found = untrustedSource(context.ancestors.slice(0, i + 1), fn);
      if (found && dynamic.some(value => dependsOnParams(value, fn))) { source = found; fromSource = true; }
    }
    const statement = text.replace(/\s+/g, ' ').trim().slice(0, 120);
    return [finding(this, astNode, { severity: fromSource ? severity.HIGH : severity.MEDIUM, confidence: fromSource ? confidence.FIRM : confidence.TENTATIVE,
      manualReview: true, properties: { statement, source },
      description: `${this.description}: ${statement}${fromSource ? ` (values come from ${source})` : ' (check where the values come from)'}` })];
  }
}
