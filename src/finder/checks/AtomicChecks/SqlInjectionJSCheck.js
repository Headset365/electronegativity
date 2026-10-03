// SQL assembled from values instead of passed as parameters:
//   dbQuery(`SELECT * FROM tblRecords WHERE RecordID = ${recordID};`)
// A local database (SQLite, Access through ADODB, an embedded server) holds the app's data; a value from a renderer,
// a file or the network that reaches the statement can change what it does (a legacy import that puts the record id a
// page sends straight into an Access query).
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { finding, visit, isFunction } from '../helpers.js';
import { onlyConstantParts, untrustedSource, dependsOnParams, identifiersIn, taintedNames, isCall } from '../analysis.js';

// statement shapes, checked against the constant text only
const SQL = /\b(?:select\b[\s\S]{1,400}?\bfrom|insert\s+into|update\b[\s\S]{1,200}?\bset|delete\s+from|replace\s+into|merge\s+into|drop\s+table|alter\s+table|create\s+table)\b/i;
// tags that build parameterised statements (sql`…`, Prisma.sql, slonik, postgres.js)
const SAFE_TAGS = /^(sql|SQL|Prisma\.sql|raw|unsafe)$/;

// drivers whose queries take no bound parameters, so the advice differs (node-adodb hands statement text to the Access engine)
const DRIVERS = /^(node-adodb|better-sqlite3|sqlite3|sqlite|mysql2?|pg|mssql|tedious|oracledb|odbc|sql\.js|knex|sequelize|typeorm)$/;
const driverCache = new WeakMap();

// the value an expression names, as the report shows it: recordID, contact.ContactID, args[0]; a longer one as …
function shownValue(node) {
  if (!node) return '…';
  if (node.type === 'Identifier') return node.name;
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed && node.property.type === 'Identifier') {
    const object = shownValue(node.object);
    return object === '…' ? '…' : `${object}.${node.property.name}`;
  }
  if (node.type === 'MemberExpression' && node.computed && (node.property.type === 'NumericLiteral' || (node.property.type === 'Literal' && typeof node.property.value === 'number'))) {
    const object = shownValue(node.object);
    return object === '…' ? '…' : `${object}[${node.property.value}]`;
  }
  if (isCall(node) && node.type !== 'NewExpression') {
    const callee = shownValue(node.callee);
    return callee === '…' ? '…' : `${callee}(…)`;
  }
  return '…';
}

// the constant text of a template or a concatenation (values as ?, to test its shape), the same text with each value
// written as in the code (${recordID}, to show it), and the parts that are not constant
function pieces(node, scope, out = { text: '', shown: '', dynamic: [] }) {
  const value = (expression) => {
    out.dynamic.push(expression);
    out.text += VALUE;
    out.shown += `\${${shownValue(expression)}}`;
  };
  if (node.type === 'TemplateLiteral') {
    node.quasis.forEach((quasi, i) => {
      const part = quasi.value.cooked ?? quasi.value.raw;
      out.text += part;
      out.shown += part;
      const expression = node.expressions[i];
      if (expression) {
        if (onlyConstantParts(expression, scope)) { out.text += '0'; out.shown += `\${${shownValue(expression)}}`; }
        else value(expression);
      }
    });
  } else if (node.type === 'BinaryExpression' && node.operator === '+') {
    pieces(node.left, scope, out);
    pieces(node.right, scope, out);
  } else if ((node.type === 'StringLiteral' || node.type === 'Literal') && typeof node.value === 'string') { out.text += node.value; out.shown += node.value; }
  else if (onlyConstantParts(node, scope)) { out.text += '0'; out.shown += `\${${shownValue(node)}}`; }
  else value(node);
  return out;
}

// where a value the code inserts stands in the statement (the text has VALUE there; a ? is the statement's own parameter)
const VALUE = '\u0001';
// after a comparison, LIKE, IN (, VALUES (, a comma in a list, LIMIT or OFFSET, or inside quotes: a value
const VALUE_BEFORE = /(?:[=<>]|\blike|\bin\s*\(|\bvalues\s*\(|,|\blimit|\boffset|\bthen|\belse|\bbetween|\band)\s*'?%?$/i;
// a name the statement compares or selects (WHERE ${column} = ?, SELECT ${column} FROM, JOIN ${table} ON): not a value
const NAME_AFTER = /^\s*(?:=|<|>|!|\bin\b|\blike\b|\bis\b|\bfrom\b|\bon\b|\bset\b|\bwhere\b|\bas\b|\.)/i;
function inValuePosition(text, skipped = []) {
  for (let at = text.indexOf(VALUE), n = 0; at !== -1; at = text.indexOf(VALUE, at + 1), n++) {
    if (skipped[n]) continue;
    const before = text.slice(Math.max(0, at - 40), at);
    const after = text.slice(at + 1, at + 20);
    if (/'%?$/.test(before)) return true;
    if (VALUE_BEFORE.test(before) && !NAME_AFTER.test(after)) return true;
  }
  return false;
}

// ids.map(() => '?').join(','), keys.map(k => `@${k}`).join(', '), Array(n).fill('?').join(), '?'.repeat(n): placeholders
const PLACEHOLDER = /^(?:\?|[@:$]\w*)$/;
function isPlaceholderList(init) {
  let n = init;
  while (n && ['TSAsExpression', 'ParenthesizedExpression'].includes(n.type)) n = n.expression;
  if (!isCall(n) || !n.callee.property) return false;
  const method = n.callee.property.name;
  if (method === 'repeat') return n.callee.object && typeof n.callee.object.value === 'string' && /^\?,?\s*$/.test(n.callee.object.value);
  if (method !== 'join') return false;
  const source = n.callee.object;
  if (!isCall(source) || !source.callee.property) return false;
  if (source.callee.property.name === 'fill') return source.arguments[0] && source.arguments[0].value === '?';
  if (source.callee.property.name !== 'map' || !isFunction(source.arguments[0])) return false;
  const body = source.arguments[0].body;
  const returned = body && body.type === 'BlockStatement' ? (body.body.find(st => st.type === 'ReturnStatement') || {}).argument : body;
  if (!returned) return false;
  if (typeof returned.value === 'string') return PLACEHOLDER.test(returned.value);
  if (returned.type === 'TemplateLiteral') return PLACEHOLDER.test(returned.quasis.map(q => q.value.cooked).join('').trim() || '') ||
    (returned.quasis.length === 2 && /^[@:$]$/.test(returned.quasis[0].value.cooked) && !returned.quasis[1].value.cooked);
  return false;
}
function placeholderList(value, ancestors) {
  if (isPlaceholderList(value)) return true;
  if (value.type !== 'Identifier') return false;
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const fn = ancestors[i];
    if (!isFunction(fn) && fn.type !== 'Program') continue;
    let found;
    let budget = 20000;
    visit(fn.body || fn, (n) => {
      if (found !== undefined || --budget < 0) return false;
      if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.id.name === value.name && n.init) found = isPlaceholderList(n.init);
      return true;
    });
    if (found !== undefined) return found;
  }
  return false;
}

// SQL text in a call's arguments: dbQuery(`SELECT …`), db.prepare('SELECT …' + id)
function hasSqlArgument(call) {
  return call.arguments.some((arg) => {
    let found = false;
    visit(arg, (n) => {
      if (found) return false;
      const part = n.type === 'TemplateElement' ? n.value.cooked ?? n.value.raw : (n.type === 'StringLiteral' || n.type === 'Literal') && typeof n.value === 'string' ? n.value : undefined;
      if (part && SQL.test(part)) found = true;
      return !found && !isFunction(n);
    });
    return found;
  });
}

// names in fn holding rows read by an earlier query: parties = await dbQuery(`SELECT …`), party = contacts[0]
function queryResults(fn) {
  const names = new Set();
  const assignments = [];
  visit(fn.body || fn, (n) => {
    if (n.type === 'VariableDeclarator' && n.init && n.id.type === 'Identifier') assignments.push([n.id.name, n.init]);
    if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier') assignments.push([n.left.name, n.right]);
    return true;
  });
  const unwrap = (node) => {
    let n = node;
    while (n && ['AwaitExpression', 'TSAsExpression', 'TSNonNullExpression', 'ParenthesizedExpression'].includes(n.type)) n = n.argument || n.expression;
    return n;
  };
  for (const [name, init] of assignments) {
    const value = unwrap(init);
    if (isCall(value) && value.type !== 'NewExpression' && hasSqlArgument(value)) names.add(name);
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, init] of assignments) {
      if (names.has(name)) continue;
      const value = unwrap(init);
      // a row or a field of one: contacts[0], rows.find(...), res.OwnerID, a ? rows[0] : null
      const reads = [...identifiersIn(value)];
      if (reads.length && reads.some(n => names.has(n)) && !isCall(value)) { names.add(name); changed = true; }
      else if (isCall(value) && value.callee.type !== 'Identifier' && value.callee.object && [...identifiersIn(value.callee.object)].some(n => names.has(n))) { names.add(name); changed = true; }
    }
  }
  return names;
}

// every value from the handler's input reaches the statement only through rows an earlier query read (second-order)
function onlyThroughQueries(dynamic, fn) {
  const tainted = taintedNames(fn);
  const rows = queryResults(fn);
  const used = dynamic.flatMap(value => [...identifiersIn(value)].filter(name => tainted.has(name)));
  return used.length > 0 && used.every(name => rows.has(name));
}

// the database library the file loads: require('node-adodb'), import Database from 'better-sqlite3'
function driverOf(program) {
  if (!program) return undefined;
  if (driverCache.has(program)) return driverCache.get(program);
  let driver;
  visit(program, (n) => {
    if (driver) return false;
    const source = n.type === 'ImportDeclaration' ? n.source.value
      : isCall(n) && n.callee.type === 'Identifier' && n.callee.name === 'require' && n.arguments[0] && typeof n.arguments[0].value === 'string' ? n.arguments[0].value : undefined;
    if (source && DRIVERS.test(source)) driver = source;
    return !driver;
  });
  driverCache.set(program, driver);
  return driver;
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
    const { text, shown, dynamic: all } = pieces(astNode, scope);
    // the cheap tests first, on every template and concatenation of the code: a statement, with a value where values go
    // (a table or column name chosen in code is the common, safe case), and not markup that carries a query as data
    // (<div data-content="select …">)
    if (!all.length || !SQL.test(text) || /^\s*</.test(text) || !inValuePosition(text)) return null;
    // a list of placeholders built from the values' count or names (ids.map(() => '?').join(), keys.map(k => `@${k}`)) is
    // the statement's own parameters
    const dynamic = all.filter(value => !placeholderList(value, context.ancestors));
    if (!dynamic.length || !inValuePosition(text, all.map(value => !dynamic.includes(value)))) return null;

    // the value may be a parameter of an outer function: new Promise(async resolve => query(`… ${id}`)) inside a handler
    let source;
    let fromSource = false;
    let secondOrder = false;
    for (let i = context.ancestors.length - 1, depth = 0; i >= 0 && depth < 4 && !fromSource; i--) {
      const fn = context.ancestors[i];
      if (!/Function/.test(fn.type)) continue;
      depth++;
      const found = untrustedSource(context.ancestors.slice(0, i + 1), fn);
      if (!found || !dynamic.some(value => dependsOnParams(value, fn))) continue;
      // the message's value chose which rows an earlier query read, and this one inserts a field of those rows
      if (onlyThroughQueries(dynamic, fn)) { secondOrder = true; source = found; break; }
      source = found;
      fromSource = true;
    }
    const statement = shown.replace(/\s+/g, ' ').trim().slice(0, 160);
    const values = [...new Set(dynamic.map(shownValue))].filter(v => v !== '…');
    const driver = driverOf(context.ancestors[0] && context.ancestors[0].type === 'Program' ? context.ancestors[0] : context.ancestors.find(n => n.type === 'Program'));
    const origin = fromSource ? ` (values come from ${source})` : secondOrder ? ` (values read by an earlier query, whose rows were chosen by ${source})` : ' (check where the values come from)';
    return [finding(this, astNode, { severity: fromSource ? severity.HIGH : severity.MEDIUM, confidence: fromSource || secondOrder ? confidence.FIRM : confidence.TENTATIVE,
      manualReview: true, properties: { statement, values, source: fromSource ? source : undefined, ...(secondOrder ? { secondOrder: true, chosenBy: source } : {}), ...(driver ? { driver } : {}) },
      description: `${this.description}: ${statement}${origin}` })];
  }
}
