// Shared AST helpers for checks. They work on ESTree (espree, TypeScript ESTree) and Babel ASTs alike.
import { getKeys } from 'eslint-visitor-keys';
import { visitorKeys } from '@typescript-eslint/visitor-keys';

const isNode = (x) => x !== null && typeof x === 'object' && typeof x.type === 'string';
const keysOf = (node) => visitorKeys[node.type] || getKeys(node);

const FUNCTION_TYPES = ['FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration', 'ObjectMethod', 'ClassMethod'];

export function isFunction(node) {
  return !!node && FUNCTION_TYPES.includes(node.type);
}

/**
 * Walks every node below (and including) `node`. `enter(node, ancestors)` may return false to skip the children.
 */
export function visit(node, enter, ancestors = []) {
  if (!isNode(node)) return;
  if (enter(node, ancestors) === false) return;
  ancestors.push(node);
  for (const key of keysOf(node)) {
    if (key === 'parent') continue;
    const child = node[key];
    if (Array.isArray(child)) child.forEach(c => visit(c, enter, ancestors));
    else visit(child, enter, ancestors);
  }
  ancestors.pop();
}

// Name of a property key or member property: `a.b`, `a['b']`, `{ b: 1 }`, `{ 'b': 1 }`
export function keyName(node) {
  if (!node) return undefined;
  if (node.type === 'Identifier' || node.type === 'PrivateName') return node.name;
  if (typeof node.value === 'string' || typeof node.value === 'number') return String(node.value);
  return undefined;
}

export function memberName(node) {
  if (!node || (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression')) return undefined;
  return keyName(node.property);
}

// `ipcMain` for `ipcMain.handle`, `electron.ipcMain.handle` and `require('electron').ipcMain.handle`
export function calleeObjectName(callee) {
  if (!callee || (callee.type !== 'MemberExpression' && callee.type !== 'OptionalMemberExpression')) return undefined;
  const object = callee.object;
  if (object.type === 'Identifier') return object.name;
  if (object.type === 'MemberExpression' || object.type === 'OptionalMemberExpression') return keyName(object.property);
  return undefined;
}

export function calleeMethodName(node) {
  if (!node || (node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression')) return undefined;
  if (node.callee.type === 'Identifier') return node.callee.name;
  return memberName(node.callee);
}

export function isProperty(node) {
  return !!node && (node.type === 'Property' || node.type === 'ObjectProperty');
}

// Literal value of a node (booleans, strings, numbers), or undefined when it can't be determined statically
export function literalValue(node) {
  if (!node) return undefined;
  if (['Literal', 'StringLiteral', 'BooleanLiteral', 'NumericLiteral'].includes(node.type)) return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0].value.cooked;
  if (node.type === 'UnaryExpression' && node.operator === '!' && typeof literalValue(node.argument) === 'number')
    return !literalValue(node.argument);
  if (node.type === 'UnaryExpression' && (node.operator === '-' || node.operator === '+') && typeof literalValue(node.argument) === 'number')
    return node.operator === '-' ? -literalValue(node.argument) : literalValue(node.argument);
  if (node.type === 'TSAsExpression' || node.type === 'TSSatisfiesExpression' || node.type === 'TSNonNullExpression')
    return literalValue(node.expression);
  return undefined;
}

// Direct properties of an object expression, as [name, valueNode, propertyNode]
export function objectProperties(node) {
  if (!node || (node.type !== 'ObjectExpression')) return [];
  return node.properties
    .filter(isProperty)
    .map(p => [p.computed ? (memberName(p.key) ?? keyName(p.key)) : keyName(p.key), p.value, p])
    .filter(([name]) => name !== undefined);
}

export function findProperty(node, name) {
  return objectProperties(node).find(([key]) => key === name);
}

// Follows an identifier to the object/function it was initialized with, when the scope analysis knows about it
export function resolveIdentifier(node, scope) {
  if (!node || node.type !== 'Identifier' || !scope || typeof scope.getVarInScope !== 'function') return node;
  try {
    const variable = scope.getVarInScope(node.name);
    const def = variable && variable.defs && variable.defs[0];
    if (!def) return node;
    // only plain `const x = ...`, destructuring (`const { x } = require(...)`) doesn't give x's value
    if (def.node && def.node.init && def.node.id && def.node.id.type === 'Identifier') return def.node.init;
    if (def.type === 'FunctionName') return def.node;
  } catch {
    // scope information is best effort
  }
  return node;
}

// The webPreferences object of a `new BrowserWindow(...)` / `new BrowserView(...)` / `new WebContentsView(...)`, if static
export function webPreferencesOf(newExpression, scope) {
  if (!newExpression.arguments || newExpression.arguments.length === 0) return undefined;
  const options = resolveIdentifier(newExpression.arguments[0], scope);
  const prefs = findProperty(options, 'webPreferences');
  return prefs ? resolveIdentifier(prefs[1], scope) : undefined;
}

export const WINDOW_CONSTRUCTORS = ['BrowserWindow', 'BrowserView', 'WebContentsView'];

export function isWindowConstructor(node) {
  if (!node || node.type !== 'NewExpression') return false;
  const name = node.callee.type === 'Identifier' ? node.callee.name : memberName(node.callee);
  return WINDOW_CONSTRUCTORS.includes(name);
}

// Builds a finding in the shape expected by the Finder
export function finding(check, node, { severity, confidence, manualReview = false, properties, description } = {}) {
  const loc = (node && node.loc) ? node.loc.start : { line: 1, column: 0 };
  return {
    line: loc.line,
    column: loc.column,
    id: check.id,
    description: description || check.description,
    shortenedURL: check.shortenedURL,
    severity,
    confidence,
    manualReview,
    properties
  };
}
