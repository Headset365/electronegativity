// Static analysis helpers that let checks reason about what code does, not only which APIs it calls.
// They are deliberately conservative: when a question can't be answered statically they return `undefined`,
// and checks then fall back to a lower confidence.
import { isFunction, memberName, keyName, literalValue, resolveIdentifier, visit } from './helpers.js';

const isCall = (node) => !!node && (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression');
const isMember = (node) => !!node && (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression');

// Innermost function enclosing the current node
export function enclosingFunction(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) if (isFunction(ancestors[i])) return ancestors[i];
  return undefined;
}

// Names bound by the parameters of a function, including destructuring: ({ url }, ...rest) -> ['url', 'rest']
export function paramNames(fn) {
  const names = [];
  const collect = (p) => {
    if (!p) return;
    if (p.type === 'Identifier') names.push(p.name);
    else if (p.type === 'AssignmentPattern') collect(p.left);
    else if (p.type === 'RestElement') collect(p.argument);
    else if (p.type === 'ObjectPattern') p.properties.forEach(prop => collect(prop.value || prop.argument));
    else if (p.type === 'ArrayPattern') p.elements.forEach(collect);
    else if (p.type === 'TSParameterProperty') collect(p.parameter);
  };
  (fn && fn.params || []).forEach(collect);
  return names;
}

// Identifiers read by an expression
export function identifiersIn(node) {
  const names = new Set();
  visit(node, (n, ancestors) => {
    const parent = ancestors[ancestors.length - 1];
    // skip property names: `a.b` reads a, not b
    if (n.type === 'Identifier' && !(parent && isMember(parent) && parent.property === n && !parent.computed)) names.add(n.name);
  });
  return names;
}

/**
 * The statically known value of an expression: literals, constants, template literals and string concatenation of those.
 * Returns undefined when the value depends on runtime data.
 */
export function constantValue(node, scope, depth = 0) {
  if (!node || depth > 5) return undefined;
  const literal = literalValue(node);
  if (literal !== undefined) return literal;
  if (node.type === 'Identifier') {
    const resolved = resolveIdentifier(node, scope);
    return resolved !== node ? constantValue(resolved, scope, depth + 1) : undefined;
  }
  if (node.type === 'TemplateLiteral') {
    let out = '';
    for (let i = 0; i < node.quasis.length; i++) {
      out += node.quasis[i].value.cooked;
      if (i < node.expressions.length) {
        const v = constantValue(node.expressions[i], scope, depth + 1);
        if (v === undefined) return undefined;
        out += v;
      }
    }
    return out;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = constantValue(node.left, scope, depth + 1);
    const right = constantValue(node.right, scope, depth + 1);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}

// Values an expression can take: both branches of `a ? b : c`, or its constant value (undefined when unknown)
export function possibleValues(node, scope) {
  if (node && node.type === 'ConditionalExpression')
    return [...possibleValues(node.consequent, scope), ...possibleValues(node.alternate, scope)];
  return [constantValue(node, scope)];
}

// The constant prefix of a string expression: `https://example.com/${path}` -> 'https://example.com/'
export function constantPrefix(node, scope) {
  if (!node) return undefined;
  const whole = constantValue(node, scope);
  if (typeof whole === 'string') return whole;
  if (node.type === 'TemplateLiteral') return node.quasis[0].value.cooked;
  if (node.type === 'BinaryExpression' && node.operator === '+') return constantPrefix(node.left, scope);
  return undefined;
}

/**
 * Does `fn` inspect a URL before using it? Looks for URL parsing and origin/protocol/host comparisons,
 * prefix checks, allowlists and validation helpers (isSafeUrl(), validateUrl(), ...).
 */
export function hasUrlValidation(fn) {
  let found = false;
  visit(fn && (fn.body || fn), (n) => {
    if (found) return false;
    if (n.type === 'NewExpression' && n.callee.type === 'Identifier' && n.callee.name === 'URL') found = true;
    const name = isCall(n) ? (n.callee.type === 'Identifier' ? n.callee.name : memberName(n.callee)) : undefined;
    if (name && /^(startsWith|endsWith|test|match|includes|has|indexOf|parse|canParse)$/.test(name)) found = true;
    if (name && /(valid|allow|trust|safe|whitelist|permit|isInternal|isExternal|checkUrl|checkOrigin)/i.test(name)) found = true;
    if (isMember(n) && /^(protocol|origin|host|hostname)$/.test(memberName(n) || '')) found = true;
    return true;
  });
  return found;
}

/**
 * Is `node` only reached under a condition, between `node` and `boundary` (a function, by default the enclosing one)?
 * Covers if/else, ternaries, `a && b()`, switch cases, loops, catch blocks and early returns (`if (!ok) return;`).
 */
export function isConditional(node, ancestors, boundary = enclosingFunction(ancestors)) {
  const start = boundary ? ancestors.indexOf(boundary) : -1;
  const chain = [...ancestors.slice(start + 1), node];
  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i];
    const child = chain[i + 1];
    if (parent.type === 'IfStatement' && child !== parent.test) return true;
    if (parent.type === 'ConditionalExpression' && child !== parent.test) return true;
    if (parent.type === 'LogicalExpression' && child === parent.right) return true;
    if (['SwitchCase', 'CatchClause', 'ForStatement', 'ForInStatement', 'ForOfStatement', 'WhileStatement', 'DoWhileStatement'].includes(parent.type)) return true;
    // statements after an early exit: if (!allowed) return;
    if (parent.type === 'BlockStatement' || parent.type === 'Program') {
      const index = parent.body.indexOf(child);
      if (parent.body.slice(0, index).some(s => s.type === 'IfStatement' && exits(s.consequent))) return true;
    }
  }
  return false;
}

function exits(statement) {
  let found = false;
  visit(statement, (n) => {
    if (found || isFunction(n)) return false;
    if (n.type === 'ReturnStatement' || n.type === 'ThrowStatement' || n.type === 'ContinueStatement' || n.type === 'BreakStatement') found = true;
    return true;
  });
  return found;
}

// Calls inside `fn` (not inside nested functions unless `nested`) whose callee matches `predicate(call, name)`
export function callsIn(fn, predicate, { nested = true } = {}) {
  const calls = [];
  const ancestorsOf = new Map();
  visit(fn && (fn.body || fn), (n, ancestors) => {
    if (!nested && n !== fn && isFunction(n)) return false;
    if (isCall(n)) {
      const name = n.callee.type === 'Identifier' ? n.callee.name : memberName(n.callee);
      if (predicate(n, name)) { calls.push(n); ancestorsOf.set(n, [...ancestors]); }
    }
    return true;
  });
  return calls.map(call => ({ call, ancestors: [fn, ...ancestorsOf.get(call)] }));
}

// Values a function can return: `return x` statements, or the body of an arrow function with an expression body
export function returnedValues(fn) {
  if (!fn) return [];
  if (fn.body && fn.body.type !== 'BlockStatement') return [{ value: fn.body, ancestors: [fn] }];
  const values = [];
  visit(fn.body, (n, ancestors) => {
    if (n !== fn.body && isFunction(n)) return false;
    if (n.type === 'ReturnStatement' && n.argument) values.push({ value: n.argument, ancestors: [fn, ...ancestors] });
    return true;
  });
  return values;
}

/**
 * How a handler answers through its callback parameter (e.g. `callback(true)` in a permission handler).
 * Returns { always: bool, sometimes: bool, never: bool } for the given literal value.
 */
export function callbackAnswers(fn, callbackIndex, grantValue, scope) {
  const params = fn && fn.params || [];
  const callbackParam = params[callbackIndex];
  const callbackName = callbackParam && callbackParam.type === 'Identifier' ? callbackParam.name : undefined;
  if (!callbackName) return { always: false, sometimes: false, never: true, unknown: true };

  const calls = callsIn(fn, (call) => call.callee.type === 'Identifier' && call.callee.name === callbackName);
  const matches = (v) => typeof grantValue === 'function' ? grantValue(v) : v === grantValue;
  // callback(cond ? a : b) can answer either way: grants if any branch grants
  const grants = calls.filter(({ call }) => possibleValues(call.arguments[0], scope).some(matches));
  const dynamic = calls.filter(({ call }) => call.arguments[0] && possibleValues(call.arguments[0], scope).includes(undefined));
  const unconditional = grants.filter(({ call, ancestors }) => !isConditional(call, ancestors, fn) && possibleValues(call.arguments[0], scope).every(matches));
  return {
    always: unconditional.length > 0,
    sometimes: grants.length > 0 || dynamic.length > 0,
    never: grants.length === 0 && dynamic.length === 0,
    unknown: dynamic.length > 0,
  };
}

// The function a handler argument refers to (inline or declared elsewhere in the file)
export function handlerFunction(node, scope) {
  const resolved = resolveIdentifier(node, scope);
  return isFunction(resolved) ? resolved : undefined;
}

// Names bound by a declaration pattern: const { a, b: [c] } = ... -> ['a', 'c']
function patternNames(pattern) {
  return paramNames({ params: [pattern] });
}

const taintCache = new WeakMap();

/**
 * Variables of `fn` holding data derived from its parameters: the parameters themselves, plus locals
 * assigned from them (`const { pathname } = new URL(request.url)`), followed until nothing changes.
 */
export function taintedNames(fn) {
  if (taintCache.has(fn)) return taintCache.get(fn);
  const tainted = new Set(paramNames(fn));
  const assignments = [];
  visit(fn.body, (n) => {
    if (n.type === 'VariableDeclarator' && n.init) assignments.push([patternNames(n.id), n.init]);
    if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier') assignments.push([[n.left.name], n.right]);
    return true;
  });
  let changed = true;
  while (changed) {
    changed = false;
    for (const [names, init] of assignments) {
      if (names.every(name => tainted.has(name))) continue;
      if ([...identifiersIn(init)].some(name => tainted.has(name))) {
        names.forEach(name => tainted.add(name));
        changed = true;
      }
    }
  }
  taintCache.set(fn, tainted);
  return tainted;
}

// Does an expression depend on the parameters of `fn` (i.e. on data handed to the handler), directly or through locals?
export function dependsOnParams(node, fn) {
  if (!fn) return false;
  const tainted = taintedNames(fn);
  return [...identifiersIn(node)].some(name => tainted.has(name));
}

// Is the current code inside a listener/handler for untrusted input? Returns a description of the source, or undefined.
const UNTRUSTED_SOURCES = [
  { test: (call, name, objName) => ['handle', 'handleOnce', 'on', 'once'].includes(name) && /^ipcMain$/.test(objName || ''), source: 'an IPC message from a renderer' },
  { test: (call, name) => name === 'setWindowOpenHandler', source: 'a window.open() call or link in web content' },
  { test: (call, name) => ['on', 'once'].includes(name) && ['will-navigate', 'will-frame-navigate', 'did-start-navigation', 'new-window', 'will-redirect'].includes(literalValue(call.arguments[0])), source: 'a navigation requested by web content' },
  { test: (call, name, objName) => ['on', 'once'].includes(name) && objName === 'app' && ['open-url', 'open-file', 'second-instance'].includes(literalValue(call.arguments[0])), source: 'a deep link, file association or command line' },
  { test: (call, name) => ['on', 'once'].includes(name) && ['message', 'ipc-message'].includes(literalValue(call.arguments[0])), source: 'a message from web content' },
];

function sourceOfCall(call) {
  if (!isCall(call)) return undefined;
  const name = memberName(call.callee);
  const object = call.callee && call.callee.object;
  const objName = object && (object.type === 'Identifier' ? object.name : memberName(object));
  const match = UNTRUSTED_SOURCES.find(s => s.test(call, name, objName));
  return match ? match.source : undefined;
}

const registrationCache = new WeakMap();

// Named functions registered as handlers elsewhere in the file: ipcMain.handle('open', openFile)
function registeredSource(program, name) {
  if (!registrationCache.has(program)) {
    const registered = new Map();
    visit(program, (n) => {
      const source = sourceOfCall(n);
      if (source) n.arguments.filter(a => a.type === 'Identifier').forEach(a => registered.set(a.name, source));
      return true;
    });
    registrationCache.set(program, registered);
  }
  return registrationCache.get(program).get(name);
}

export function untrustedSource(ancestors, fn) {
  const index = ancestors.lastIndexOf(fn);
  // inline handler: ipcMain.handle('x', (event, arg) => ...)
  const direct = index > 0 ? sourceOfCall(ancestors[index - 1]) : undefined;
  if (direct) return direct;

  // functions exposed to the page through contextBridge are called with whatever the page passes
  for (let i = index - 1; i >= 0; i--) {
    const node = ancestors[i];
    if (isCall(node) && ['exposeInMainWorld', 'exposeInIsolatedWorld'].includes(memberName(node.callee))) return 'the web page (through contextBridge)';
  }

  // named handler: function openFile(event, path) {...} ... ipcMain.handle('open', openFile)
  const name = fn && fn.id ? fn.id.name : (index > 0 && ancestors[index - 1].type === 'VariableDeclarator' && ancestors[index - 1].id.type === 'Identifier' ? ancestors[index - 1].id.name : undefined);
  const program = ancestors.find(n => n.type === 'Program') || ancestors[0];
  return name && program ? registeredSource(program, name) : undefined;
}

export { isCall, isMember, keyName, visit };
