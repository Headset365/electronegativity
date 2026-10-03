// Static analysis helpers that let checks reason about what code does, not only which APIs it calls.
// They are deliberately conservative: when a question can't be answered statically they return `undefined`,
// and checks then fall back to a lower confidence.
import { isFunction, memberName, keyName, literalValue, resolveIdentifier, visit, isWindowConstructor, combineAssignments, isScalarInit } from './helpers.js';

// The file being analyzed and the project index, set by the Finder before each file
let analysisContext = { file: undefined, program: undefined, index: undefined };

export function setAnalysisContext(context) {
  analysisContext = { ...analysisContext, ...context };
}

// Runs `fn` as if analyzing another file (to evaluate a value defined there)
export function inFile(file, program, fn, ancestors = []) {
  const previous = analysisContext;
  analysisContext = { ...analysisContext, file, program, ancestors };
  try {
    return fn();
  } finally {
    analysisContext = previous;
  }
}

export function currentAnalysisContext() { return analysisContext; }

// A callable together with its lexical/module context, for evaluating small local or imported helpers.
export function functionDefinition(callee, scope) {
  if (!callee) return undefined;
  const imported = callee.type === 'Identifier' && importedDefinition(callee.name);
  if (imported && isFunction(imported.node)) return imported;
  const fn = handlerFunction(callee, scope, analysisContext.ancestors || []);
  return fn && { node: fn, file: analysisContext.file, program: analysisContext.program };
}

// CommonJS loaders keep their identity through aliases and Node's createRequire factory.
export function isModuleLoader(callee, scope, depth = 0) {
  if (!callee || depth > 6) return false;
  const shadowed = name => (analysisContext.ancestors || []).some(fn => isFunction(fn) && paramNames(fn).includes(name));
  if (callee.type === 'Identifier') {
    if (shadowed(callee.name)) return false;
    const resolved = resolveLocal(callee, scope);
    if (resolved !== callee) return isModuleLoader(resolved, scope, depth + 1);
    return callee.name === 'require' && !moduleBindings(analysisContext.program).has(callee.name);
  }
  if (isMember(callee) && memberName(callee) === 'require' && callee.object.name === 'module')
    return !shadowed('module') && resolveLocal(callee.object, scope) === callee.object;
  if (!isCall(callee)) return false;
  const factory = callee.callee;
  const object = isMember(factory) ? factory.object : undefined;
  const reference = object || factory;
  if (reference.type === 'Identifier' && shadowed(reference.name)) return false;
  const binding = reference.type === 'Identifier' && moduleBindings(analysisContext.program).get(reference.name);
  if (binding && ['module', 'node:module'].includes(binding.module)) {
    const imported = object ? memberName(factory) : binding.imported;
    return imported === 'createRequire';
  }
  return object && isCall(object) && isModuleLoader(object.callee, scope, depth + 1) &&
    ['module', 'node:module'].includes(constantValue(object.arguments[0], scope)) && memberName(factory) === 'createRequire';
}

/**
 * Resolves an identifier to the value it was declared with. Uses scope analysis when available, and otherwise
 * (TypeScript files, other files) looks for `const name = ...` / `function name` in the enclosing blocks.
 */
export function resolveLocal(node, scope) {
  const resolved = resolveIdentifier(node, scope);
  if (resolved !== node || !node || node.type !== 'Identifier') return resolved;
  const declaration = lexicalDeclaration(node.name);
  if (!declaration) return node;
  if (declaration.type !== 'VariableDeclarator') return declaration;
  // a let/var assigned again in the block that declares it: combine the assignments (see combineAssignments)
  const writes = declaration.kind !== 'const' && declaration.block && isScalarInit(declaration.init) ? assignmentsTo(declaration.block, node.name) : [];
  return writes.length > 0 ? combineAssignments(declaration.init, writes) : declaration.init;
}

const assignmentCache = new WeakMap();

// `name = ...` and `name += ...` inside `block`, in source order (nested functions included: they run later, but may run)
function assignmentsTo(block, name) {
  if (!assignmentCache.has(block)) {
    const byName = new Map();
    visit(block, (n) => {
      if (n.type === 'AssignmentExpression' && n.left && n.left.type === 'Identifier') {
        if (!byName.has(n.left.name)) byName.set(n.left.name, []);
        byName.get(n.left.name).push({ operator: n.operator, right: n.right });
      }
      return true;
    });
    assignmentCache.set(block, byName);
  }
  return assignmentCache.get(block).get(name) || [];
}

// `const name = ...` (with an initializer) or `function name` declared in a block enclosing the current node. Variable
// declarators are returned with the declaration's kind and the block, to find later assignments of a let/var.
function lexicalDeclaration(name) {
  const ancestors = analysisContext.ancestors || [];
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const block = ancestors[i];
    const body = block.type === 'BlockStatement' || block.type === 'Program' || block.type === 'StaticBlock' ? block.body : undefined;
    if (!Array.isArray(body)) continue;
    for (const statement of body) {
      const declaration = statement && statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
      if (!declaration) continue;
      if (declaration.type === 'FunctionDeclaration' && declaration.id && declaration.id.name === name) return declaration;
      if (declaration.type === 'VariableDeclaration') {
        const d = declaration.declarations.find(d => d.id.type === 'Identifier' && d.id.name === name && d.init);
        if (d) return Object.assign(Object.create(d), { kind: declaration.kind, block, init: d.init, type: d.type, id: d.id });
      }
    }
  }
  return undefined;
}

/**
 * Scope stand-in for TypeScript files, which eslint-scope can't analyze: resolves names to their declarations in the
 * blocks enclosing the node being matched, so `const options: any = {...}; new BrowserWindow(options)` is understood.
 */
export class LexicalScope {
  updateFunctionScope() {}

  getVarInScope(name) {
    const declaration = lexicalDeclaration(name);
    if (!declaration) return null;
    if (declaration.type !== 'VariableDeclarator') return { defs: [{ type: 'FunctionName', node: declaration }] };
    // a let/var assigned again later: its value combines the assignments
    const writes = declaration.kind !== 'const' && isScalarInit(declaration.init) ? assignmentsTo(declaration.block, name) : [];
    const node = writes.length > 0 ? { type: 'VariableDeclarator', id: declaration.id, init: combineAssignments(declaration.init, writes) } : declaration;
    return { defs: [{ type: 'Variable', node }] };
  }

  resolveVarValue(astNode) {
    return isWindowConstructor(astNode) ? resolveWindowOptions(astNode, this) : resolveLocal(astNode.arguments[0], this);
  }
}

/**
 * The node a name imported from another file of the project refers to: { node, file, program } or undefined.
 * import { handler } from './handlers'; const { URL_BASE } = require('./constants');
 */
export function importedDefinition(name, program = analysisContext.program) {
  const { index, file } = analysisContext;
  if (!index || !file || !program) return undefined;
  const binding = moduleBindings(program).get(name);
  if (!binding) return undefined;
  return index.lookup(file, binding.module, binding.imported === '*' ? 'default' : binding.imported);
}

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
    const resolved = resolveLocal(node, scope);
    if (resolved !== node) return constantValue(resolved, scope, depth + 1);
    // top-level constants of the file, when scope information is unavailable (e.g. evaluating another file)
    const local = topLevelConstant(analysisContext.program, node.name);
    if (local) return constantValue(local, null, depth + 1);
    const imported = importedDefinition(node.name);
    return imported ? inFile(imported.file, imported.program, () => constantValue(imported.node, null, depth + 1)) : undefined;
  }
  // imported namespace members: Constants.RELEASE_NOTES_URL
  if (node.type === 'MemberExpression' && !node.computed && node.object.type === 'Identifier') {
    const binding = analysisContext.program && moduleBindings(analysisContext.program).get(node.object.name);
    if (binding && binding.imported === '*' && analysisContext.index) {
      const found = analysisContext.index.lookup(analysisContext.file, binding.module, memberName(node));
      if (found) return inFile(found.file, found.program, () => constantValue(found.node, null, depth + 1));
    }
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
  // a variable assigned several constants (see combineAssignments) is developer-controlled: its last value stands in
  if (node.type === 'ConditionalExpression' && node.assignments) {
    const first = constantValue(node.consequent, scope, depth + 1);
    const second = constantValue(node.alternate, scope, depth + 1);
    return first === undefined || second === undefined ? undefined : second;
  }
  return undefined;
}

/**
 * Whether every piece an expression is assembled from is a constant: `cond ? '<b>a</b>' : '<i>b</i>'`,
 * '<div class="' + (open ? 'open' : '') + '">'. Such a value is chosen by the developer, not taken from data, even though
 * it has no single constant value.
 */
export function onlyConstantParts(node, scope, depth = 0) {
  if (!node || depth > 8) return false;
  if (constantValue(node, scope) !== undefined) return true;
  switch (node.type) {
    case 'ConditionalExpression':
      return onlyConstantParts(node.consequent, scope, depth + 1) && onlyConstantParts(node.alternate, scope, depth + 1);
    case 'LogicalExpression':
      return onlyConstantParts(node.left, scope, depth + 1) && onlyConstantParts(node.right, scope, depth + 1);
    case 'BinaryExpression':
      return node.operator === '+' && onlyConstantParts(node.left, scope, depth + 1) && onlyConstantParts(node.right, scope, depth + 1);
    case 'TemplateLiteral':
      return node.expressions.every(expression => onlyConstantParts(expression, scope, depth + 1));
    case 'ParenthesizedExpression':
    case 'TSAsExpression':
    case 'TSNonNullExpression':
      return onlyConstantParts(node.expression, scope, depth + 1);
    case 'Identifier': {
      const resolved = resolveLocal(node, scope);
      return resolved !== node && onlyConstantParts(resolved, scope, depth + 1);
    }
    default:
      return false;
  }
}

// Values an expression can take: both branches of `a ? b : c`, or its constant value (undefined when unknown)
export function possibleValues(node, scope, depth = 0) {
  if (!node || depth > 5) return [undefined];
  if (node.type === 'ConditionalExpression')
    return [...possibleValues(node.consequent, scope, depth + 1), ...possibleValues(node.alternate, scope, depth + 1)];
  const constant = constantValue(node, scope);
  if (constant !== undefined || node.type !== 'Identifier') return [constant];
  // a name bound to a ternary: const URL = beta ? 'https://a' : 'https://b' (possibly in another file)
  const resolved = resolveLocal(node, scope);
  if (resolved !== node) return possibleValues(resolved, scope, depth + 1);
  const local = topLevelConstant(analysisContext.program, node.name);
  if (local) return possibleValues(local, null, depth + 1);
  const imported = importedDefinition(node.name);
  return imported ? inFile(imported.file, imported.program, () => possibleValues(imported.node, null, depth + 1)) : [undefined];
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
    if (name && /(valid|allow|trust|safe|whitelist|permit|sanitiz|isInternal|isExternal|checkUrl|checkOrigin)/i.test(name)) found = true;
    // predicates like isTeamUrl(url), isCustomProtocol(url), hasPermission(origin)
    if (name && /^(is|has|can|should|check|verify|ensure|assert)[A-Z_]/.test(name) && n.arguments && n.arguments.length > 0) found = true;
    if (isMember(n) && /^(protocol|origin|host|hostname)$/.test(memberName(n) || '')) found = true;
    // const { protocol } = new URL(target), maybeParseUrl(target)
    if (n.type === 'ObjectPattern' && n.properties.some(p => /^(protocol|origin|host|hostname)$/.test(keyName(p.key) || ''))) found = true;
    if (name && /parse_?ur[il]/i.test(name)) found = true;
    return true;
  });
  return found;
}

// Only a guard referring to the URL reaching this sink may downgrade it. Merely parsing a URL elsewhere in a
// function, or checking an unrelated parameter, provides no protection.
export function urlArgumentIsGuarded(call, value, scope, ancestors, fn) {
  const related = urlRelatedNames(urlReads(value), fn);
  const unchanged = guard => {
    let changed = false;
    const after = (a, b) => a?.loc && b?.loc && (a.loc.start.line > b.loc.start.line ||
      (a.loc.start.line === b.loc.start.line && a.loc.start.column > b.loc.start.column));
    visit(fn.body, node => {
      if (node.type === 'AssignmentExpression' && [...urlReads(node.left)].some(name => related.has(name)) && after(node, guard) && after(call, node)) changed = true;
      return node === fn.body || !isFunction(node);
    });
    return !changed;
  };
  const start = ancestors.indexOf(fn);
  const chain = [...ancestors.slice(start + 1), call];
  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i], child = chain[i + 1];
    if ((parent.type === 'IfStatement' || parent.type === 'ConditionalExpression') && child !== parent.test &&
      unchanged(parent.test) && urlPredicateAllows(parent.test, child === parent.consequent, related, scope)) return true;
    if (parent.type === 'LogicalExpression' && child === parent.right && unchanged(parent.left) &&
      urlPredicateAllows(parent.left, parent.operator === '&&', related, scope)) return true;
    if (parent.type === 'BlockStatement') {
      const position = parent.body.indexOf(child);
      if (position < 0) continue;
      if (parent.body.slice(0, position).some(statement => statement.type === 'IfStatement' &&
        guardExits(statement.consequent) && unchanged(statement.test) && urlPredicateAllows(statement.test, false, related, scope))) return true;
    }
  }
  return false;
}

function urlReads(node) {
  const names = new Set();
  visit(node, (n, chain) => {
    const parent = chain.at(-1);
    if (isCall(parent) && parent.callee === n && !(isMember(n) && ['toString', 'toJSON'].includes(memberName(n)))) return false;
    if (n.type === 'Identifier' && !(isMember(parent) && parent.property === n && !parent.computed)) names.add(n.name);
    return true;
  });
  return names;
}

function urlRelatedNames(names, fn) {
  const related = new Set(names), aliases = [];
  visit(fn?.body, node => {
    if (node.type === 'VariableDeclarator' && node.init) {
      for (const name of paramNames({ params: [node.id] })) aliases.push([name, node.init]);
    }
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier') aliases.push([node.left.name, node.right]);
    return node === fn?.body || !isFunction(node);
  });
  for (let depth = 0; depth < 6; depth++) for (const [name, init] of aliases) {
    const reads = [...urlReads(init)];
    if (related.has(name)) reads.forEach(read => related.add(read));
    if (reads.some(read => related.has(read))) related.add(name);
  }
  return related;
}

function guardExits(node) {
  if (!node) return false;
  if (['ReturnStatement', 'ThrowStatement'].includes(node.type)) return true;
  if (node.type === 'BlockStatement') return node.body.some(guardExits);
  return node.type === 'IfStatement' && guardExits(node.consequent) && guardExits(node.alternate);
}

// A true AND or false OR guarantees each operand; their opposite paths must all be restrictive.
function urlPredicateAllows(test, accepted, related, scope, depth = 0) {
  if (!test || depth > 6) return false;
  if (test.type === 'UnaryExpression' && test.operator === '!') return urlPredicateAllows(test.argument, !accepted, related, scope, depth + 1);
  if (test.type === 'LogicalExpression') {
    const checks = [test.left, test.right].map(node => urlPredicateAllows(node, accepted, related, scope, depth + 1));
    return (test.operator === '&&') === accepted ? checks.some(Boolean) : checks.every(Boolean);
  }
  const refers = node => [...urlReads(node)].some(name => related.has(name));
  if (test.type === 'BinaryExpression' && ['===', '==', '!==', '!='].includes(test.operator)) {
    if (['===', '=='].includes(test.operator) !== accepted) return false;
    return [[test.left, test.right], [test.right, test.left]].some(([field, allow]) =>
      /^(protocol|origin|host|hostname)$/.test(isMember(field) ? memberName(field) || '' : field.name || '') &&
      refers(field) && typeof constantValue(allow, scope) === 'string' && constantValue(allow, scope).length > 0);
  }
  if (!isCall(test)) return false;
  const definition = functionDefinition(test.callee, scope);
  if (definition) {
    const names = definition.node.params.flatMap((param, i) => test.arguments[i] && refers(test.arguments[i]) ? paramNames({ params: [param] }) : []);
    if (!names.length) return false;
    return inFile(definition.file, definition.program, () => {
      const returns = returnedValues(definition.node);
      const helperNames = urlRelatedNames(names, definition.node);
      return returns.length > 0 && returns.every(({ value }) => urlPredicateAllows(value, accepted, helperNames, null, depth + 1));
    }, [definition.program, definition.node, definition.node.body]);
  }
  if (!accepted || !isMember(test.callee)) return false;
  const method = memberName(test.callee), target = test.callee.object;
  if (['startsWith', 'endsWith', 'includes'].includes(method)) return refers(target) &&
    typeof constantValue(test.arguments[0], scope) === 'string' && constantValue(test.arguments[0], scope).length > 0;
  if (method === 'test') {
    const regex = resolveLocal(target, scope), pattern = regex?.regex?.pattern || regex?.pattern;
    return !!pattern && pattern.startsWith('^') && !/^\^\.\*/.test(pattern) && test.arguments.some(refers);
  }
  if (method === 'has') return test.arguments.some(refers);
  return false;
}

// A URL created with a fixed origin remains fixed when only its query/hash is changed. Resolve small helper
// return values too; reject reassigned URL objects, origin/path mutations, or unknown methods.
export function fixedUrlPrefix(value, scope, depth = 0) {
  if (!value || depth > 6) return undefined;
  if (value.type === 'Identifier') {
    const resolved = resolveLocal(value, scope);
    return resolved !== value ? fixedUrlPrefix(resolved, scope, depth + 1) : undefined;
  }
  if (value.type === 'NewExpression' && value.callee.name === 'URL') {
    if (resolveLocal(value.callee, scope) !== value.callee) return undefined;
    if ((analysisContext.ancestors || []).some(node => isFunction(node) && paramNames(node).includes('URL'))) return undefined;
    const binding = moduleBindings(analysisContext.program).get('URL');
    if (binding && (!['url', 'node:url'].includes(binding.module) || binding.imported !== 'URL')) return undefined;
    const initial = constantValue(value.arguments[0], scope);
    if (typeof initial !== 'string') return undefined;
    try { const url = new URL(initial); return `${url.origin}/`; } catch { return undefined; }
  }
  if (isMember(value) && ['href', 'origin'].includes(memberName(value))) return fixedUrlObject(value.object, scope, depth + 1);
  if (isCall(value) && isMember(value.callee) && value.arguments.length === 0 && ['toString', 'toJSON'].includes(memberName(value.callee))) return fixedUrlObject(value.callee.object, scope, depth + 1);
  if (isCall(value) && value.type !== 'NewExpression') {
    const definition = functionDefinition(value.callee, scope);
    if (!definition) return undefined;
    return inFile(definition.file, definition.program, () => {
      const values = returnedValues(definition.node);
      const prefixes = values.map(({ value: returned, ancestors }) => inFile(definition.file, definition.program, () => fixedUrlPrefix(returned, null, depth + 1), [definition.program, ...ancestors]));
      return prefixes.length && prefixes.every(prefix => prefix && prefix === prefixes[0]) ? prefixes[0] : undefined;
    }, [definition.program, definition.node, definition.node.body]);
  }
  return undefined;
}

function fixedUrlObject(object, scope, depth) {
  if (object.type !== 'Identifier') return fixedUrlPrefix(object, scope, depth);
  const prefix = fixedUrlPrefix(resolveLocal(object, scope), scope, depth);
  if (!prefix) return undefined;
  let mutated = false;
  const fn = enclosingFunction(analysisContext.ancestors || []);
  const aliases = new Set([object.name]);
  for (let depth = 0; depth < 6; depth++) visit(fn?.body || analysisContext.program, n => {
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init?.type === 'Identifier' && aliases.has(n.init.name)) aliases.add(n.id.name);
    return true;
  });
  visit(fn?.body || analysisContext.program, n => {
    if (n.type === 'AssignmentExpression') {
      if (n.left.type === 'Identifier' && aliases.has(n.left.name)) mutated = true;
      if (isMember(n.left) && n.left.object.type === 'Identifier' && aliases.has(n.left.object.name) && !['search', 'hash'].includes(memberName(n.left))) mutated = true;
    }
    if (isCall(n) && n.arguments.some(arg => arg.type === 'Identifier' && aliases.has(arg.name))) mutated = true;
    if (isCall(n) && isMember(n.callee) && n.callee.object.type === 'Identifier' && aliases.has(n.callee.object.name) && !['toString', 'toJSON'].includes(memberName(n.callee))) mutated = true;
    return !mutated;
  });
  return mutated ? undefined : prefix;
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

// The function a handler argument refers to: inline, declared elsewhere in the file, a method of the enclosing
// class (this.onNavigate, this.onNavigate.bind(this)) or of an object literal in the file (handlers.onNavigate)
export function handlerFunction(node, scope, ancestors = []) {
  if (!node) return undefined;
  // fn.bind(this) and wrappers like once(fn) keep the handler's body
  if (isCall(node) && memberName(node.callee) === 'bind' && isMember(node.callee)) return handlerFunction(node.callee.object, scope, ancestors);
  // factories: on('will-navigate', makeNavigationHandler(log)) analyzes the function the factory returns
  if (isCall(node) && node.type !== 'NewExpression') return factoryProduct(node, scope, ancestors);
  if (isMember(node) && node.object.type === 'ThisExpression') return classMember(ancestors, memberName(node));
  if (isMember(node) && node.object.type === 'Identifier') {
    const object = resolveIdentifier(node.object, scope);
    const prop = object && object.type === 'ObjectExpression' && object.properties.find(p => keyName(p.key) === memberName(node));
    if (prop) return isFunction(prop) ? prop : handlerFunction(prop.value, scope, ancestors);
  }
  const resolved = resolveLocal(node, scope);
  if (isFunction(resolved)) return resolved;
  if (resolved !== node && isCall(resolved)) return factoryProduct(resolved, scope, ancestors);
  // a function declared anywhere in the file (hoisted, or when scope information is unavailable)
  if (node.type === 'Identifier') {
    const declared = declaredFunction(programOf(ancestors) || analysisContext.program, node.name);
    if (declared) return declared;
    // imported from another file of the project
    const imported = importedDefinition(node.name);
    if (imported && isFunction(imported.node)) return imported.node;
  }
  return undefined;
}

const factoryDepth = { current: 0 };

function factoryProduct(call, scope, ancestors) {
  if (factoryDepth.current > 3) return undefined;
  factoryDepth.current++;
  try {
    const factory = handlerFunction(call.callee, scope, ancestors);
    if (!factory) return undefined;
    const product = returnedValues(factory).map(({ value }) => value).find(isFunction);
    return product;
  } finally {
    factoryDepth.current--;
  }
}

// A method, arrow-function field or function-valued property of the class enclosing the current node
function classMember(ancestors, name) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const body = ancestors[i];
    if (body.type !== 'ClassBody') continue;
    for (const member of body.body) {
      if (keyName(member.key) !== name) continue;
      if (isFunction(member)) return member; // Babel ClassMethod
      if (member.value && isFunction(member.value)) return member.value; // MethodDefinition, PropertyDefinition, ClassProperty
      if (member.value && isCall(member.value)) return factoryProduct(member.value, null, ancestors);
    }
    return undefined;
  }
  return undefined;
}

const constantCache = new WeakMap();

function topLevelConstant(program, name) {
  if (!program) return undefined;
  if (!constantCache.has(program)) {
    const constants = new Map();
    for (const statement of program.body || []) {
      const declaration = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
      if (declaration && declaration.type === 'VariableDeclaration' && declaration.kind === 'const')
        declaration.declarations.filter(d => d.id.type === 'Identifier' && d.init).forEach(d => constants.set(d.id.name, d.init));
    }
    constantCache.set(program, constants);
  }
  return constantCache.get(program).get(name);
}

const declarationCache = new WeakMap();

function declaredFunction(program, name) {
  if (!program) return undefined;
  if (!declarationCache.has(program)) {
    const declared = new Map();
    visit(program, (n) => {
      if (n.type === 'FunctionDeclaration' && n.id) declared.set(n.id.name, n);
      if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && isFunction(n.init)) declared.set(n.id.name, n.init);
      return true;
    });
    declarationCache.set(program, declared);
  }
  return declarationCache.get(program).get(name);
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
      // a lookup keyed by untrusted data returns the app's own data: map.get(id), list.find(...)
      if (isLookup(init)) continue;
      if ([...identifiersIn(init)].some(name => tainted.has(name))) {
        names.forEach(name => tainted.add(name));
        changed = true;
      }
    }
  }
  taintCache.set(fn, tainted);
  return tainted;
}

const LOOKUPS = /^(get|has|find|findIndex|findLast|indexOf|includes|some|every|getItem|getPath|getSavePath|fromId|fromWebContents)$/;

function isLookup(node) {
  let n = node;
  while (n && (n.type === 'AwaitExpression' || n.type === 'TSAsExpression' || n.type === 'TSNonNullExpression')) n = n.expression || n.argument;
  return isCall(n) && LOOKUPS.test(memberName(n.callee) || '');
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

export function sourceOfCall(call) {
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
      if (!source) return true;
      n.arguments.filter(a => a.type === 'Identifier').forEach(a => registered.set(a.name, source));
      // helpers the handler passes the untrusted data to: app.on('open-url', (e, url) => processUrl(url))
      for (const handler of n.arguments.filter(isFunction)) {
        visit(handler.body, (inner) => {
          if (inner !== handler.body && isFunction(inner)) return false;
          if (isCall(inner) && inner.callee.type === 'Identifier' && !registered.has(inner.callee.name) &&
              inner.arguments.some(argument => dependsOnParams(argument, handler))) registered.set(inner.callee.name, source);
          return true;
        });
      }
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
  const local = name && program ? registeredSource(program, name) : undefined;
  if (local) return local;
  // helpers reached from a handler in another file, or several calls deep
  const project = analysisContext.index;
  return project && analysisContext.file && fn ? project.untrustedSource(analysisContext.file, fn) : undefined;
}

// Is `fn` only called with constant arguments across the project? (see ProjectIndex.onlyConstantCallers)
export function onlyConstantCallers(fn) {
  const project = analysisContext.index;
  return !!(fn && project && analysisContext.file && project.onlyConstantCallers(analysisContext.file, fn));
}

const bindingCache = new WeakMap();

function requiredModule(node) {
  if (isCall(node) && node.callee.type === 'Identifier' && node.callee.name === 'require') return literalValue(node.arguments[0]);
  if (isCall(node) && /^(?:__importDefault|__importStar|__toESM|_interopRequireDefault|_interopRequireWildcard)$/.test(node.callee.name || '') && node.arguments.length === 1) return requiredModule(node.arguments[0]);
  // await import('m')
  if (node && node.type === 'AwaitExpression') return requiredModule(node.argument);
  if (node && node.type === 'ImportExpression') return literalValue(node.source);
  return undefined;
}

/**
 * Where the names of a file come from: import x from 'm', import { a as b } from 'm', const { a } = require('m'),
 * const cp = require('m'), const run = promisify(exec). Returns Map localName -> { module, imported }
 * (imported is '*' for the whole module).
 */
export function moduleBindings(program) {
  if (bindingCache.has(program)) return bindingCache.get(program);
  const bindings = new Map();
  visit(program, (n) => {
    if (n.type === 'ImportDeclaration') {
      const module = literalValue(n.source);
      for (const spec of n.specifiers) {
        const imported = spec.type === 'ImportSpecifier' ? keyName(spec.imported) : '*';
        bindings.set(spec.local.name, { module, imported });
      }
    }
    if (n.type === 'VariableDeclarator' && n.init) {
      let init = n.init;
      // promisify(exec), util.promisify(cp.exec)
      if (isCall(init) && /^promisify$/.test(init.callee.type === 'Identifier' ? init.callee.name : memberName(init.callee) || '') && init.arguments[0]) {
        const target = init.arguments[0];
        const from = target.type === 'Identifier' ? bindings.get(target.name)
          : (isMember(target) && target.object.type === 'Identifier' && bindings.get(target.object.name)
            ? { module: bindings.get(target.object.name).module, imported: memberName(target) } : undefined);
        if (from && n.id.type === 'Identifier') bindings.set(n.id.name, from);
        return true;
      }
      // require('m').exec
      let imported = '*';
      if (isMember(init) && requiredModule(init.object)) { imported = memberName(init); init = init.object; }
      const module = requiredModule(init);
      if (!module) return true;
      if (n.id.type === 'Identifier') bindings.set(n.id.name, { module, imported });
      if (n.id.type === 'ObjectPattern') {
        for (const prop of n.id.properties) {
          if (prop.type === 'RestElement' || !prop.value) continue;
          const local = prop.value.type === 'AssignmentPattern' ? prop.value.left : prop.value;
          if (local.type === 'Identifier') bindings.set(local.name, { module, imported: keyName(prop.key) });
        }
      }
    }
    return true;
  });
  bindingCache.set(program, bindings);
  return bindings;
}

// The Program node of the file being analyzed
export function programOf(ancestors) {
  return ancestors.find(n => n.type === 'Program') || ancestors[0];
}

export { isCall, isMember, keyName, visit };

// The operating system a piece of code is limited to: 'darwin', 'linux', 'win32', 'non-windows' or 'non-darwin'; undefined
// when it runs everywhere. Read from the enclosing branches (process.platform === 'darwin', os.platform() !== 'win32',
// isMac), early returns (if (process.platform !== 'darwin') return;) and the function's name (openInMac, linuxHelper).
const PLATFORM_NAMES = { darwin: 'darwin', mac: 'darwin', macos: 'darwin', osx: 'darwin', linux: 'linux', win32: 'win32', windows: 'win32', win: 'win32' };
const PLATFORM_FLAG = /^(?:is|on)?(Mac|MacOS|OSX|Darwin|Linux|Windows|Win|Win32)$/i;
// openInMac, runOnLinux, forWindows, macOpen, darwinHelper (not getMacAddress or closeAllWindows)
const NAMED_PLATFORM = /(?:In|On|For|Only)(Mac|MacOS|OSX|Darwin|Linux|Windows|Win32)(?=[A-Z_$0-9]|$)|^(mac|macos|osx|darwin|linux|win32)(?=[A-Z_$0-9]|$)/;
function isPlatformRead(node) {
  if (!node) return false;
  if (isMember(node)) return memberName(node) === 'platform' && (node.object.type === 'Identifier' || isMember(node.object));
  if (isCall(node)) return memberName(node.callee) === 'platform' || (node.callee.type === 'Identifier' && node.callee.name === 'platform');
  return false;
}
// the platform a test selects, and whether it selects it (===) or every other one (!==)
function platformTest(test) {
  if (!test) return undefined;
  if (test.type === 'UnaryExpression' && test.operator === '!') {
    const inner = platformTest(test.argument);
    return inner && { platform: inner.platform, equal: !inner.equal };
  }
  if (test.type === 'Identifier' || isMember(test)) {
    const name = test.type === 'Identifier' ? test.name : memberName(test);
    const flag = PLATFORM_FLAG.exec(name || '');
    return flag && /^is|^on/i.test(name) ? { platform: PLATFORM_NAMES[flag[1].toLowerCase()], equal: true } : undefined;
  }
  if (test.type === 'BinaryExpression' && /^[!=]==?$/.test(test.operator)) {
    const [read, other] = isPlatformRead(test.left) ? [test.left, test.right] : isPlatformRead(test.right) ? [test.right, test.left] : [];
    const value = read && literalValue(other);
    return typeof value === 'string' && PLATFORM_NAMES[value] ? { platform: PLATFORM_NAMES[value], equal: test.operator.startsWith('=') } : undefined;
  }
  return undefined;
}
const otherThan = platform => (platform === 'win32' ? 'non-windows' : platform === 'darwin' ? 'non-darwin' : undefined);
const leavesBlock = (node) => !!node && (['ReturnStatement', 'ThrowStatement'].includes(node.type) || (node.type === 'BlockStatement' && node.body.length === 1 && leavesBlock(node.body[0])));

export function platformGuard(ancestors, node) {
  let child = node;
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const parent = ancestors[i];
    if (parent.type === 'IfStatement' || parent.type === 'ConditionalExpression') {
      const test = platformTest(parent.test);
      if (test && child !== parent.test) {
        const inThen = child === parent.consequent;
        if (inThen === test.equal) return test.platform;
        const other = otherThan(test.platform);
        if (other) return other;
      }
    }
    if (parent.type === 'BlockStatement' || parent.type === 'Program') {
      // if (process.platform !== 'darwin') return;  before this statement
      for (const statement of parent.body) {
        if (statement === child) break;
        if (statement.type !== 'IfStatement' || !leavesBlock(statement.consequent)) continue;
        const test = platformTest(statement.test);
        if (!test) continue;
        if (!test.equal) return test.platform;
        const other = otherThan(test.platform);
        if (other) return other;
      }
    }
    if (isFunction(parent)) {
      const declarator = ancestors[i - 1];
      const name = parent.id?.name || (declarator && declarator.type === 'VariableDeclarator' && declarator.id.type === 'Identifier' ? declarator.id.name : undefined)
        || (declarator && (declarator.type === 'ObjectProperty' || declarator.type === 'Property') ? keyName(declarator.key) : undefined);
      const named = name && NAMED_PLATFORM.exec(name);
      if (named) return PLATFORM_NAMES[(named[1] || named[2]).toLowerCase()];
    }
    child = parent;
  }
  return undefined;
}

const TYPE_WRAPPERS = ['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TSTypeAssertion', 'TypeCastExpression', 'ParenthesizedExpression'];
const unwrapType = (node) => {
  while (node && TYPE_WRAPPERS.includes(node.type)) node = node.expression;
  return node;
};
const isSpread = (node) => node && (node.type === 'SpreadElement' || node.type === 'SpreadProperty' || node.type === 'ExperimentalSpreadProperty');

/**
 * The properties an object value is built from, in evaluation order: `{ ...base, x }`, `Object.assign({}, base, opts)`,
 * `Object.freeze({...})`, and constants declared in this file or imported from another one.
 * Each entry is { property, origin } where `origin` ({ file, program }) is set when the property is defined in another file.
 */
function objectProperties(node, scope, origin, depth = 0) {
  node = unwrapType(node);
  if (!node || depth > 8) return [];
  if (node.type === 'Identifier') {
    const local = resolveLocal(node, scope);
    if (local !== node) return objectProperties(local, scope, origin, depth + 1);
    const constant = topLevelConstant(analysisContext.program, node.name);
    if (constant) return objectProperties(constant, null, origin, depth + 1);
    const imported = importedDefinition(node.name);
    return imported ? inFile(imported.file, imported.program, () => objectProperties(imported.node, null, imported, depth + 1)) : [];
  }
  if (node.type === 'ObjectExpression') {
    return node.properties.flatMap(property => isSpread(property) ? objectProperties(property.argument, scope, origin, depth + 1) : [{ property, origin }]);
  }
  if (node.type === 'CallExpression' && isMember(node.callee) && node.callee.object.type === 'Identifier' && node.callee.object.name === 'Object') {
    const method = memberName(node.callee);
    if (method === 'assign') return node.arguments.flatMap(argument => objectProperties(argument, scope, origin, depth + 1));
    if (method === 'freeze' || method === 'seal') return objectProperties(node.arguments[0], scope, origin, depth + 1);
  }
  return [];
}

// A copy of a node from another file, placed at `loc` and using this file's property node type, so checks can read it
function transplant(node, loc, propertyName) {
  const copy = structuredClone(node);
  visit(copy, (child) => {
    child.loc = loc;
    delete child.range;
    delete child.start;
    delete child.end;
    if ((child.type === 'Property' || child.type === 'ObjectProperty') && propertyName) child.type = propertyName;
  });
  return copy;
}

const needsMerge = (node) => {
  node = unwrapType(node);
  return !node || node.type !== 'ObjectExpression' || node.properties.some(isSpread);
};

/**
 * The options object of `new BrowserWindow(options)`, merged from every place it is built from (spreads, Object.assign,
 * constants imported from a shared config file): the last value of each key wins, as at runtime, and webPreferences is
 * merged the same way. Returns the argument itself when there is nothing to merge.
 */
export function resolveWindowOptions(newExpression, scope) {
  const argument = newExpression.arguments && newExpression.arguments[0];
  if (!argument) return argument;
  const { propertyName } = analysisContext;
  const merge = (node, nodeScope, origin, nested) => {
    const entries = objectProperties(node, nodeScope, origin);
    if (entries.length === 0) return undefined;
    const byKey = new Map();
    const unnamed = [];
    for (const entry of entries) {
      const name = entry.property.computed ? undefined : keyName(entry.property.key);
      if (name === undefined) unnamed.push(entry);
      else {
        byKey.delete(name); // the last definition wins
        byKey.set(name, entry);
      }
    }
    const properties = [...unnamed, ...byKey.values()].map(({ property, origin: from }) => {
      if (!nested && keyName(property.key) === 'webPreferences' && needsMerge(property.value)) {
        const prefs = from ? inFile(from.file, from.program, () => merge(property.value, null, from, true)) : merge(property.value, nodeScope, undefined, true);
        if (prefs) return { ...(from ? transplant(property, newExpression.loc, propertyName) : property), value: prefs };
      }
      return from ? transplant(property, newExpression.loc, propertyName) : property;
    });
    return { type: 'ObjectExpression', properties, loc: newExpression.loc };
  };
  // the common case, a literal without spreads: keep the original node
  const direct = unwrapType(argument);
  if (!needsMerge(direct) && !direct.properties.some(p => keyName(p.key) === 'webPreferences' && needsMerge(p.value))) return direct;
  return merge(argument, scope, undefined, false) || resolveLocal(argument, scope);
}
