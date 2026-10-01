// Bounded, evidence-producing IPC call traversal. A recognized guard is a code pattern, never proof of authorization.
// Unknown callees, recursion and budgets remain visible instead of being treated as safe.
import { isFunction, visit, memberName, keyName, literalValue } from './helpers.js';
import { currentAnalysisContext, inFile, resolveLocal, moduleBindings, paramNames, isCall, isMember, returnedValues, constantValue, handlerFunction } from './analysis.js';

const MAX_DEPTH = 6;
const MAX_CALLS = 160;
const nameOf = node => node?.type === 'Identifier' ? node.name : memberName(node);
const at = (file, node) => ({ file, line: node?.loc?.start.line });
const keyOf = ref => `${ref.file}:${ref.node.start ?? ref.node.loc?.start.line}:${ref.node.loc?.start.column}`;
const union = values => new Set(values.flatMap(value => [...value]));
const withoutFunctions = (node, fn) => visit(node, (n, ancestors) => isFunction(n) ? false : fn(n, ancestors));

export function ipcObject(object, expected, scope, depth = 0) {
  if (!object || depth > MAX_DEPTH) return false;
  if (object.name === expected || memberName(object) === expected) return true;
  if (object.type !== 'Identifier') return false;
  const binding = moduleBindings(currentAnalysisContext().program).get(object.name);
  if (binding && /^(electron|node:electron)$/.test(binding.module) && binding.imported === expected) return true;
  const resolved = resolveLocal(object, scope);
  return resolved !== object && ipcObject(resolved, expected, scope, depth + 1);
}

export function ipcListener(call, scope) {
  let callee = call.callee;
  if (callee?.type === 'Identifier') callee = resolveLocal(callee, scope);
  const method = memberName(callee);
  if (!['on', 'once', 'addListener', 'handle', 'handleOnce'].includes(method)) return undefined;
  return ipcObject(callee.object, 'ipcMain', scope) ? method : undefined;
}

// Preserve the defining file for named imports, namespace/default objects, CommonJS exports and local aliases.
export function ipcDefinition(node, scope, ancestors = [], depth = 0) {
  if (!node || depth > MAX_DEPTH) return undefined;
  const context = currentAnalysisContext();
  if (isFunction(node)) return { node, file: context.file, program: context.program, ancestors };
  if (isCall(node) && memberName(node.callee) === 'bind' && node.arguments.length <= 1) return ipcDefinition(node.callee.object, scope, ancestors, depth + 1);
  if (node.type === 'SequenceExpression') return ipcDefinition(node.expressions.at(-1), scope, ancestors, depth + 1);
  if (['TSAsExpression', 'TSNonNullExpression', 'TypeCastExpression'].includes(node.type)) return ipcDefinition(node.expression, scope, ancestors, depth + 1);
  if (node.type === 'Identifier') {
    const binding = context.program && moduleBindings(context.program).get(node.name);
    if (binding && context.index) {
      const found = context.index.lookup(context.file, binding.module, binding.imported === '*' ? 'default' : binding.imported);
      if (binding.imported === '*' && !isFunction(found?.node)) return { namespace: binding.module, file: context.file, program: context.program };
      if (found) return { ...found, ancestors: [found.program] };
    }
    const local = resolveLocal(node, scope);
    return local && local !== node ? ipcDefinition(local, scope, ancestors, depth + 1) : undefined;
  }
  if (isMember(node) && (!node.computed || literalValue(node.property) !== undefined)) {
    if (node.object.type === 'ThisExpression') {
      const fn = handlerFunction(node, scope, ancestors);
      if (fn) return { node: fn, file: context.file, program: context.program, ancestors };
    }
    const object = ipcDefinition(node.object, scope, ancestors, depth + 1);
    const property = memberName(node);
    if (property === 'default' && isFunction(object?.node)) return object;
    if (object?.namespace) {
      const found = context.index.lookup(object.file, object.namespace, property);
      if (found) return { ...found, ancestors: [found.program] };
      // TypeScript __importDefault(require('./auth')).default on a CommonJS named-export module.
      if (property === 'default') return object;
      const defaultObject = context.index.lookup(object.file, object.namespace, 'default');
      if (defaultObject?.node?.type === 'ObjectExpression') {
        const p = defaultObject.node.properties.find(p => !p.computed && keyName(p.key) === property);
        if (p) return inFile(defaultObject.file, defaultObject.program,
          () => ipcDefinition(isFunction(p) ? p : p.value, null, [defaultObject.program], depth + 1), [defaultObject.program]);
      }
    }
    if (object?.node?.type === 'ObjectExpression') {
      const p = object.node.properties.find(p => !p.computed && keyName(p.key) === property);
      if (p) return inFile(object.file, object.program,
        () => ipcDefinition(isFunction(p) ? p : p.value, null, [object.program], depth + 1), [object.program]);
    }
  }
  return undefined;
}

function references(node, env) {
  const values = [];
  withoutFunctions(node, (n, ancestors) => {
    const parent = ancestors.at(-1);
    if (isMember(n) && !(isCall(parent) && parent.callee === n)) {
      let root = n;
      const fields = [];
      while (isMember(root)) { fields.unshift(root.computed && literalValue(root.property) === undefined ? '*' : memberName(root)); root = root.object; }
      if (root?.type === 'Identifier' && env.objectNames?.has(root.name)) {
        values.push(new Set([...(env.get(root.name) || [])].map(source => source === '$sender' ? source : `${source}.${fields.join('.')}`)));
        return false;
      }
    }
    if (isMember(n) && !n.computed && n.object.type === 'Identifier' && env.has(`${n.object.name}.${memberName(n)}`)) {
      values.push(env.get(`${n.object.name}.${memberName(n)}`));
      return false;
    }
    if (n.type === 'Identifier' && !(isMember(parent) && parent.property === n && !parent.computed)) values.push(env.get(n.name) || new Set());
    return true;
  });
  return union(values);
}

function bind(pattern, sources, env, prefix) {
  if (!pattern) return;
  if (pattern.type === 'Identifier') env.set(pattern.name, new Set(sources));
  else if (pattern.type === 'AssignmentPattern') bind(pattern.left, sources, env, prefix);
  else if (pattern.type === 'RestElement') bind(pattern.argument, sources, env, prefix);
  else if (pattern.type === 'ObjectPattern') pattern.properties.forEach(p => bind(p.value || p.argument,
    prefix ? new Set([`${prefix}.${keyName(p.key) || '*'}`]) : sources, env));
  else if (pattern.type === 'ArrayPattern') pattern.elements.forEach((p, i) => bind(p, prefix ? new Set([`${prefix}[${i}]`]) : sources, env));
}

function environment(fn, supplied, constants = []) {
  const env = new Map();
  env.constants = new Map();
  env.objectNames = new Set(paramNames(fn));
  fn.params.forEach((param, i) => {
    const simple = param.type === 'AssignmentPattern' ? param.left : param;
    if (simple.type === 'Identifier' && constants[i] !== undefined) env.constants.set(simple.name, constants[i]);
    if (supplied) bind(param, supplied[i] || new Set(), env);
    else if (i === 0) bind(param, new Set(['$sender']), env);
    else if (param.type === 'ObjectPattern' || param.type === 'ArrayPattern') bind(param, new Set(), env, `argument${i}`);
    else bind(param, new Set(paramNames({ params: [param] })), env);
  });
  return env;
}

function constant(node, env) {
  if (node?.type === 'Identifier' && env.constants?.has(node.name)) return env.constants.get(node.name);
  if (node?.type === 'Identifier' && env.has(node.name)) return undefined;
  return constantValue(node, null);
}

function assignments(fn, env) {
  // Fixed point, preserving alternatives: reassignment is never used to erase evidence of IPC input.
  const writes = [];
  const reassigned = new Set();
  withoutFunctions(fn.body, n => {
    if (n.type === 'VariableDeclarator' && n.init) writes.push([n.id, n.init]);
    if (n.type === 'AssignmentExpression') { writes.push([n.left, n.right]); paramNames({ params: [n.left] }).forEach(name => reassigned.add(name)); }
    return true;
  });
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    for (const [target, source] of writes) {
      const values = references(source, env);
      if (target.type === 'Identifier' && source.type === 'Identifier' && env.objectNames.has(source.name)) env.objectNames.add(target.name);
      if (target.type === 'Identifier') {
        const value = constant(source, env);
        if (value !== undefined && !reassigned.has(target.name)) env.constants.set(target.name, value);
        else env.constants.delete(target.name);
      }
      const names = paramNames({ params: [target] });
      if (names.some(name => [...values].some(value => !env.get(name)?.has(value)))) changed = true;
      for (const name of names) env.set(name, union([env.get(name) || new Set(), values]));
    }
    if (!changed) break;
  }
}

function replyNodes(fn, replyCallback) {
  const expressions = returnedValues(fn).map(item => item.value);
  const declarations = new Map();
  withoutFunctions(fn.body, node => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') declarations.set(node.id.name, node.init);
    if (node.type === 'AssignmentExpression' && memberName(node.left) === 'returnValue') expressions.push(node.right);
    if (isCall(node) && (nameOf(node.callee) === 'reply' || nameOf(node.callee) === 'send' && memberName(node.callee.object) === 'sender')) expressions.push(...node.arguments.slice(1));
    if (isCall(node) && node.callee.name === replyCallback) expressions.push(...node.arguments);
    return true;
  });
  const nodes = new Set();
  const expand = (expression, depth = 0) => {
    if (!expression || depth > MAX_DEPTH || nodes.has(expression)) return;
    withoutFunctions(expression, node => {
      nodes.add(node);
      if (isCall(node)) {
        if (nameOf(node.callee) === 'resolve' && node.callee.object?.name === 'Promise') node.arguments.forEach(argument => expand(argument, depth + 1));
        return false; // Passing a secret to a helper does not imply that the helper returns it.
      }
      if (node.type === 'Identifier' && declarations.has(node.name)) expand(declarations.get(node.name), depth + 1);
      return true;
    });
  };
  expressions.forEach(expression => expand(expression));
  return nodes;
}

function pathTransforms(fn, env) {
  const definitions = new Map();
  withoutFunctions(fn.body, n => {
    const target = n.type === 'VariableDeclarator' ? n.id : n.type === 'AssignmentExpression' ? n.left : undefined;
    const value = n.type === 'VariableDeclarator' ? n.init : n.right;
    if (target?.type === 'Identifier') definitions.set(target.name, definitions.has(target.name) ? undefined : value);
    return true;
  });
  const transformed = (expression, seen = new Set()) => {
    if (!expression || seen.has(expression)) return new Set();
    seen.add(expression);
    if (expression.type === 'Identifier') return transformed(definitions.get(expression.name), seen);
    if (isCall(expression) && nameOf(expression.callee) === 'basename') return references(expression.arguments[0], env);
    if (isCall(expression) && ['join', 'resolve'].includes(nameOf(expression.callee))) return union(expression.arguments.map(arg => transformed(arg, new Set(seen))));
    return new Set();
  };
  return transformed;
}

const literalReply = node => !node || ['Literal', 'StringLiteral', 'NumericLiteral', 'BooleanLiteral', 'NullLiteral'].includes(node.type);
function rejects(node) {
  if (!node) return false;
  if (node.type === 'ThrowStatement') return true;
  if (node.type === 'ReturnStatement') return literalReply(node.argument);
  return node.type === 'BlockStatement' && rejects(node.body.at(-1));
}

function guardKind(test) {
  let kind;
  withoutFunctions(test, n => {
    const name = isCall(n) ? nameOf(n.callee) : undefined;
    if (n.type === 'UnaryExpression' && n.operator === 'typeof' || n.type === 'BinaryExpression' && n.operator === 'instanceof') kind ||= 'type';
    if (/^(isArray|isInteger|isFinite)$/.test(name || '')) kind ||= 'type';
    if (/inside|within|contain|allowedPath|safePath|validPath/i.test(name || '') || name === 'relative' || name === 'startsWith') kind = 'path';
    else if (/extname|extension/i.test(name || '') || name === 'endsWith' && typeof literalValue(n.arguments[0]) === 'string' && /^\.[a-z0-9]+$/i.test(literalValue(n.arguments[0]))) kind ||= 'extension';
    else if (/^(validate|verify|check|is[A-Z])/.test(name || '')) kind ||= 'policy';
    return true;
  });
  return kind;
}

// Guards must precede the call in a containing block, or reject the other branch of its containing if.
function guardsBefore(target, ancestors, env, file) {
  const result = [];
  const add = (statement) => {
    const args = [...references(statement.test, env)];
    const sender = args.includes('$sender');
    const kind = sender ? 'sender' : guardKind(statement.test);
    if (kind && args.length) result.push({ ...at(file, statement), kind, arguments: args, status: 'recognized-unverified' });
  };
  for (let i = 0; i < ancestors.length; i++) {
    const parent = ancestors[i];
    const child = ancestors[i + 1] || target;
    if (parent.type === 'BlockStatement') {
      const position = parent.body.indexOf(child);
      for (const statement of parent.body.slice(0, Math.max(position, 0)))
        if (statement.type === 'IfStatement' && (rejects(statement.consequent) || rejects(statement.alternate))) add(statement);
    }
    if (parent.type === 'IfStatement' && ((child === parent.consequent && rejects(parent.alternate)) ||
      (child === parent.alternate && rejects(parent.consequent)))) add(parent);
  }
  return result;
}

const FS = /^(node:)?(fs|fs\/promises|original-fs|graceful-fs|fs-extra|fs-jetpack)$/;
const FILE_OP = /^(readFile|readFileSync|createReadStream|readdir|readdirSync|readJson|readJSON|readJsonSync|opendir|opendirSync|open|openSync|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|outputFile|outputFileSync|writeJson|writeJSON|writeJsonSync|mkdir|mkdirSync|symlink|symlinkSync|link|linkSync|chmod|chmodSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|remove|removeSync|emptyDir|emptyDirSync|rename|renameSync|copyFile|copyFileSync|copy|copySync|cp|cpSync|move|moveSync|stat|statSync)$/;
const SECRET = /creds|credential|password|passwd|authToken|accessToken|refreshToken|secret|apiKey/i;

function operation(call, program) {
  const name = nameOf(call.callee);
  let root = call.callee;
  while (isMember(root)) root = root.object;
  const binding = root?.type === 'Identifier' && moduleBindings(program).get(root.name);
  const module = binding?.module || (/^(fs|fsp|fse)$/.test(root?.name || '') ? 'fs' : undefined);
  const method = binding && !isMember(call.callee) && binding.imported !== '*' ? binding.imported : name;
  if (FS.test(module || '') && FILE_OP.test(method || '')) {
    const kind = /^(stat)/.test(method) ? 'file-metadata' : /^(read|createRead|opendir|open)/.test(method) ? 'file-read' :
      /^(unlink|rm|remove|emptyDir)/.test(method) ? 'file-delete' : /^(rename|copy|cp|move|link|symlink)/.test(method) ? 'file-copy' : 'file-write';
    return { kind, capability: 'files', pathIndexes: kind === 'file-copy' ? [0, 1] : [0] };
  }
  if (['openPath', 'openItem', 'openExternal', 'trashItem', 'showItemInFolder', 'writeShortcutLink'].includes(name)) return { kind: `shell-${name}`, capability: 'shell', pathIndexes: ['openExternal'].includes(name) ? [] : [0] };
  if (module === 'child_process' || module === 'node:child_process') return { kind: 'process', capability: 'processes', pathIndexes: [] };
  if (name === 'fetch' || /^(axios|got|https?|net|request|undici|superagent)$/.test(module || root?.name || '') && /^(get|post|put|patch|delete|request)$/.test(name || '')) return { kind: 'network', capability: 'network', pathIndexes: [] };
  if (['decryptString', 'getPassword', 'findPassword', 'findCredentials', 'unprotectData'].includes(name)) return { kind: 'credential-read', capability: 'credentials', pathIndexes: [] };
  if (['get', 'getItem', 'getSync'].includes(name) && typeof literalValue(call.arguments[0]) === 'string' && SECRET.test(literalValue(call.arguments[0]))) return { kind: 'credential-read', capability: 'credentials', pathIndexes: [] };
  if (['loadURL', 'loadFile', 'executeJavaScript', 'close', 'destroy', 'setBounds', 'focus', 'show', 'hide', 'reload', 'openDevTools'].includes(name)) return { kind: `window-${name}`, capability: 'windows', pathIndexes: [] };
  if (root?.name === 'clipboard' || memberName(call.callee.object) === 'clipboard') return { kind: `clipboard-${name}`, capability: 'clipboard', pathIndexes: [] };
  return undefined;
}

export function ipcContext(definition) {
  if (!definition || !isFunction(definition.node)) return { status: 'incomplete', unresolved: [{ reason: 'handler-unresolved' }], effects: [], helpers: [], arguments: [] };
  const result = { status: 'analyzed', arguments: [], effects: [], helpers: [], unresolved: [], credentials: [], channels: [] };
  result.state = [];
  const rootEnv = environment(definition.node);
  const labels = union([...rootEnv.values()]);
  labels.delete('$sender');
  const active = new Set();
  let remaining = MAX_CALLS;
  const unresolved = (call, file, reason) => {
    if (result.unresolved.length < 30) result.unresolved.push({ ...at(file, call), call: nameOf(call?.callee) || '<dynamic>', reason });
    result.status = 'incomplete';
  };
  const stateSeen = new Set();
  const traceState = (ref, name) => {
    const stateKey = `${ref.file}:${name}`;
    if (stateSeen.has(stateKey)) return;
    stateSeen.add(stateKey);
    const topLevel = ref.program.body.flatMap(statement => {
      const declaration = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
      return declaration?.type === 'VariableDeclaration' ? declaration.declarations : [];
    }).find(declaration => declaration.id.name === name);
    if (!topLevel) return;
    const state = { reference: name, ...at(ref.file, topLevel), writes: [], callers: [], status: 'candidate-state-writes' };
    const writers = new Map();
    visit(ref.program, (node, ancestors) => {
      if (node.type !== 'AssignmentExpression' || node.left.type !== 'Identifier' || node.left.name !== name) return true;
      const owner = ancestors.findLast(isFunction);
      if (owner && paramNames(owner).includes(name)) return true;
      // Avoid linking a function's local variable to the module's identically named state.
      let shadowed = false;
      if (owner) withoutFunctions(owner.body, child => {
        if (child.type === 'VariableDeclarator' && paramNames({ params: [child.id] }).includes(name)) shadowed = true;
        return !shadowed;
      });
      if (shadowed) return true;
      const parent = owner && ancestors[ancestors.indexOf(owner) - 1];
      const writer = owner?.id?.name || (parent?.type === 'VariableDeclarator' ? parent.id.name :
        parent?.type === 'AssignmentExpression' ? memberName(parent.left) : keyName(owner?.key));
      state.writes.push({ ...at(ref.file, node), writer, source: node.right.type === 'Identifier' ? node.right.name :
        isMember(node.right) ? `${node.right.object.name || '<object>'}.${memberName(node.right)}` : node.right.type,
      fields: node.right.type === 'ObjectExpression' ? node.right.properties.map(p => keyName(p.key)).filter(Boolean) : undefined });
      if (writer) writers.set(writer, owner);
      return true;
    });
    const index = currentAnalysisContext().index;
    if (index) for (const [writer, fn] of writers) {
      const exportedNames = [...(index.exportsOf(ref.file)?.named || [])].filter(([, entry]) => entry.node && keyOf({ ...ref, node: entry.node }) === keyOf({ ...ref, node: fn })).map(([name]) => name);
      const files = new Set([ref.file, ...[writer, ...exportedNames].flatMap(name => index.filesMentioning(name))]);
      if (files.size > 20) { state.status = 'state-search-limited'; unresolved(fn, ref.file, 'state-search-limit'); }
      for (const file of [...files].slice(0, 20)) {
        const program = index.exportsOf(file)?.program;
        if (!program) continue;
        visit(program, (node, ancestors) => {
          if (!isCall(node) || state.callers.length >= 20) return true;
          const target = inFile(file, program, () => ipcDefinition(node.callee, null, [program, ...ancestors]), [program, ...ancestors]);
          if (target && target.file === ref.file && keyOf(target) === keyOf({ ...ref, node: fn }))
            state.callers.push({ ...at(file, node), writer, call: nameOf(node.callee),
              enclosingFunction: ancestors.findLast(isFunction)?.id?.name,
              arguments: node.arguments.map(arg => arg.type === 'Identifier' ? arg.name : arg.type) });
          return true;
        });
      }
      if (state.callers.length >= 20) { state.status = 'state-search-limited'; unresolved(fn, ref.file, 'state-caller-limit'); }
    }
    result.state.push(state);
  };
  const walk = (ref, env, inherited, trace, depth, reply = false, replyCallback) => {
    if (depth > MAX_DEPTH) { unresolved(ref.node, ref.file, 'depth-limit'); return; }
    const key = keyOf(ref);
    if (active.has(key)) { unresolved(ref.node, ref.file, 'recursive-call'); return; }
    active.add(key);
    inFile(ref.file, ref.program, () => {
      assignments(ref.node, env);
      const returned = reply ? replyNodes(ref.node, replyCallback) : new Set();
      const transformed = pathTransforms(ref.node, env);
      visit(ref.node.body, (node, ancestors) => {
        if (isFunction(node)) {
          // Inline callbacks inherit captured inputs; their own parameters shadow outer bindings.
          const nested = new Map(env);
          nested.constants = new Map(env.constants);
          nested.objectNames = new Set(env.objectNames);
          paramNames(node).forEach(name => nested.delete(name));
          paramNames(node).forEach(name => nested.constants.delete(name));
          paramNames(node).forEach(name => nested.objectNames.delete(name));
          const parent = ancestors.at(-1);
          const resolvesReply = parent?.type === 'NewExpression' && parent.callee.name === 'Promise' && returned.has(parent);
          walk({ ...ref, node }, nested, [...inherited, ...guardsBefore(node, ancestors, env, ref.file)], trace, depth + 1, resolvesReply,
            resolvesReply && node.params[0]?.type === 'Identifier' ? node.params[0].name : undefined);
          return false;
        }
        if (returned.has(node) && node.type === 'Identifier' && SECRET.test(node.name)) {
          const parent = ancestors.at(-1);
          if (!(isMember(parent) && parent.property === node && !parent.computed) &&
            !((parent?.type === 'ObjectProperty' || parent?.type === 'Property') && parent.key === node && parent.value !== node)) {
            result.credentials.push({ ...at(ref.file, node), reference: node.name, trace });
            traceState(ref, node.name);
          }
        }
        if (returned.has(node) && isMember(node) && SECRET.test(memberName(node) || '')) {
          result.credentials.push({ ...at(ref.file, node), reference: memberName(node), trace });
          if (node.object.type === 'Identifier') traceState(ref, node.object.name);
        }
        if (!isCall(node)) return true;
        if (--remaining < 0) { if (remaining === -1) unresolved(node, ref.file, 'call-budget'); return false; }
        const sources = node.arguments.map(arg => references(arg, env));
        const guards = [...inherited, ...guardsBefore(node, ancestors, env, ref.file)];
        const sanitizers = node.arguments.flatMap(arg => [...transformed(arg)]);
        if (sanitizers.length) guards.push({ ...at(ref.file, node), kind: 'path-basename', arguments: sanitizers, status: 'recognized-unverified' });
        const fullAncestors = [ref.program, ref.node, ...ancestors];
        const target = inFile(ref.file, ref.program, () => ipcDefinition(node.callee, null, fullAncestors), fullAncestors);
        const op = isFunction(target?.node) ? undefined : operation(node, ref.program);
        const callTrace = [...trace, { ...at(ref.file, node), call: nameOf(node.callee) || '<dynamic>' }];
        const inputs = [...union(sources)].filter(arg => arg !== '$sender');
        if (op) {
          const pathInputs = [...union(op.pathIndexes.map(i => sources[i] || new Set()))].filter(arg => arg !== '$sender');
          result.effects.push({ ...at(ref.file, node), call: nameOf(node.callee), kind: op.kind, capability: op.capability,
            arguments: inputs, pathArguments: pathInputs, guards, trace: callTrace,
            pathControl: pathInputs.length ? (pathInputs.every(p => guards.some(g => ['path', 'path-basename'].includes(g.kind) && g.arguments.includes(p))) ? 'recognized-unverified' : 'not-recognized') : 'not-applicable',
            extensionControl: pathInputs.length ? (pathInputs.every(p => guards.some(g => g.kind === 'extension' && g.arguments.includes(p))) ? 'recognized-unverified' : 'not-recognized') : 'not-applicable' });
          if (returned.has(node) && op.kind === 'credential-read') result.credentials.push({ ...at(ref.file, node), reference: nameOf(node.callee), trace: callTrace });
          return true;
        }
        if (['invoke', 'send', 'sendSync', 'sendTo', 'sendToHost', 'postMessage'].includes(nameOf(node.callee)) &&
          inFile(ref.file, ref.program, () => ipcObject(node.callee.object, 'ipcRenderer', null), [ref.program, ref.node, ...ancestors])) {
          const channel = constant(node.arguments[0], env);
          result.channels.push(typeof channel === 'string' ? channel : '*');
          return true;
        }
        const returns = returned.has(node);
        if (target && isFunction(target.node)) {
          result.helpers.push({ ...at(target.file, target.node), call: nameOf(node.callee), arguments: inputs });
          walk(target, environment(target.node, sources, node.arguments.map(arg => constant(arg, env))), guards, callTrace, depth + 1, returns);
        } else {
          let root = node.callee;
          while (isMember(root)) root = root.object;
          const external = root?.type === 'Identifier' && moduleBindings(ref.program).get(root.name);
          const projectImport = external && currentAnalysisContext().index?.resolve(ref.file, external.module);
          // Standard/library operations are opaque; distinguish them from unresolved application helpers.
          if ((inputs.length || returns) && !['split', 'pop', 'join', 'resolve', 'basename', 'normalize', 'extname', 'toUTCString', 'log', 'error', 'info', 'warn', 'then', 'catch', 'resolve', 'reject'].includes(nameOf(node.callee)) &&
            !['Promise', 'Error', 'URL', 'Buffer'].includes(root?.name)) unresolved(node, ref.file, external && !projectImport ? 'external-helper-opaque' : 'callee-unresolved');
          if (external && projectImport && !target) unresolved(node, ref.file, 'project-helper-unresolved');
        }
        return true;
      });
    }, [ref.program, ...(ref.ancestors || []), ref.node]);
    active.delete(key);
  };
  walk(definition, rootEnv, [], [], 0, true);
  result.effects.forEach(effect => effect.arguments.forEach(name => labels.add(name)));
  result.arguments = [...labels].map(name => {
    const uses = result.effects.filter(effect => effect.arguments.includes(name));
    return { name, operations: [...new Set(uses.map(effect => effect.kind))],
      validation: uses.length ? (uses.every(effect => effect.guards.some(g => g.kind !== 'sender' && g.arguments.includes(name))) ? 'recognized-unverified' : 'not-recognized') : 'no-resolved-operation' };
  });
  result.credentials = result.credentials.filter((item, i, all) => all.findIndex(other => other.file === item.file && other.line === item.line && other.reference === item.reference) === i);
  result.channels = [...new Set(result.channels)];
  return result;
}
