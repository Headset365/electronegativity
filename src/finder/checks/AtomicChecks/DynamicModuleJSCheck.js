import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { finding, memberName } from '../helpers.js';
import { constantValue, enclosingFunction, untrustedSource, dependsOnParams, functionDefinition, inFile,
  resolveLocal, visit, isCall, isMember, identifiersIn, paramNames, returnedValues, currentAnalysisContext, isModuleLoader } from '../analysis.js';

// A module path executes code, rather than merely reading a file.
export default class DynamicModuleJSCheck {
  constructor() {
    this.id = 'DYNAMIC_MODULE_JS_CHECK';
    this.description = __('DYNAMIC_MODULE_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://owasp.org/www-community/attacks/Path_Traversal';
  }

  match(node, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    const arg = node.type === 'ImportExpression' ? node.source :
      isCall(node) && node.type !== 'NewExpression' && isModuleLoader(node.callee, scope) ? node.arguments[0] : undefined;
    if (!arg || constantValue(arg, scope) !== undefined) return null;
    const fn = enclosingFunction(context.ancestors);
    if (!fn || !dependsOnParams(arg, fn)) return null;
    const source = untrustedSource(context.ancestors, fn);
    if (!source || safeModulePath(arg, fn, scope)) return null;
    return [finding(this, node, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: true,
      properties: { source, operation: 'module', sink: node.type === 'ImportExpression' ? 'import' : 'require' },
      description: `${this.description} (a module path from ${source} is loaded without a restrictive identifier allowlist; traversal can select JavaScript outside the intended module folder)` })];
  }
}

function safeModulePath(arg, fn, scope, depth = 0, tainted = new Set(paramNames(fn))) {
  if (!arg || depth > 5) return false;
  if (isCall(arg) && arg.type !== 'NewExpression') {
    const definition = functionDefinition(arg.callee, scope);
    const passed = definition && new Set(definition.node.params.flatMap((param, i) => arg.arguments[i] && constantValue(arg.arguments[i], scope) === undefined ? paramNames({ params: [param] }) : []));
    if (definition) return inFile(definition.file, definition.program, () => {
      const returns = returnedValues(definition.node);
      return returns.length > 0 && returns.every(({ value }) => {
        let chain = [];
        visit(definition.node.body, (node, ancestors) => { if (node === value) chain = [...ancestors]; return true; });
        return inFile(definition.file, definition.program,
          () => safeModulePath(value, definition.node, null, depth + 1, passed), [definition.program, definition.node, ...chain]);
      });
    }, [definition.program, definition.node, definition.node.body]);
  }
  const used = new Set(identifiersIn(arg));
  for (let depth = 0; depth < 6; depth++) visit(fn.body, n => {
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && used.has(n.id.name) && n.init)
      identifiersIn(n.init).forEach(name => used.add(name));
  });
  const required = [...used].filter(name => tainted.has(name));
  if (!required.length) return false;
  const guarded = new Set();
  const ancestors = currentAnalysisContext().ancestors || [];
  const chain = [...ancestors.slice(ancestors.indexOf(fn) + 1), arg];
  for (let i = 0; i < chain.length - 1; i++) {
    const block = chain[i], child = chain[i + 1];
    if (block.type !== 'BlockStatement') continue;
    const position = block.body.indexOf(child);
    if (position < 0) continue;
    for (const statement of block.body.slice(0, position)) {
      if (statement.type !== 'IfStatement' || !alwaysExits(statement.consequent)) continue;
      for (const name of rejectedIdentifiers(statement.test, scope)) guarded.add(name);
    }
  }
  // A validated parameter reassigned before use is no longer covered by its old guard.
  visit(fn.body, n => {
    if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier' && (!arg.loc || n.loc?.start.line <= arg.loc.start.line)) guarded.delete(n.left.name);
    return n === fn.body || !/Function/.test(n.type);
  });
  return required.every(name => guarded.has(name));
}

function alwaysExits(node) {
  if (!node) return false;
  if (node.type === 'ThrowStatement' || node.type === 'ReturnStatement') return true;
  return node.type === 'BlockStatement' && alwaysExits(node.body.at(-1));
}

function rejectedIdentifiers(test, scope) {
  if (test.type === 'LogicalExpression' && test.operator === '||') return [...rejectedIdentifiers(test.left, scope), ...rejectedIdentifiers(test.right, scope)];
  if (test.type !== 'UnaryExpression' || test.operator !== '!' || !isCall(test.argument)) return [];
  const call = test.argument;
  if (!isMember(call.callee) || memberName(call.callee) !== 'test' || call.arguments[0]?.type !== 'Identifier') return [];
  const regex = resolveLocal(call.callee.object, scope);
  const pattern = regex?.regex?.pattern || regex?.pattern;
  const flags = regex?.regex?.flags || regex?.flags || '';
  if (!/^\^\[(?:a-z|A-Z|0-9|_|-)+\]\+\$$/.test(pattern || '') || /[gmy]/.test(flags)) return [];
  return [call.arguments[0].name];
}
