import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, calleeObjectName, finding, isFunction, combineAssignments } from '../helpers.js';
import { constantValue, isCall, isMember, resolveLocal, onlyConstantParts, currentAnalysisContext, moduleBindings,
  functionDefinition, inFile, returnedValues, visit } from '../analysis.js';
import { htmlOrigin, looksLikeHtml, ORIGINS } from '../html.js';

// properties that parse their value as HTML: an iframe's srcdoc becomes a whole document in the frame, which shares the
// window's origin (and, with nodeIntegration and no sandbox, its Node.js access through parent.require)
const HTML_PROPERTIES = ['innerHTML', 'outerHTML', 'srcdoc'];
// what document.write is called on: the page's document, or a frame's (iframe.contentDocument, frame.contentWindow.document)
const DOCUMENT_OBJECTS = new Set(['document', 'contentDocument']);
// jsx("iframe", props), React.createElement("iframe", props) and similar compiled JSX calls
const ELEMENT_FACTORIES = new Set(['jsx', 'jsxs', '_jsx', '_jsxs', 'jsxDEV', 'createElement', 'h']);
// Vue's compiled render functions: createElementVNode("div", { innerHTML: x }) is what v-html becomes
const VUE_FACTORIES = new Set(['createElementVNode', '_createElementVNode', 'createVNode', '_createVNode', 'createElementBlock', '_createElementBlock', 'h']);
const JQUERY_INSERTION = ['append', 'prepend', 'before', 'after', 'replaceWith'];
// sanitizers make the value safe to insert
const SANITIZER_MODULES = /^(dompurify|isomorphic-dompurify|sanitize-html|escape-html|he|lodash|underscore)(\/|$)/;
const SANITIZER_MUTATIONS = new WeakMap();

// XSS in an Electron renderer can reach IPC, preload APIs and, without isolation, Node.js itself
export default class XssSinkJSCheck {
  constructor() {
    this.id = "XSS_SINK_JS_CHECK";
    this.description = __("XSS_SINK_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context) {
    let sink;
    let value;
    // el.innerHTML = x, el.outerHTML += x
    if (astNode.type === 'AssignmentExpression' && HTML_PROPERTIES.includes(memberName(astNode.left))) {
      sink = memberName(astNode.left);
      value = astNode.right;
    }
    // el.insertAdjacentHTML(pos, x), document.write(x), document.writeln(x), iframe.contentDocument.write(x)
    if (isCall(astNode) && astNode.type !== 'NewExpression') {
      const method = memberName(astNode.callee);
      if (method === 'insertAdjacentHTML') { sink = method; value = astNode.arguments[1]; }
      if ((method === 'write' || method === 'writeln') && DOCUMENT_OBJECTS.has(calleeObjectName(astNode.callee))) {
        sink = `${calleeObjectName(astNode.callee)}.${method}`;
        value = astNode.arguments[0];
      }
      // el.setAttribute('srcdoc', x) and range.createContextualFragment(x), which runs the scripts in its markup
      if (method === 'setAttribute' && String(constantValue(astNode.arguments[0], scope)).toLowerCase() === 'srcdoc') { sink = 'srcdoc'; value = astNode.arguments[1]; }
      if (method === 'createContextualFragment') { sink = method; value = astNode.arguments[0]; }
      // jsx("iframe", { srcDoc: x }) in a compiled bundle
      const factory = astNode.callee.type === 'Identifier' ? astNode.callee.name : method;
      if (ELEMENT_FACTORIES.has(factory) && constantValue(astNode.arguments[0], scope) === 'iframe' && astNode.arguments[1] && astNode.arguments[1].type === 'ObjectExpression') {
        const property = astNode.arguments[1].properties.find(p => p.type !== 'SpreadElement' && /^srcdoc$/i.test(keyName(p.key) || ''));
        if (property) { sink = 'srcdoc'; value = property.value; }
      }
      // document.execCommand('insertHTML', false, x) parses its argument as HTML
      if (method === 'execCommand' && String(constantValue(astNode.arguments[0], scope)).toLowerCase() === 'inserthtml') { sink = "execCommand('insertHTML')"; value = astNode.arguments[2]; }
      // jQuery: $el.html(x); append/prepend/before/after/replaceWith parse strings as HTML too, flag them when given built strings
      if (method === 'html' && astNode.arguments.length === 1) { sink = '.html()'; value = astNode.arguments[0]; }
      if (JQUERY_INSERTION.includes(method) && astNode.arguments.length === 1 && isBuiltString(astNode.arguments[0])) { sink = `.${method}()`; value = astNode.arguments[0]; }
      // $(htmlString) and angular.element(htmlString) parse markup into live nodes
      const isJQuery = astNode.callee.type === 'Identifier' && (astNode.callee.name === '$' || astNode.callee.name === 'jQuery');
      const isAngularElement = method === 'element' && calleeObjectName(astNode.callee) === 'angular';
      if ((isJQuery || isAngularElement) && astNode.arguments.length >= 1 && isHtmlArgument(astNode.arguments[0], scope, context)) {
        sink = isJQuery ? '$(html)' : 'angular.element(html)';
        value = astNode.arguments[0];
      }
      // Attribute a shared HTML helper to its caller as well as to the helper's generic sink.
      if (!sink) {
        const definition = functionDefinition(astNode.callee, scope);
        if (definition) {
          const parameters = htmlSinkParameters(definition.node);
          const index = parameters.find(i => astNode.arguments[i] && !isSanitized(astNode.arguments[i], scope));
          if (index !== undefined) { sink = 'HTML helper'; value = astNode.arguments[index]; }
        }
      }
    }
    // compiled React and Preact: jsx("div", { dangerouslySetInnerHTML: { __html: x } }), props.dangerouslySetInnerHTML = {...},
    // or a helper that wraps the value: { dangerouslySetInnerHTML: getHtml(x) }
    if ((astNode.type === 'ObjectProperty' || astNode.type === 'Property') && keyName(astNode.key) === 'dangerouslySetInnerHTML') {
      sink = 'dangerouslySetInnerHTML';
      value = innerHtmlValue(astNode.value, scope);
    }
    if (astNode.type === 'AssignmentExpression' && memberName(astNode.left) === 'dangerouslySetInnerHTML') {
      sink = 'dangerouslySetInnerHTML';
      value = innerHtmlValue(astNode.right, scope);
    }
    // compiled Vue v-html: createElementVNode("div", { innerHTML: x })
    if ((astNode.type === 'ObjectProperty' || astNode.type === 'Property') && keyName(astNode.key) === 'innerHTML' && context && context.ancestors) {
      const object = context.ancestors[context.ancestors.length - 1];
      const call = context.ancestors[context.ancestors.length - 2];
      const factory = call && isCall(call) ? (call.callee.type === 'Identifier' ? call.callee.name : memberName(call.callee)) : undefined;
      if (object && object.type === 'ObjectExpression' && VUE_FACTORIES.has(factory) && call.arguments[1] === object) { sink = 'innerHTML prop'; value = astNode.value; }
    }
    // <iframe srcDoc={x} />
    if (astNode.type === 'JSXAttribute' && astNode.name && /^srcdoc$/i.test(astNode.name.name || '')) {
      sink = 'srcdoc';
      value = astNode.value && (astNode.value.type === 'JSXExpressionContainer' ? astNode.value.expression : astNode.value);
    }
    // <div dangerouslySetInnerHTML={{ __html: x }} />
    if (astNode.type === 'JSXAttribute' && astNode.name && astNode.name.name === 'dangerouslySetInnerHTML') {
      sink = 'dangerouslySetInnerHTML';
      const expression = astNode.value && astNode.value.expression;
      const html = expression && expression.type === 'ObjectExpression' && expression.properties.find(p => keyName(p.key) === '__html');
      value = html ? html.value : expression;
    }
    if (!sink || !value) return null;

    // a constant, or markup assembled only from constants (cond ? '<b>a</b>' : '<i>b</i>'): nothing from data
    if (onlyConstantParts(value, scope)) return null;
    if (isSanitized(value, scope)) return null;
    // server-controlled HTML rendered by another user's client is the stored-content threat, and pasted, dropped or
    // imported content can be written by someone else too: raise them to HIGH
    const origin = htmlOrigin(value, scope, context && context.ancestors);
    return [finding(this, astNode, { severity: origin ? severity.HIGH : severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} (${sink} with ${origin || 'a dynamic value'})`, properties: { sink, serverFed: origin === ORIGINS.SERVER, origin } })];
  }
}

// The markup in a dangerouslySetInnerHTML value: x in { __html: x }, or the argument a wrapper puts there
// (function getHtml(html) { return { __html: html } } called as getHtml(x))
function innerHtmlValue(node, scope) {
  if (!node) return undefined;
  if (node.type === 'ObjectExpression') {
    const html = node.properties.find(p => p.type !== 'SpreadElement' && keyName(p.key) === '__html');
    return html ? html.value : undefined;
  }
  if (isCall(node) && node.type !== 'NewExpression') {
    const definition = functionDefinition(node.callee, scope);
    const fn = definition && definition.node;
    if (fn && isFunction(fn)) {
      const params = fn.params.map(param => param.type === 'AssignmentPattern' ? param.left : param);
      for (const { value } of returnedValues(fn)) {
        const html = value && value.type === 'ObjectExpression' && value.properties.find(p => p.type !== 'SpreadElement' && keyName(p.key) === '__html');
        if (!html) continue;
        const index = params.findIndex(param => param.type === 'Identifier' && [...identifierNames(html.value)].includes(param.name));
        if (index !== -1) return node.arguments[index];
        return html.value && onlyConstantParts(html.value, null) ? html.value : node;
      }
    }
    return node;
  }
  return node;
}
function identifierNames(node) {
  const names = new Set();
  visit(node, n => { if (n.type === 'Identifier') names.add(n.name); return true; });
  return names;
}

// Whether an argument to $()/angular.element() is an HTML string rather than a selector: a built string with markup,
// or server-controlled data (a plain identifier could be either, so it is not flagged on its own)
function isHtmlArgument(node, scope, context) {
  if (!node) return false;
  const constant = constantValue(node, scope);
  if (typeof constant === 'string') return /<[a-z!]/i.test(constant);
  if (constant !== undefined) return false;
  // a markup string built in a variable: let html = '<div>'; html += x; $(html)
  const resolved = node.type === 'Identifier' ? resolveLocal(node, scope) : node;
  return looksLikeHtml(node) || (resolved !== node && looksLikeHtml(resolved)) || !!htmlOrigin(node, scope, context && context.ancestors);
}

// Strings assembled from pieces: `<b>${x}</b>`, '<b>' + x
function isBuiltString(node) {
  return node.type === 'TemplateLiteral' || (node.type === 'BinaryExpression' && node.operator === '+');
}

/**
 * Whether every dynamic part of the HTML goes through a sanitizer. A sanitizer nested deeper doesn't count:
 * in render(escape(text)) the render function can re-introduce markup (Signal Desktop CVE-2018-10994).
 */
export function isSanitized(value, scope, depth = 0, parameters = new Map()) {
  if (!value || depth > 12) return false;
  if (value.type === 'Identifier' && parameters.has(value.name)) return parameters.get(value.name);
  if (constantValue(value, scope) !== undefined) return true;
  const safe = node => isSanitized(node, scope, depth + 1, parameters);
  switch (value.type) {
    case 'Identifier': {
      const resolved = resolveLocal(value, scope);
      return resolved !== value && safe(resolved);
    }
    case 'CallExpression':
    case 'OptionalCallExpression': {
      const definition = functionDefinition(value.callee, scope);
      if (definition) {
        if (isHtmlEscaper(definition.node)) return true;
        const states = new Map();
        definition.node.params.forEach((param, i) => { if (param.type === 'Identifier') states.set(param.name, safe(value.arguments[i])); });
        visit(definition.node.body, node => {
          if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && states.has(node.left.name)) states.set(node.left.name, false);
          if (node.type === 'UpdateExpression' && node.argument.type === 'Identifier' && states.has(node.argument.name)) states.set(node.argument.name, false);
          return node === definition.node.body || !isFunction(node);
        });
        return inFile(definition.file, definition.program, () => {
          const localScope = functionValueScope(definition.node);
          const returns = returnedValues(definition.node);
          return returns.length > 0 && returns.every(({ value: returned }) => isSanitized(returned, localScope, depth + 1, states));
        }, [definition.program, definition.node, definition.node.body]);
      }
      if (knownSanitizer(value.callee, scope)) return true;
      // String slicing preserves escaped content; decoding, replace(), render(), etc. do not.
      return isMember(value.callee) && ['slice', 'substring', 'substr', 'trim', 'trimStart', 'trimEnd'].includes(memberName(value.callee)) && safe(value.callee.object);
    }
    case 'TemplateLiteral': return value.expressions.every(safe);
    case 'BinaryExpression': return value.operator === '+' && safe(value.left) && safe(value.right);
    case 'ConditionalExpression': return safe(value.consequent) && safe(value.alternate);
    case 'LogicalExpression': return safe(value.left) && safe(value.right);
    case 'AwaitExpression': return safe(value.argument);
    case 'TSAsExpression': case 'TSNonNullExpression': return safe(value.expression);
    default: return false;
  }
}

function htmlSinkParameters(fn) {
  const indexes = new Set();
  visit(fn.body, n => {
    if (n.type === 'AssignmentExpression' && HTML_PROPERTIES.includes(memberName(n.left)) && n.right.type === 'Identifier') {
      const index = fn.params.findIndex(p => p.type === 'Identifier' && p.name === n.right.name);
      if (index !== -1) indexes.add(index);
    }
    return n === fn.body || !isFunction(n);
  });
  return [...indexes];
}

// Recognize a concrete HTML-escaping implementation, rather than trusting its name. Require a global
// replacement of every HTML metacharacter and an entity for every matched character.
function isHtmlEscaper(fn) {
  const returns = returnedValues(fn);
  if (!returns.length) return false;
  return returns.every(({ value }) => {
    if (!isCall(value) || !isMember(value.callee) || memberName(value.callee) !== 'replace') return false;
    const [regex, replacement] = value.arguments;
    const pattern = regex?.regex?.pattern || regex?.pattern;
    const flags = regex?.regex?.flags || regex?.flags || '';
    if (!pattern || !flags.includes('g') || !/^\[[&<>"']{5}\]$/.test(pattern) || new Set(pattern.slice(1, -1)).size !== 5 || !isFunction(replacement)) return false;
    const outputs = returnedValues(replacement);
    if (outputs.length !== 1) return false;
    let table = outputs[0].value;
    if (table.type === 'LogicalExpression' && table.operator === '||') table = table.left;
    if (!isMember(table) || !table.computed || table.object.type !== 'ObjectExpression' || table.property.name !== replacement.params[0]?.name) return false;
    const entities = new Map(table.object.properties.map(p => [keyName(p.key), p.value?.value]));
    return [...'&<>"\''].every(char => /^&(?:amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);$/i.test(entities.get(char) || ''));
  });
}

function knownSanitizer(callee, scope) {
  const { program, ancestors = [] } = currentAnalysisContext();
  const bindings = moduleBindings(program);
  const method = callee.type === 'Identifier' ? callee.name : memberName(callee);
  const object = isMember(callee) && callee.object.type === 'Identifier' ? callee.object : undefined;
  const reference = object || callee;
  if (reference.type !== 'Identifier' || ancestors.some(node => isFunction(node) && node.params.some(p => p.type === 'Identifier' && p.name === reference.name))) return false;
  const binding = bindings.get(object ? object.name : method);
  const resolved = resolveLocal(reference, scope);
  const required = isMember(resolved) ? resolved.object : resolved;
  const boundRequire = binding && isCall(required) && required.callee.name === 'require' && constantValue(required.arguments[0], scope) === binding.module;
  if (resolved !== reference && !boundRequire) return false;
  if (sanitizerWasMutated(reference, object && method, program)) return false;
  if (binding && SANITIZER_MODULES.test(binding.module || '')) {
    if (/dompurify/.test(binding.module)) return (object ? method : binding.imported) === 'sanitize';
    if (/^(sanitize-html|escape-html)(\/|$)/.test(binding.module)) return !object && ['default', '*'].includes(binding.imported);
    return ['escape', 'encode', 'escapeHtml'].includes(object ? method : binding.imported);
  }
  // Recognized browser globals, provided they have not been replaced by a local declaration.
  if (object && resolveLocal(object, scope) === object)
    return (object.name === 'DOMPurify' && method === 'sanitize') || (object.name === '_' && method === 'escape');
  return callee.type === 'Identifier' && ['escapeHtml', 'escapeHTML', '$sanitize'].includes(method) && resolveLocal(callee, scope) === callee;
}

function sanitizerWasMutated(reference, method, program) {
  if (!program) return false;
  if (!SANITIZER_MUTATIONS.has(program)) SANITIZER_MUTATIONS.set(program, new Map());
  const cache = SANITIZER_MUTATIONS.get(program), key = `${reference.name}:${method || ''}`;
  if (cache.has(key)) return cache.get(key);
  const aliases = new Set([reference.name]);
  for (let depth = 0; depth < 6; depth++) visit(program, node => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init?.type === 'Identifier' && aliases.has(node.init.name)) aliases.add(node.id.name);
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && node.right.type === 'Identifier' && aliases.has(node.right.name)) aliases.add(node.left.name);
    return true;
  });
  const targets = node => node?.type === 'Identifier' ? aliases.has(node.name) :
    isMember(node) && node.object.type === 'Identifier' && aliases.has(node.object.name) && (!method || !memberName(node) || memberName(node) === method);
  let mutated = false;
  visit(program, node => {
    if ((node.type === 'AssignmentExpression' && targets(node.left)) || (node.type === 'UnaryExpression' && node.operator === 'delete' && targets(node.argument))) mutated = true;
    if (isCall(node) && isMember(node.callee) && node.callee.object.name === 'Object' && ['assign', 'defineProperty', 'defineProperties'].includes(memberName(node.callee)) && targets(node.arguments[0])) mutated = true;
    return !mutated;
  });
  cache.set(key, mutated);
  return mutated;
}

// Resolve a helper's local string construction without borrowing the caller's lexical scope.
function functionValueScope(fn) {
  const declarations = new Map(), writes = new Map();
  visit(fn.body, n => {
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init) declarations.set(n.id.name, n);
    if (n.type === 'FunctionDeclaration' && n.id) declarations.set(n.id.name, n);
    if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier') {
      if (!writes.has(n.left.name)) writes.set(n.left.name, []);
      writes.get(n.left.name).push({ operator: n.operator, right: n.right });
    }
    return n === fn.body || !isFunction(n);
  });
  return { getVarInScope(name) {
    const declaration = declarations.get(name);
    if (!declaration) return null;
    const node = declaration.type === 'VariableDeclarator' && writes.has(name) ? { ...declaration, init: combineAssignments(declaration.init, writes.get(name)) } : declaration;
    return { defs: [{ type: node.type === 'FunctionDeclaration' ? 'FunctionName' : 'Variable', node }] };
  } };
}
