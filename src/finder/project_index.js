// Cross-file resolution: what the files of the scanned project export, so handlers and constants imported from
// other files can be analyzed. Files are parsed lazily, only when something imports from them.
import path from 'node:path';
import fs from 'node:fs';
import { sourceTypes } from '../parser/types.js';
import { sourceOfCall, dependsOnParams, moduleBindings } from './checks/analysis.js';
import { isFunction, visit } from './checks/helpers.js';
import { diagnostics } from '../util/diagnostics.js';

// How many calls deep untrusted data is followed from a handler into helpers
const MAX_CALL_DEPTH = 6;
// Files that may register handlers for untrusted input (see UNTRUSTED_SOURCES in analysis.js)
const SOURCE_HINT = /ipcMain|setWindowOpenHandler|will-navigate|will-frame-navigate|did-start-navigation|new-window|will-redirect|open-url|open-file|second-instance|['"`](ipc-)?message['"`]/;
const functionKey = (file, fn) => fn && fn.loc ? `${file}:${fn.loc.start.line}:${fn.loc.start.column}` : undefined;

const EXTENSIONS = ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.mts', '.cts', '.jsx'];

const keyName = (node) => node && (node.type === 'Identifier' ? node.name : (typeof node.value === 'string' ? node.value : undefined));
const isMember = (node) => node && (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression');

// tsconfig.json / jsconfig.json are JSON with comments and trailing commas
function readJsonc(file) {
  try {
    const text = fs.readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:"'])\/\/.*$/gm, '$1')
      .replace(/,(\s*[}\]])/g, '$1');
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// Non-relative imports resolved by the TypeScript/JavaScript project configuration: baseUrl and paths
function loadAliases(root) {
  if (!root) return undefined;
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const config = readJsonc(path.join(root, name));
    const options = config && config.compilerOptions;
    if (!options || (!options.baseUrl && !options.paths)) continue;
    const baseUrl = path.resolve(root, options.baseUrl || '.');
    const paths = Object.entries(options.paths || {}).map(([pattern, targets]) => ({
      prefix: pattern.replace(/\*$/, ''), wildcard: pattern.endsWith('*'),
      // path.resolve drops the trailing slash of 'lib/*', keep it so 'lib/' + 'urls' stays 'lib/urls'
      targets: [].concat(targets).map(t => ({ prefix: path.resolve(baseUrl, t.replace(/\*$/, '')) + (/\/\*$/.test(t) ? path.sep : ''), wildcard: t.endsWith('*') }))
    }));
    return { baseUrl: options.baseUrl ? baseUrl : undefined, paths };
  }
  return undefined;
}

export class ProjectIndex {
  constructor(loader, parser, root) {
    this.loader = loader;
    this.parser = parser;
    this.files = new Set(loader.list_files);
    this.exports = new Map();
    this.aliases = loadAliases(root);
    // cross-file taint: per-file summaries, handlers (seeds), calls passing parameters on (edges), call sites
    this.summaries = new Map();
    this.seeds = new Map();
    this.edges = new Map();
    this.callSites = new Map();
  }

  // Resolves an import specifier to a scanned file (or a file on disk, for directory scans)
  resolve(fromFile, specifier) {
    if (!specifier) return undefined;
    if (!/^\.\.?(\/|$)/.test(specifier)) return this.resolveAlias(specifier);
    return this.resolvePath(path.join(path.dirname(fromFile), specifier));
  }

  // 'app/views/x' with baseUrl ./src, '@/lib/x' with paths { "@/*": ["src/*"] }
  resolveAlias(specifier) {
    if (!this.aliases) return undefined;
    for (const alias of this.aliases.paths) {
      const matches = alias.wildcard ? specifier.startsWith(alias.prefix) : specifier === alias.prefix;
      if (!matches) continue;
      for (const target of alias.targets) {
        const found = this.resolvePath(target.wildcard ? target.prefix + specifier.slice(alias.prefix.length) : target.prefix);
        if (found) return found;
      }
    }
    return this.aliases.baseUrl ? this.resolvePath(path.join(this.aliases.baseUrl, specifier)) : undefined;
  }

  resolvePath(base) {
    // TypeScript projects import './x.js' for './x.ts'
    const stem = base.replace(/\.(c|m)?js$/, '');
    const candidates = [base, ...EXTENSIONS.map(ext => stem + ext), ...EXTENSIONS.map(ext => path.join(base, 'index' + ext))];
    return candidates.find(candidate => this.files.has(candidate) || (path.isAbsolute(candidate) && safeIsFile(candidate)));
  }

  // { named: Map(name -> { node, reexport }), default: node, program } for a file, or undefined
  exportsOf(file) {
    if (this.exports.has(file)) return this.exports.get(file);
    this.exports.set(file, undefined); // guards against import cycles
    let result;
    try {
      const content = this.files.has(file) ? this.loader.load_buffer(file) : fs.readFileSync(file, 'utf8');
      const [type, data] = this.parser.parse(file, content);
      if (type === sourceTypes.JAVASCRIPT && data) result = collectExports(data.type === 'File' ? data.program : data);
    } catch {
      result = undefined; // unparsable files simply don't resolve
    }
    this.exports.set(file, result);
    return result;
  }

  /**
   * Where the data a function receives comes from, when a handler for untrusted input (IPC, navigation, deep links,
   * ...) passes its data to it, directly or through other helpers, in any file of the project. Returns a description
   * of the source or undefined.
   */
  untrustedSource(file, fn) {
    if (!this.taintedFunctions) {
      const start = performance.now();
      this.taintedFunctions = this.findTaintedFunctions();
      const collector = diagnostics();
      if (collector) collector.phase('crossFileDataFlow (within checks)', performance.now() - start);
    }
    return this.taintedFunctions.get(functionKey(file, fn));
  }

  // Is the function only ever called, anywhere in the project, with constant arguments (and never passed around)?
  onlyConstantCallers(file, fn) {
    const summary = this.summarize(file);
    const name = summary && summary.names.get(functionKey(file, fn));
    if (!name) return false; // anonymous or default-exported: callers can't be found by name
    for (const candidate of this.filesMentioning(name)) this.summarize(candidate);
    const calls = this.callSites.get(functionKey(file, fn));
    return !!calls && calls.count > 0 && calls.constant && !calls.escapes;
  }

  // Seeds are the handlers in files registering them; files the data flows into are summarized on demand
  findTaintedFunctions() {
    for (const file of this.files) if (SOURCE_HINT.test(this.text(file))) this.summarize(file);
    const tainted = new Map(this.seeds);
    let frontier = [...this.seeds.keys()];
    for (let depth = 0; depth < MAX_CALL_DEPTH && frontier.length > 0; depth++) {
      const next = [];
      for (const key of frontier) {
        this.summarize(key.slice(0, key.lastIndexOf(':', key.lastIndexOf(':') - 1)));
        for (const target of this.edges.get(key) || []) {
          if (tainted.has(target)) continue;
          tainted.set(target, tainted.get(key));
          next.push(target);
        }
      }
      frontier = next;
    }
    return tainted;
  }

  text(file) {
    try {
      return (this.files.has(file) ? this.loader.load_buffer(file) : fs.readFileSync(file)).toString();
    } catch {
      return '';
    }
  }

  // Scanned files whose source contains the word, e.g. every file that might call a helper
  filesMentioning(name) {
    if (!this.words) {
      const start = performance.now();
      const collector = diagnostics();
      this.words = new Map();
      for (const file of this.files) {
        if (!/\.[cm]?[jt]sx?$/.test(file)) continue;
        for (const word of new Set(this.text(file).match(/[A-Za-z_$][\w$]*/g) || [])) {
          if (!this.words.has(word)) this.words.set(word, []);
          this.words.get(word).push(file);
        }
      }
      if (collector) collector.phase('wordIndex (within checks)', performance.now() - start);
    }
    return this.words.get(name) || [];
  }

  /**
   * Records, once per file: the handlers registered in it (seeds), which functions pass their parameters (or values
   * derived from them) to which callees (edges), how each function is called (call sites) and the names of functions.
   */
  summarize(file) {
    if (this.summaries.has(file)) return this.summaries.get(file);
    this.summaries.set(file, undefined);
    let program;
    try {
      const [type, data] = this.parser.parse(file, this.text(file));
      if (type !== sourceTypes.JAVASCRIPT || !data) return undefined;
      program = data.type === 'File' ? data.program : data;
    } catch {
      return undefined;
    }
    const local = localFunctions(program);
    const names = new Map();
    for (const [name, fns] of local) for (const fn of fns) names.set(functionKey(file, fn), name);
    const resolve = (callee) => {
      if (!callee || callee.type !== 'Identifier') return isFunction(callee) ? [functionKey(file, callee)] : [];
      if (local.has(callee.name)) return local.get(callee.name).map(fn => functionKey(file, fn));
      const binding = moduleBindings(program).get(callee.name);
      const found = binding && binding.module && this.lookup(file, binding.module, binding.imported === '*' ? 'default' : binding.imported);
      return found && isFunction(found.node) ? [functionKey(found.file, found.node)] : [];
    };
    const site = (key) => {
      if (!this.callSites.has(key)) this.callSites.set(key, { count: 0, constant: true, escapes: false });
      return this.callSites.get(key);
    };
    // one walk: a call passing a function's parameters (or values derived from them) links that function to the callee
    visit(program, (node, ancestors) => {
      if (node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression' && node.type !== 'NewExpression') return true;
      const source = node.type !== 'NewExpression' ? sourceOfCall(node) : undefined;
      if (source) for (const handler of node.arguments) for (const key of resolve(handler)) if (key && !this.seeds.has(key)) this.seeds.set(key, source);
      const callees = resolve(node.callee).filter(Boolean);
      for (const key of callees) {
        const calls = site(key);
        calls.count++;
        if (!node.arguments.every(isConstant)) calls.constant = false;
      }
      // list.forEach(helper), setTimeout(helper): called with data we don't follow
      for (const argument of node.arguments) if (argument.type === 'Identifier') for (const key of resolve(argument)) if (key) site(key).escapes = true;
      if (callees.length > 0) {
        for (const fn of ancestors) {
          if (!isFunction(fn) || !node.arguments.some(argument => dependsOnParams(argument, fn))) continue;
          const key = functionKey(file, fn);
          this.edges.set(key, [...(this.edges.get(key) || []), ...callees]);
        }
      }
      return true;
    });
    const summary = { names };
    this.summaries.set(file, summary);
    return summary;
  }

  /**
   * The node bound to `imported` ('default', '*' or a name) in the module `specifier` imported from `fromFile`.
   * Returns { node, file, program } or undefined.
   */
  lookup(fromFile, specifier, imported, depth = 0) {
    if (depth > 5) return undefined;
    const file = this.resolve(fromFile, specifier);
    const exported = file && this.exportsOf(file);
    if (!exported) return undefined;
    if (imported === 'default' || imported === '*') {
      if (exported.default) return { node: exported.default, file, program: exported.program };
      return undefined;
    }
    const entry = exported.named.get(imported);
    if (entry && entry.reexport) return this.lookup(file, entry.reexport, entry.imported, depth + 1);
    if (entry) return { node: entry.node, file, program: exported.program };
    // export * from './other'
    for (const source of exported.star) {
      const found = this.lookup(file, source, imported, depth + 1);
      if (found) return found;
    }
    return undefined;
  }
}

function safeIsFile(file) {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

function collectExports(program) {
  const topLevel = new Map();
  const named = new Map();
  const star = [];
  let defaultExport;

  const declare = (declaration) => {
    if (!declaration) return [];
    if ((declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') && declaration.id) {
      topLevel.set(declaration.id.name, declaration);
      return [declaration.id.name];
    }
    if (declaration.type === 'VariableDeclaration') {
      return declaration.declarations.filter(d => d.id.type === 'Identifier').map(d => {
        topLevel.set(d.id.name, d.init);
        return d.id.name;
      });
    }
    return [];
  };

  for (const statement of program.body || []) {
    const node = statement.type === 'ExportNamedDeclaration' || statement.type === 'ExportDefaultDeclaration' ? statement.declaration || statement : statement;
    declare(node);
  }

  for (const statement of program.body || []) {
    if (statement.type === 'ExportNamedDeclaration') {
      for (const name of declare(statement.declaration)) named.set(name, { node: topLevel.get(name) });
      for (const spec of statement.specifiers || []) {
        const exported = keyName(spec.exported);
        const local = keyName(spec.local);
        if (statement.source) named.set(exported, { reexport: statement.source.value, imported: local });
        else named.set(exported, { node: topLevel.get(local) });
      }
    }
    if (statement.type === 'ExportAllDeclaration' && statement.source && !statement.exported) star.push(statement.source.value);
    if (statement.type === 'ExportDefaultDeclaration') {
      const declaration = statement.declaration;
      defaultExport = declaration && declaration.type === 'Identifier' ? topLevel.get(declaration.name) : declaration;
    }

    // CommonJS: module.exports = {...} / function, module.exports.x = ..., exports.x = ...
    const expression = statement.type === 'ExpressionStatement' ? statement.expression : undefined;
    if (expression && expression.type === 'AssignmentExpression' && isMember(expression.left)) {
      const left = expression.left;
      const target = keyName(left.property);
      const isModuleExports = left.object.type === 'Identifier' && left.object.name === 'module' && target === 'exports';
      const onExports = (left.object.type === 'Identifier' && left.object.name === 'exports') ||
        (isMember(left.object) && keyName(left.object.object) === 'module' && keyName(left.object.property) === 'exports');
      const value = expression.right.type === 'Identifier' && topLevel.has(expression.right.name) ? topLevel.get(expression.right.name) : expression.right;
      if (isModuleExports) {
        defaultExport = value;
        if (value && value.type === 'ObjectExpression') {
          for (const prop of value.properties) {
            const name = keyName(prop.key);
            if (!name) continue;
            const propValue = prop.value && prop.value.type === 'Identifier' && topLevel.has(prop.value.name) ? topLevel.get(prop.value.name) : (prop.value || prop);
            named.set(name, { node: propValue });
          }
        }
      } else if (onExports && target) {
        named.set(target, { node: value });
      }
    }
  }
  return { named, star, default: defaultExport, program };
}

// Literal arguments: 'https://example.com', 42, `text`, ['a', 'b'], { a: 1 }
function isConstant(node) {
  if (!node) return true;
  switch (node.type) {
    case 'Literal': case 'StringLiteral': case 'NumericLiteral': case 'BooleanLiteral': case 'NullLiteral': return true;
    case 'TemplateLiteral': return node.expressions.length === 0;
    case 'ArrayExpression': return node.elements.every(isConstant);
    case 'ObjectExpression': return node.properties.every(p => (p.type === 'Property' || p.type === 'ObjectProperty') && !p.computed && isConstant(p.value));
    case 'UnaryExpression': return isConstant(node.argument);
    default: return false;
  }
}

// Functions declared in a file by name: function f() {}, const f = () => {}, const f = function () {}
function localFunctions(program) {
  const functions = new Map();
  const add = (name, fn) => functions.set(name, [...(functions.get(name) || []), fn]);
  visit(program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id) add(node.id.name, node);
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && isFunction(node.init)) add(node.id.name, node.init);
    return true;
  });
  return functions;
}
