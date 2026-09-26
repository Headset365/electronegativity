// Cross-file resolution: what the files of the scanned project export, so handlers and constants imported from
// other files can be analyzed. Files are parsed lazily, only when something imports from them.
import path from 'node:path';
import fs from 'node:fs';
import { sourceTypes } from '../parser/types.js';

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
