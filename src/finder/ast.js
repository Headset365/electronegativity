import traverse from "@babel/traverse";
import estraverse from 'estraverse';
import * as eslintScope from 'eslint-scope';
import { getKeys } from 'eslint-visitor-keys';
import { visitorKeys } from '@typescript-eslint/visitor-keys';
import { resolveWindowOptions } from './checks/analysis.js';
import { isWindowConstructor } from './checks/helpers.js';

// ESTree + JSX + TypeScript visitor keys, falling back to the node's own keys for anything unknown (e.g. Flow annotations)
const keysOf = (node) => visitorKeys[node.type] || getKeys(node);
const isNode = (x) => x !== null && typeof x === 'object' && typeof x.type === 'string';

// Drop-in replacement for ESLint's former internal Traverser (lib/shared/traverser), which is no longer importable
class Traverser {
  constructor() {
    this._skipped = false;
    this._broken = false;
  }

  skip() { this._skipped = true; }

  break() { this._broken = true; }

  traverse(node, { enter = () => {}, leave = () => {} }) {
    this._enter = enter;
    this._leave = leave;
    this._skipped = false;
    this._broken = false;
    this._traverse(node, null);
  }

  _traverse(node, parent) {
    if (!isNode(node)) return;

    this._skipped = false;
    this._enter(node, parent);

    if (!this._skipped && !this._broken) {
      for (const key of keysOf(node)) {
        if (this._broken) break;
        const child = node[key];
        if (Array.isArray(child)) {
          for (let j = 0; j < child.length && !this._broken; ++j)
            this._traverse(child[j], node);
        } else {
          this._traverse(child, node);
        }
      }
    }

    if (!this._broken) this._leave(node, parent);
  }
}

class Ast {
  findNodeByType(ast, type, max_depth, stopAtFirst, found) {
    const cb = found;
    return this.findNode(ast, max_depth, stopAtFirst, (node) => {
      if ((node.type === type) && cb(node)) {
        return true;
      }
    });
  }

  constructor(settings) {
    this.settings = settings;
  }

  get PropertyName() {
    return this.settings.PropertyName;
  }

  get StringLiteral() {
    return this.settings.StringLiteral;
  }

  get PropertyDepth() {
    return this.settings.PropertyDepth;
  }

}

export class TreeSettings {
  constructor({propertyName = 'Property', stringLiteral = 'Literal', propertyDepth = 4} = {}) {
    this.PropertyName = propertyName;
    this.StringLiteral = stringLiteral;
    this.PropertyDepth = propertyDepth;
  }
}

export class Scope {

  constructor(ast) {
    if (/Program|File/.test(ast.type)) {
      const options = { ecmaVersion: 2022, childVisitorKeys: visitorKeys, fallback: getKeys };
      let scopeManager;
      try {
        scopeManager = eslintScope.analyze(ast, { ...options, sourceType: ast.sourceType === 'script' ? 'script' : 'module' });
      }
      catch {
        scopeManager = eslintScope.analyze(ast, { ...options, sourceType: 'script' });
      }

      this.scopeManager = scopeManager;
      this.globalScope = scopeManager.globalScope;
      this.functionScope = scopeManager.acquire(ast, true); // module scope for ES modules, global scope otherwise
    }
  }

  updateFunctionScope(ast, action) {
    if (!this.scopeManager) return;
    const outerScope = this.scopeManager.acquire(ast);
    if (outerScope == null) return;

    if (action === 'enter')
      this.functionScope = this.scopeManager.acquire(ast, true);
    else if (outerScope.upper != null) //check that functionScope is not globalScope (for code snippet with no func)
      this.functionScope = outerScope.upper;
  }

  getVarInScope(varName) {
    // walk up from the innermost scope (block, function, module) to the global one
    for (let scope = this.functionScope; scope; scope = scope.upper) {
      const res = scope.set.get(varName);
      if (res) return res;
    }
    return (this.globalScope && this.globalScope.set.get(varName)) || null;
  }

  resolveVarValue(astNode) {
    // BrowserWindow options are often merged from shared defaults: { ...defaults }, Object.assign({}, defaults, options)
    if (isWindowConstructor(astNode) && astNode.arguments[0]) return resolveWindowOptions(astNode, this);
    if (astNode.arguments[0].type !== "Identifier")
      return astNode.arguments[0];
    else {
      var target = this.getVarInScope(astNode.arguments[0].name);
      if (target != null) {
        target = target.defs[0].node.init;
        return target;
      } else {
        return astNode.arguments[0];
      }
    }
  }

}

export class EsprimaAst extends Ast {
  constructor(settings) {
    super(settings);
  }

  traverseTree(tree, options) {
    estraverse.traverse(tree, { keys: visitorKeys, fallback: keysOf, ...options });
  }

  getNode(node) {
    return node;
  }

  findNode(ast, max_depth, stopAtFirst, found) {
    const nodes = [];
    let depth = 0;
    estraverse.traverse(ast, {
      keys: visitorKeys,
      fallback: keysOf,
      enter: (node) => {
        depth += 1;
        if (found(node)) {
          nodes.push(node);
          if (stopAtFirst)
            return estraverse.VisitorOption.Break;
        }
        if (max_depth > 0) {
          if (depth > max_depth)
            throw new Error('Traversal error'); // shouldn't be here

          if (depth === max_depth)
            return estraverse.VisitorOption.Skip;
        }
      },
      leave: () => {
        depth -= 1;
      },
    });
    return nodes;
  }
}

export class BabelAst extends Ast {
  constructor(settings) {
    super(settings);
  }

  traverseTree(tree, options) {
    traverse(tree, options);
  }

  getNode(node) {
    return node.node;
  }

  findNode(ast, max_depth, stopAtFirst, found) {
    const nodes = [];
    let depth = 0;
    let shouldStop = false;
    traverse(ast, {
      noScope: true,
      enter: (node) => {
        depth += 1;
        if (found(this.getNode(node))) {
          nodes.push(this.getNode(node));
          if (stopAtFirst) {
            shouldStop = true;
            node.stop();
            return;
          }
        }
        if (max_depth > 0) {
          if (depth > max_depth)
            throw new Error('Traversal error'); // shouldn't be here

          if (depth === max_depth) {
            node.skip();
            depth -= 1; // exit will be not called
          }
        }
      },
      exit: (node) => {
        depth -= 1;
        if (shouldStop)
          node.stop();
      },
    });
    return nodes;
  }
}

export class ESLintAst extends Ast {
  constructor(settings) {
    super(settings);
    this.esLintTraverser = new Traverser();
  }

  findNodeByTypeParent(ast, type, max_depth, stopAtFirst, found) {
    return super.findNodeByType(ast, type, max_depth, stopAtFirst, found);
  }

  findNodeByType(ast, type, max_depth, stopAtFirst, found) {
    // create new instance, because findNode might stop traversing for current esLintTraverser
    return new ESLintAst(this.settings).findNodeByTypeParent(ast, type, max_depth, stopAtFirst, found);
  }

  traverseTree(tree, options) {
    this.esLintTraverser.traverse(tree, options);
  }

  getNode(node) {
    return node;
  }

  findNode(ast, max_depth, stopAtFirst, found) {
    const nodes = [];
    let depth = 0;
    this.esLintTraverser.traverse(ast, {
      enter: (node) => {
        if (max_depth > 0) {
          if (depth === max_depth) {
            this.esLintTraverser.skip();
            return;
          }
          if (depth > max_depth)
            throw new Error('Traversal error'); // shouldn't be here
        }

        depth += 1;
        if (found(this.getNode(node))) {
          nodes.push(this.getNode(node));
          if (stopAtFirst) {
            this.esLintTraverser.break();
            return;
          }
        }
      },
      leave: () => {
        depth -= 1;
      },
    });
    return nodes;
  }
}