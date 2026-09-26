import * as espree from 'espree';
import * as babelParser from "@babel/parser";
import * as typescriptEstreeParser from '@typescript-eslint/typescript-estree';
import { load as cheerio_load } from 'cheerio';

import { extension } from '../util/index.js';
import { isLockfile, listLockfilePackages } from '../util/lockfiles.js';
import { parse as parseYaml } from 'yaml';
import path from 'node:path';
import { sourceTypes, sourceExtensions } from './types.js';

import { LexicalScope } from '../finder/checks/analysis.js';
import { EsprimaAst, BabelAst, ESLintAst, TreeSettings, Scope } from '../finder/ast.js';

export class Parser {
  constructor(babelFirst, typescriptBabelFirst) {
    this.esLintESTreeAst = new ESLintAst(new TreeSettings());
    this.esLintBabelTreeAst = new ESLintAst(new TreeSettings({propertyName: 'ObjectProperty', stringLiteral: 'StringLiteral'}));
    this.babelAst = new BabelAst(new TreeSettings({propertyName: 'ObjectProperty', stringLiteral: 'StringLiteral'}));
    this.esprimaAst = new EsprimaAst(new TreeSettings());

    this.babelFirst = babelFirst;
    this.typescriptBabelFirst = typescriptBabelFirst;
    // Syntax that reached Stage 4 is enabled by default in Babel 8, only non-standard syntax needs a plugin
    this.babelPlugins = [
      "jsx",
      "decorators-legacy",
      "flow",
      "exportDefaultFrom", // export x from './y', common in Vue/webpack era projects
      "estree",
    ];

    this.tsPlugins = [
      "jsx",
      "decorators-legacy",
      "typescript",
    ];
  }

  addPlugin(plugin) {
    this.tsPlugins.push(plugin);
    this.babelPlugins.push(plugin);
  }

  // Kept under its historical name: espree replaced the unmaintained esprima parser, producing the same ESTree AST
  parseEsprima(content) {
    let data;
    try {
      data = espree.parse(content, { ecmaVersion: 'latest', sourceType: 'module', loc: true, range: true, ecmaFeatures: { jsx: true } });
    } catch {
      data = espree.parse(content, { ecmaVersion: 'latest', sourceType: 'script', loc: true, range: true, ecmaFeatures: { jsx: true, globalReturn: true } });
    }
    data.astParser = this.esprimaAst;
    data.Scope = new Scope(data);
    return data;
  }

  parseBabel(content) {
    const file = babelParser.parse(content, {
      sourceType: "unambiguous",
      errorRecovery: true,
      ranges: true,
      plugins: this.babelPlugins,
    });
    let data = file.program;
    if (file.errors && file.errors.length > 0) data.errors = file.errors;

    data.astParser = this.esprimaAst;
    data.Scope = new Scope(data);
    return data;
  }

  // JSX is only valid in .tsx: in .ts files `<T>(x) => x` is a generic arrow function, not an element
  parseTypeScript(content, jsx = true) {
    let data = babelParser.parse(content, {
      sourceType: "unambiguous",
      plugins: jsx ? this.tsPlugins : this.tsPlugins.filter(p => p !== 'jsx')
    });

    data.astParser = this.esLintBabelTreeAst;
    data.Scope = new LexicalScope(); // eslint-scope doesn't understand TypeScript nodes
    return data;
  }

  parseTypescriptEstree(content, jsx = true) {
    let data = typescriptEstreeParser.parse(content, {
      loc: true,
      range: true,
      tokens: true,
      errorOnUnknownASTType: true,
      jsx,
    });

    data.astParser = this.esLintESTreeAst;
    data.Scope = new LexicalScope(); // eslint-scope doesn't understand TypeScript nodes
    return data;
  }

  parse(filename, content) {
    const ext = extension(filename);

    const isBuilderYaml = /^electron-builder\.ya?ml$/i.test(path.basename(filename));
    const sourceType = isLockfile(filename) ? sourceTypes.LOCKFILE : (isBuilderYaml ? sourceTypes.JSON : sourceExtensions[ext]);
    content = content.toString();
    let data = null;

    switch (sourceType) {
      case sourceTypes.JAVASCRIPT:
        // replace shebang (https://en.wikipedia.org/wiki/Shebang_(Unix)) with spaces to keep offsets intact
        content = content.replace(/(^#!.*)/, function(m) { return Array(m.length + 1).join(' '); });

        if (['ts', 'tsx', 'mts', 'cts'].includes(ext)) {
          try {
            const jsx = ext === 'tsx';
            data = this.typescriptBabelFirst ? this.parseTypeScript(content, jsx) : this.parseTypescriptEstree(content, jsx);
          } catch (error1) {
            try {
              data = this.typescriptBabelFirst ? this.parseTypescriptEstree(content, ext === 'tsx') : this.parseTypeScript(content, ext === 'tsx');
            } catch (error2) {
              throw this.typescriptBabelFirst ? error1 : error2; // prefer babel as it contains line number
            }
          }
          break;
        }

        try {
          data = this.babelFirst ? this.parseBabel(content) : this.parseEsprima(content);
        } catch (error) {
          data = this.babelFirst ? this.parseEsprima(content) : this.parseBabel(content);
        }
        break;
      case sourceTypes.HTML:
        data = cheerio_load(content, { xmlMode: true, withStartIndices: true, lowerCaseTags: true, lowerCaseAttributeNames: true });
        break;
      case sourceTypes.JSON:
        data = {json: isBuilderYaml ? parseYaml(content) : JSON.parse(content), text: content};
        break;
      case sourceTypes.LOCKFILE:
        data = {filename, packages: listLockfilePackages(filename, content)};
        break;
      default:
        break;
    }

    return [sourceType, data, content, data ? data.errors : undefined];
  }
}
