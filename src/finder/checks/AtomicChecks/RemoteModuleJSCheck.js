import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { constantValue } from '../analysis.js';
import { memberName, literalValue } from '../helpers.js';
import { isWindowConstructor } from '../helpers.js';

export default class RemoteModuleJSCheck {
  constructor() {
    this.id = "REMOTE_MODULE_JS_CHECK";
    this.description = __("REMOTE_MODULE_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/REMOTE_MODULE_JS_CHECK";
  }

  match(astNode, astHelper, scope, defaults){
    if (astNode.type === 'CallExpression') return this.matchElectronRemote(astNode);
    if (astNode.type === 'ImportDeclaration' && /^@electron\/remote(\/(main|renderer))?$/.test(literalValue(astNode.source) || ''))
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true }];
    if (astNode.type !== 'NewExpression') return null;
    if (!isWindowConstructor(astNode)) return null; // also new electron.BrowserWindow() and minified new o.BrowserWindow()
    // the built-in 'remote' module was removed in Electron 14, where enableRemoteModule has no effect
    if (!('enableRemoteModule' in defaults)) return null;

    let wasFound = false;
    let loc = [];
    if (astNode.arguments.length > 0) {

      var target = scope.resolveVarValue(astNode);

      const found_nodes = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value === 'enableRemoteModule' || node.key.name === 'enableRemoteModule'));

      for (const node of found_nodes) {
        wasFound = true;
        const value = constantValue(node.value, scope);
        if (value === false) continue;
        const at = { line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, shortenedURL: this.shortenedURL, severity: severity.MEDIUM };
        if (value === undefined) loc.push({ ...at, description: `${this.description} (enableRemoteModule is set from a value that can't be determined statically)`, confidence: confidence.TENTATIVE, manualReview: true });
        else loc.push({ ...at, description: `${this.description} (enableRemoteModule is enabled)`, confidence: confidence.CERTAIN, manualReview: false });
      }
    }

    if (wasFound) {
      return loc;
    } else if (defaults.enableRemoteModule) { // before Electron 10 the remote module is enabled unless enableRemoteModule is false
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: `${this.description} (the remote module is enabled by default before Electron 10)`, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: false }];
    }
  }

  // @electron/remote, the userland replacement of the removed module: require('@electron/remote'), remoteMain.initialize() / .enable(webContents)
  matchElectronRemote(astNode) {
    const callee = astNode.callee;
    const isRequire = callee.type === 'Identifier' && callee.name === 'require' && /^@electron\/remote(\/(main|renderer))?$/.test(literalValue(astNode.arguments[0]) || '');
    const method = memberName(callee);
    const object = callee.object;
    const objectName = object && (object.type === 'Identifier' ? object.name :
      (object.type === 'CallExpression' && object.callee.name === 'require' ? literalValue(object.arguments[0]) : undefined));
    const isEnable = ['enable', 'initialize'].includes(method) && /remote/i.test(objectName || '');
    if (!isRequire && !isEnable) return null;
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: isEnable ? confidence.CERTAIN : confidence.FIRM, manualReview: true }];
  }
}
