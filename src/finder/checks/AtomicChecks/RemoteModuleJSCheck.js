import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue } from '../helpers.js';

export default class RemoteModuleJSCheck {
  constructor() {
    this.id = "REMOTE_MODULE_JS_CHECK";
    this.description = __("REMOTE_MODULE_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/JvqrQ";
  }

  match(astNode, astHelper, scope, defaults){
    if (astNode.type === 'CallExpression') return this.matchElectronRemote(astNode);
    if (astNode.type === 'ImportDeclaration' && /^@electron\/remote(\/(main|renderer))?$/.test(literalValue(astNode.source) || ''))
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
    if (astNode.type !== 'NewExpression') return null;
    if (astNode.callee.name !== 'BrowserWindow' && astNode.callee.name !== 'BrowserView') return null;
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
        if (node.value.value === false) {
          continue;
        }
        loc.push({ line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: false });
      }
    }

    if (wasFound) {
      return loc;
    } else if (defaults.enableRemoteModule) { // in earlier versions, 'remote' is enabled by default (assuming nodeIntegration:true), which is a misconfiguration
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
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
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: isEnable ? confidence.FIRM : confidence.TENTATIVE, manualReview: true }];
  }
}
