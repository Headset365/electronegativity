import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { isWindowConstructor, literalValue } from '../helpers.js';

export default class SandboxJSCheck {
  constructor() {
    this.id = "SANDBOX_JS_CHECK";
    this.description = __("SANDBOX_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#4-enable-process-sandboxing";
  }

  match(astNode, astHelper, scope, defaults){
    // app.enableSandbox() sandboxes every renderer; SandboxGlobalCheck then drops the per-window findings
    if (astNode.type === 'CallExpression' && astNode.callee.property && astNode.callee.property.name === 'enableSandbox')
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: __("SANDBOX_JS_CHECK_ENABLED_GLOBALLY"), shortenedURL: this.shortenedURL, severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: false, properties: { sandboxedGlobally: true } }];
    if (astNode.type !== 'NewExpression') return null;
    if (!isWindowConstructor(astNode)) return null; // also new electron.BrowserWindow() and minified new o.BrowserWindow()

    let wasFound = false;
    let nodeIntegrationEnabled = false;
    let loc = [];
    if (astNode.arguments.length > 0) {

      var target = scope.resolveVarValue(astNode);

      // since Electron 20 renderers are sandboxed by default, unless nodeIntegration is enabled
      nodeIntegrationEnabled = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value === 'nodeIntegration' || node.key.name === 'nodeIntegration') && literalValue(node.value) !== false).length > 0;

      const found_nodes = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value === 'sandbox' || node.key.name === 'sandbox'));

      for (const node of found_nodes) {
        wasFound = true;
        if (literalValue(node.value) === true) {
          continue;
        }
        loc.push({ line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: false });
      }
    }

    if (wasFound) {
      return loc;
    } else if (!defaults.sandbox || nodeIntegrationEnabled) { // default is false before Electron 20
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: false }];
    }
    return loc;
  }
}
