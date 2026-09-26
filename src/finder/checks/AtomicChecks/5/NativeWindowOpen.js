import { sourceTypes } from '../../../../parser/types.js';
import { severity, confidence } from '../../../attributes.js';
import { isWindowConstructor, literalValue } from '../../helpers.js';

export default class NativeWindowOpen {
  constructor() {
    this.id = "NATIVE_WINDOW_OPEN_CHANGE";
    this.description = __("NATIVE_WINDOW_OPEN_CHANGE");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/NATIVE_WINDOW_OPEN_CHANGE";
  }

  match(astNode, astHelper, scope){
    if (astNode.type !== 'NewExpression') return null;
    if (!isWindowConstructor(astNode)) return null; // also new electron.BrowserWindow() and minified new o.BrowserWindow()

    let location = [];

    if (astNode.arguments.length > 0) {
      
      var target = scope.resolveVarValue(astNode);

      const found_nodes = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value === 'nativeWindowOpen' || node.key.name === 'nativeWindowOpen'));

      for (const node of found_nodes) {
        if (literalValue(node.value)) {
          location.push({ line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: true });
        }
      }
    }

    return location;
  }
}