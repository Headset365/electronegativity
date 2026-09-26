import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { isWindowConstructor, literalValue } from '../helpers.js';

export default class ExperimentalFeaturesJSCheck {
  constructor() {
    this.id = "EXPERIMENTAL_FEATURES_JS_CHECK";
    this.description = __("EXPERIMENTAL_FEATURES_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#9-do-not-enable-experimental-features";
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
        node => (node.key.value === 'experimentalFeatures' ||
                 node.key.name  === 'experimentalFeatures' ||
                 node.key.value === 'experimentalCanvasFeatures' ||
                 node.key.name  === 'experimentalCanvasFeatures'));

      for (const node of found_nodes) {
        if (literalValue(node.value) === true) {
          location.push({ line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: false });
        }
      }
    }

    return location;
  }
}