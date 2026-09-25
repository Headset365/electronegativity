import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { electronAtLeast, ELECTRON_CHANGES } from '../versions.js';

export default class AffinityJSCheck {
  constructor() {
    this.id = "AFFINITY_JS_CHECK";
    this.description = __("AFFINITY_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/Jeu1z";
  }

  match(astNode, astHelper, scope, defaults, electronVersion) {
    // the affinity option was removed in Electron 14
    if (electronAtLeast(electronVersion, ELECTRON_CHANGES.AFFINITY_REMOVED)) return null;
    if (astNode.type !== 'NewExpression') return null;
    if (astNode.callee.name !== 'BrowserWindow' && astNode.callee.name !== 'BrowserView') return null;

    let location = [];

    if (astNode.arguments.length > 0) {

      var target = scope.resolveVarValue(astNode);

      const found_nodes = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value  === 'affinity' || node.key.name === 'affinity'));

      for (const node of found_nodes) {
        if (node.value.value) {
          location.push({ line: node.value.loc.start.line, column: node.value.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, properties: { "AffinityString": node.value.value }, manualReview: true });
        }
      }
    }

    return location;
  }
}