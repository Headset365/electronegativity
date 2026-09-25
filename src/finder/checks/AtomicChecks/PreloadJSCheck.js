import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class PreloadJSCheck {
  constructor() {
    this.id = "PRELOAD_JS_CHECK";
    this.description = __("PRELOAD_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/JeuMu";
  }

  match(astNode, astHelper, scope, defaults = {}){
    if (astNode.type !== 'NewExpression') return null;
    if (astNode.callee.name !== 'BrowserWindow' && astNode.callee.name !== 'BrowserView') return null;

    let location = [];

    if (astNode.arguments.length > 0) {

      var target = scope.resolveVarValue(astNode);
      
      const found_nodes = astHelper.findNodeByType(target,
        astHelper.PropertyName,
        astHelper.PropertyDepth,
        false,
        node => (node.key.value === 'preload' || node.key.name === 'preload'));

      // with context isolation the preload only reaches the page through contextBridge, which CONTEXT_BRIDGE_EXPOSURE_JS_CHECK analyzes
      const isolation = astHelper.findNodeByType(target, astHelper.PropertyName, astHelper.PropertyDepth, false,
        node => (node.key.value === 'contextIsolation' || node.key.name === 'contextIsolation'));
      const isolated = isolation.length > 0 ? isolation.every(node => node.value.value === true) : !!defaults.contextIsolation;

      for (const node of found_nodes) {
        location.push(isolated
          ? { line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, description: __("PRELOAD_JS_CHECK_ISOLATED"), shortenedURL: this.shortenedURL, severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: true }
          : { line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true });
      }
    }

    return location;
  }
}