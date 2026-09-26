import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { constantValue } from '../analysis.js';
import { isWindowConstructor } from '../helpers.js';

// Electron security checklist #3: enable context isolation
export default class ContextIsolationJSCheck {
  constructor() {
    this.id = "CONTEXT_ISOLATION_JS_CHECK";
    this.description = __("CONTEXT_ISOLATION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://github.com/doyensec/electronegativity/wiki/CONTEXT_ISOLATION_JS_CHECK";
  }

  match(astNode, astHelper, scope, defaults){
    if (astNode.type !== 'NewExpression') return null;
    if (!isWindowConstructor(astNode)) return null; // also new electron.BrowserWindow() and minified new o.BrowserWindow()

    const report = (node, description, level, manualReview = false) => ({ line: node.loc.start.line, column: node.loc.start.column, id: this.id,
      description: `${this.description} (${description})`, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: level, manualReview });

    const target = astNode.arguments.length > 0 ? scope.resolveVarValue(astNode) : undefined;
    const contextIsolation = target ? astHelper.findNodeByType(target, astHelper.PropertyName, astHelper.PropertyDepth, false,
      node => (node.key.value === 'contextIsolation' || node.key.name === 'contextIsolation')) : [];

    // with duplicate keys the last one wins, but report any insecure value to be on the safe side
    const locations = [];
    for (const node of contextIsolation) {
      const value = constantValue(node.value, scope);
      if (value === undefined) locations.push(report(node.key, "contextIsolation is set from a value that can't be determined statically", confidence.TENTATIVE, true));
      else if (value !== true) locations.push(report(node.key, 'contextIsolation is disabled', confidence.CERTAIN));
    }

    // contextIsolation is enabled by default since Electron 12
    if (contextIsolation.length === 0 && !defaults.contextIsolation)
      locations.push(report(astNode, 'contextIsolation is disabled by default before Electron 12', confidence.FIRM));

    return locations;
  }
}
