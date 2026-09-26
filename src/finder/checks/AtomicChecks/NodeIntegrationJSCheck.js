import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { constantValue } from '../analysis.js';
import { isWindowConstructor } from '../helpers.js';

// Options giving renderers access to Node.js, and how bad it is when they're on
const OPTIONS = {
  nodeIntegration: severity.HIGH,
  nodeIntegrationInWorker: severity.MEDIUM,
  nodeIntegrationInSubFrames: severity.MEDIUM,
};

// Electron security checklist #2: do not enable Node.js integration for remote content
export default class NodeIntegrationJSCheck {
  constructor() {
    this.id = "NODE_INTEGRATION_JS_CHECK";
    this.description = __("NODE_INTEGRATION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#2-do-not-enable-nodejs-integration-for-remote-content";
  }

  match(astNode, astHelper, scope, defaults){
    if (astNode.type !== 'NewExpression') return null;
    if (!isWindowConstructor(astNode)) return null; // also new electron.BrowserWindow() and minified new o.BrowserWindow()

    const locations = [];
    let nodeIntegrationFound = false;

    if (astNode.arguments.length > 0) {
      const target = scope.resolveVarValue(astNode);
      const valuesOf = (name) => astHelper.findNodeByType(target, astHelper.PropertyName, astHelper.PropertyDepth, false,
        node => node.key.value === name || node.key.name === name);

      // sandbox: true takes Node.js away from the renderer, whatever nodeIntegration says
      const sandboxed = valuesOf('sandbox').some(node => constantValue(node.value, scope) === true);

      for (const [option, optionSeverity] of Object.entries(OPTIONS)) {
        for (const node of valuesOf(option)) {
          if (option === 'nodeIntegration') nodeIntegrationFound = true;
          const value = constantValue(node.value, scope);
          // Electron treats nodeIntegration as on unless it's exactly false, the other options as off unless exactly true
          const enabled = option === 'nodeIntegration' ? value !== false : value === true;
          const at = { line: node.key.loc.start.line, column: node.key.loc.start.column, id: this.id, shortenedURL: this.shortenedURL };
          if (value === undefined) {
            locations.push({ ...at, description: `${this.description} (${option} is set from a value that can't be determined statically)`, severity: optionSeverity, confidence: confidence.TENTATIVE, manualReview: true });
          } else if (enabled && sandboxed) {
            continue;
          } else if (enabled) {
            locations.push({ ...at, description: `${this.description} (${option} is enabled)`, severity: optionSeverity, confidence: confidence.CERTAIN, manualReview: false });
          }
        }
      }
    }

    if (!nodeIntegrationFound && defaults.nodeIntegration) {
      locations.push({ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: `${this.description} (nodeIntegration is enabled by default before Electron 5)`, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false });
    }

    return locations;
  }
}
