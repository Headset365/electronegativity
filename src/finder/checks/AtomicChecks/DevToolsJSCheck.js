import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';

// DevTools left reachable in production builds give full control over the renderer (and the IPC it can reach)
export default class DevToolsJSCheck {
  constructor() {
    this.id = "DEVTOOLS_JS_CHECK";
    this.description = __("DEVTOOLS_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/web-contents#contentsopendevtoolsoptions";
  }

  match(astNode) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    const method = memberName(astNode.callee);
    if (method === 'openDevTools' || method === 'setDevToolsWebContents' || method === 'toggleDevTools') {
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.TENTATIVE, manualReview: true })];
    }
    return null;
  }
}
