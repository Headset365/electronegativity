import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, calleeObjectName, literalValue, finding } from '../helpers.js';

// Events delivering attacker-controllable files, URLs or command lines to the main process
const EVENTS = {
  'open-file': 'files opened through file associations (macOS)',
  'open-url': 'URLs opened through custom protocols (macOS)',
  'second-instance': 'the command line of a second instance, including deep links and files on Windows/Linux',
};

export default class FileHandlerJSCheck {
  constructor() {
    this.id = "FILE_HANDLER_JS_CHECK";
    this.description = __("FILE_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/launch-app-from-url-in-another-app";
  }

  match(astNode) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (!['on', 'once', 'addListener'].includes(memberName(astNode.callee)) || calleeObjectName(astNode.callee) !== 'app') return null;
    const event = literalValue(astNode.arguments[0]);
    if (!EVENTS[event]) return null;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description}: ${EVENTS[event]}`, properties: { event } })];
  }
}
