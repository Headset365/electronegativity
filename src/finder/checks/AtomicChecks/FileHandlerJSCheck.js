import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, calleeObjectName, literalValue, finding, isFunction } from '../helpers.js';
import { handlerFunction, paramNames, visit } from '../analysis.js';
import { entryContext, flowDescription } from '../entry_context.js';

// Events delivering attacker-controllable files, URLs or command lines to the main process
const EVENTS = {
  'open-file': 'files opened through file associations (macOS)',
  'open-url': 'URLs opened through custom protocols (macOS)',
  'second-instance': 'the command line of a second instance, including deep links and files on Windows/Linux',
};

// every use of the handler's data arguments is a comparison with constants: x.includes('--flag'), x.indexOf('a') !== -1,
// x === 'b', x.length
function onlyInspected(fn) {
  const params = new Set(paramNames(fn).slice(1));
  if (!params.size) return true;
  let inspected = true;
  visit(fn.body || fn, (node, ancestors) => {
    if (!inspected) return false;
    if (node.type !== 'Identifier' || !params.has(node.name)) return true;
    const parent = ancestors[ancestors.length - 1];
    if (!parent) return true;
    if ((parent.type === 'MemberExpression' || parent.type === 'OptionalMemberExpression') && parent.object === node) {
      const method = memberName(parent);
      const call = ancestors[ancestors.length - 2];
      if (method === 'length') return true;
      if (['includes', 'indexOf', 'some', 'startsWith', 'endsWith'].includes(method) && call && call.type === 'CallExpression' && call.callee === parent
        && call.arguments.every(arg => literalValue(arg) !== undefined)) return true;
      inspected = false;
      return false;
    }
    if (parent.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(parent.operator)) return true;
    // a parameter declaration itself
    if (isFunction(parent) && parent.params.includes(node)) return true;
    inspected = false;
    return false;
  });
  return inspected;
}

export default class FileHandlerJSCheck {
  constructor() {
    this.id = "FILE_HANDLER_JS_CHECK";
    this.description = __("FILE_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/launch-app-from-url-in-another-app";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (!['on', 'once', 'addListener'].includes(memberName(astNode.callee)) || calleeObjectName(astNode.callee) !== 'app') return null;
    const event = literalValue(astNode.arguments[0]);
    if (!EVENTS[event]) return null;
    const flow = entryContext(astNode.arguments[1], scope, context.ancestors, event === 'second-instance' ? [null, 'commandLine', 'workingDirectory', 'additionalData'] : [null, event === 'open-url' ? 'url' : 'filePath']);
    // a handler that only looks for a fixed switch (commandLine.includes('--quick-calc')) and passes nothing on
    const fn = handlerFunction(astNode.arguments[1], scope, context.ancestors);
    if (fn && !flow.effects.some(effect => effect.arguments.length) && onlyInspected(fn))
      return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: false,
        description: `${this.description}: ${EVENTS[event]}; the handler only compares it with fixed values and passes none of it on`, properties: { event, context: flow } })];
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description}: ${EVENTS[event]}; ${flowDescription(flow)}`, properties: { event, context: flow } })];
  }
}
