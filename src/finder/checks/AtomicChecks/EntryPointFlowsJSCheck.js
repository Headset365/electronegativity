import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue, finding } from '../helpers.js';
import { isCall, resolveLocal } from '../analysis.js';
import { entryContext, flowDescription } from '../entry_context.js';

// Renderer input routes: pasted/dropped files and markup, messages, file-picker changes and FileReader results. These are
// the page's own inputs, not deep links or file associations: reported when the input reaches an operation, and only as
// an informational entry point when the analysis could not follow it.
export default class EntryPointFlowsJSCheck {
  constructor() {
    this.id = 'RENDERER_INPUT_JS_CHECK';
    this.description = __('RENDERER_INPUT_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/tutorial/security';
  }
  match(node, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    let event, callback;
    if (isCall(node) && memberName(node.callee) === 'addEventListener') {
      event = literalValue(node.arguments[0]); callback = node.arguments[1];
      if (!['paste', 'drop', 'change', 'message'].includes(event)) return null;
    } else if (node.type === 'AssignmentExpression' && memberName(node.left) === 'onload') {
      // Restrict onload to a FileReader constructed in the same lexical context.
      const receiver = node.left.object;
      if (receiver?.type !== 'Identifier') return null;
      const variable = resolveLocal(receiver, scope);
      if (variable?.type !== 'NewExpression' || variable.callee.name !== 'FileReader') return null;
      event = 'file-reader'; callback = node.right;
    } else return null;
    const flow = entryContext(callback, scope, context.ancestors, ['input']);
    const effects = flow.effects.filter(effect => effect.arguments.length);
    if (!effects.length && flow.status !== 'incomplete') return null;
    return [finding(this, node, { severity: effects.length ? severity.MEDIUM : severity.INFORMATIONAL, confidence: effects.length ? confidence.FIRM : confidence.TENTATIVE,
      manualReview: true, description: `External ${event} input: ${flowDescription(flow)}`, properties: { event, context: flow } })];
  }
}
