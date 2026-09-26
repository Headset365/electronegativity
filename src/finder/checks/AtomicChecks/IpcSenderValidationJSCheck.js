import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { calleeObjectName, memberName, visit, finding } from '../helpers.js';
import { handlerFunction } from '../analysis.js';

const LISTENER_METHODS = ['handle', 'handleOnce', 'on', 'once', 'addListener'];
// Properties of the IPC event (event.senderFrame.url, event.sender.getURL(), ...) that identify the sender
const SENDER_PROPERTIES = ['senderFrame', 'origin', 'url', 'getURL'];

function memberChain(node) {
  const names = [];
  while (node && (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression')) {
    names.unshift(memberName(node));
    node = node.object;
  }
  return { root: node && node.type === 'Identifier' ? node.name : undefined, names };
}

// Electron security checklist #17: validate the sender of all IPC messages
export default class IpcSenderValidationJSCheck {
  constructor() {
    this.id = "IPC_SENDER_VALIDATION_JS_CHECK";
    this.description = __("IPC_SENDER_VALIDATION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#17-validate-the-sender-of-all-ipc-messages";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    if (!LISTENER_METHODS.includes(memberName(astNode.callee))) return null;
    if (!/^ipcMain$/.test(calleeObjectName(astNode.callee) || '')) return null;
    if (astNode.arguments.length < 2) return null;

    let handlerArg = astNode.arguments[astNode.arguments.length - 1];
    // wrappers like ipcValidate(handler, schema) or withSenderCheck(handler)
    if ((handlerArg.type === 'CallExpression' || handlerArg.type === 'OptionalCallExpression') && memberName(handlerArg.callee) !== 'bind' && handlerArg.arguments.length > 0) {
      const wrapper = handlerArg.callee.type === 'Identifier' ? handlerArg.callee.name : memberName(handlerArg.callee);
      if (/sender|origin|trusted|secure|guard|auth/i.test(wrapper || ''))
        return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
          description: `${this.description} (wrapped by ${wrapper}(); verify that it validates the sender)` })];
      handlerArg = handlerArg.arguments[0];
    }
    const handler = handlerFunction(handlerArg, scope, context.ancestors);
    if (!handler) {
      // handler defined elsewhere, can't tell whether it validates the sender
      return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true })];
    }

    if (this.validatesSender(handler)) return null;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true })];
  }

  validatesSender(handler) {
    const eventParam = handler.params && handler.params[0];
    if (!eventParam) return false; // the event object isn't even received

    let validates = false;
    // `({ senderFrame }) => ...`
    if (eventParam.type === 'ObjectPattern') {
      validates = eventParam.properties.some(p => p.key && SENDER_PROPERTIES.includes(p.key.name || p.key.value));
    }

    visit(handler.body, (node) => {
      if (validates) return false;
      if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
        const { root, names } = memberChain(node);
        if (names.includes('senderFrame') ||
            (eventParam.type === 'Identifier' && root === eventParam.name && names.some(n => SENDER_PROPERTIES.includes(n))))
          validates = true;
      }
      // a helper receiving the whole event, e.g. validateSender(event)
      if ((node.type === 'CallExpression' || node.type === 'OptionalCallExpression') && eventParam.type === 'Identifier' &&
          node.arguments.some(a => a.type === 'Identifier' && a.name === eventParam.name)) validates = true;
    });
    return validates;
  }
}
