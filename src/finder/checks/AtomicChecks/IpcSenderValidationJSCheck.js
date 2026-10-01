import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, visit, finding, isFunction } from '../helpers.js';
import { handlerFunction } from '../analysis.js';
import { ipcListener, ipcDefinition, inspectPredicate } from '../ipc_context.js';

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
    if (!ipcListener(astNode, scope)) return null;
    if (astNode.arguments.length < 2) return null;

    // the channel name, so a watch session can tie content seen on that channel to this handler
    const channelArg = astNode.arguments[0];
    const properties = (channelArg.type === 'StringLiteral' || channelArg.type === 'Literal') && typeof channelArg.value === 'string' ? { channel: channelArg.value } : undefined;
    let handlerArg = astNode.arguments[astNode.arguments.length - 1];
    // wrappers like ipcValidate(handler, schema) or withSenderCheck(handler)
    if ((handlerArg.type === 'CallExpression' || handlerArg.type === 'OptionalCallExpression') && memberName(handlerArg.callee) !== 'bind' && handlerArg.arguments.length > 0) {
      const wrapper = handlerArg.callee.type === 'Identifier' ? handlerArg.callee.name : memberName(handlerArg.callee);
      if (/sender|origin|trusted|secure|guard|auth/i.test(wrapper || '') && !ipcDefinition(handlerArg, scope, context.ancestors))
        return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true, properties,
          description: `${this.description} (wrapped by ${wrapper}(); wrapper authorization is unverified)` })];
      if (!ipcDefinition(handlerArg, scope, context.ancestors)) handlerArg = handlerArg.arguments[0];
    }
    const definition = ipcDefinition(handlerArg, scope, context.ancestors);
    const handler = definition?.node || handlerFunction(handlerArg, scope, context.ancestors);
    if (!handler || !isFunction(handler)) {
      // handler defined elsewhere, can't tell whether it validates the sender
      return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true, properties })];
    }

    if (this.validatesSender(handler, definition)) return null;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties })];
  }

  validatesSender(handler, definition) {
    const eventParam = handler.params && handler.params[0];
    if (!eventParam) return false; // the event object isn't even received

    const eventNames = eventParam.type === 'Identifier' ? [eventParam.name] :
      eventParam.type === 'ObjectPattern' ? eventParam.properties.filter(p => p.key && SENDER_PROPERTIES.includes(p.key.name || p.key.value)).map(p => p.value && p.value.name).filter(Boolean) : [];
    if (!eventNames.length) return false;
    // An expression-bodied handler can explicitly gate its result on a named sender assertion.
    // General calls receiving `event` (including logging) do not count.
    if (handler.body && handler.body.type === 'LogicalExpression' && handler.body.operator === '&&') {
      const gate = handler.body.left;
      const name = gate && gate.callee && (gate.callee.name || memberName(gate.callee));
      if (gate && (gate.type === 'CallExpression' || gate.type === 'OptionalCallExpression') &&
        /^(?:assert|validate|verify|is)(?:Trusted|Authorized|Allowed|Secure)(?:Sender|Origin)?$/i.test(name || '') &&
        gate.arguments.some(arg => arg.type === 'Identifier' && eventNames.includes(arg.name)) &&
        (!definition || inspectPredicate(gate, definition).arguments.includes('$sender'))) return true;
    }
    const referencesSender = (root) => {
      let found = false;
      visit(root, node => {
        if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
          const chain = memberChain(node);
          if (eventNames.includes(chain.root) && (eventParam.type === 'ObjectPattern' || chain.names.some(n => SENDER_PROPERTIES.includes(n)))) found = true;
        } else if (node.type === 'Identifier' && eventParam.type === 'ObjectPattern' && eventNames.includes(node.name)) found = true;
      });
      return found;
    };
    let guarded = false;
    visit(handler.body, (node, ancestors) => {
      if (isFunction(node)) return false;
      if (node.type !== 'IfStatement' || !referencesSender(node.test)) return;
      // Reading or logging senderFrame is not validation. Require a rejecting branch before the handler's work.
      const rejects = branch => {
        let found = false;
        if (branch?.type === 'BlockStatement') branch = branch.body.at(-1);
        if (branch?.type === 'ThrowStatement' || branch?.type === 'ReturnStatement' && (!branch.argument || /^(Literal|\w*Literal)$/.test(branch.argument.type))) found = true;
        return found;
      };
      // A guard buried in a conditional or appearing after work does not protect the whole handler.
      if (ancestors.length !== 1 || ancestors[0] !== handler.body) return;
      let priorWork = false;
      for (const statement of handler.body.body.slice(0, handler.body.body.indexOf(node))) visit(statement, child => {
        if (isFunction(child)) return false;
        if (child.type === 'AssignmentExpression' && memberName(child.left) === 'returnValue') priorWork = true;
        if (/^(CallExpression|OptionalCallExpression|NewExpression)$/.test(child.type)) {
          const name = child.callee.name || memberName(child.callee);
          if (!(/^(URL|getURL)$/.test(name || '') && referencesSender(child))) priorWork = true;
        }
        return true;
      });
      if (!priorWork && (rejects(node.consequent) || rejects(node.alternate)) &&
        (!definition || inspectPredicate(node.test, definition, !rejects(node.consequent)).arguments.includes('$sender'))) guarded = true;
    });
    return guarded;
  }
}
