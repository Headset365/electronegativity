import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { entryContext } from '../entry_context.js';

const REGISTRATIONS = ['registerStandardSchemes', 'registerServiceWorkerSchemes', 'registerFileProtocol', 'registerHttpProtocol',
  'registerStringProtocol', 'registerBufferProtocol', 'registerStreamProtocol'];
const INTERCEPTIONS = ['interceptFileProtocol', 'interceptHttpProtocol', 'interceptStringProtocol', 'interceptBufferProtocol', 'interceptStreamProtocol'];
// Custom protocols (checklist #18) replace file://, but their handlers must not serve files outside the app
export default class ProtocolHandlerJSCheck {
  constructor() {
    this.id = "PROTOCOL_HANDLER_JS_CHECK";
    this.description = __("PROTOCOL_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression') return null;
    const method = astNode.callee.type === 'Identifier' ? astNode.callee.name : memberName(astNode.callee);
    const object = astNode.callee.object;
    const objectName = object && (object.name || (object.property && object.property.name)) || '';
    // protocol.handle() (Electron 25+), only on the protocol module since `handle` is a common method name (e.g. ipcMain.handle)
    const isHandle = method === 'handle' && /protocol$/i.test(objectName);
    let flow;
    const report = (sev, conf, reason, manualReview = true) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, properties: flow ? { context: flow, entryPoint: 'custom-protocol' } : undefined, description: `${this.description} (${reason})` })];

    if (method === 'setAsDefaultProtocolClient')
      return report(severity.LOW, confidence.CERTAIN, 'the app registers itself as a deep link handler; every URL of this scheme reaches it');
    if (INTERCEPTIONS.includes(method))
      return report(severity.LOW, confidence.FIRM, `${method} replaces the handling of a standard scheme; review the handler`);
    if (!isHandle && !REGISTRATIONS.includes(method)) return null;

    flow = entryContext(astNode.arguments[1], scope, context.ancestors, ['request', null]);
    const effects = flow.effects.filter(effect => effect.capability === 'files' && effect.pathArguments.length);
    const servesFiles = effects.length || method === 'registerFileProtocol';
    if (!servesFiles) return report(severity.LOW, confidence.FIRM, `custom protocol handler; review what it serves (${flow.status})`);
    const contained = effects.length && effects.every(effect => effect.pathControl === 'recognized-unverified');
    if (!contained)
      return report(severity.HIGH, confidence.FIRM, 'request-derived file paths have no relevant pre-operation containment guard; validate traversal and caller access', true);
    return report(severity.LOW, confidence.FIRM, 'the relevant file paths have recognized guards; review their implementation and runtime behavior');
  }
}
