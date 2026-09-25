import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { handlerFunction, callsIn, dependsOnParams, constantPrefix, visit } from '../analysis.js';

const REGISTRATIONS = ['registerStandardSchemes', 'registerServiceWorkerSchemes', 'registerFileProtocol', 'registerHttpProtocol',
  'registerStringProtocol', 'registerBufferProtocol', 'registerStreamProtocol'];
const INTERCEPTIONS = ['interceptFileProtocol', 'interceptHttpProtocol', 'interceptStringProtocol', 'interceptBufferProtocol', 'interceptStreamProtocol'];
// calls that turn a request into a file access
const FILE_SINKS = /^(join|resolve|readFile|readFileSync|createReadStream|fetch|pathToFileURL|sendFile|stat|statSync|access)$/;
// ways to keep a path inside a directory
const CONTAINMENT = /^(startsWith|relative|normalize|isAbsolute|realpath|realpathSync|includes|indexOf|test|basename)$/;

// Custom protocols (checklist #18) replace file://, but their handlers must not serve files outside the app
export default class ProtocolHandlerJSCheck {
  constructor() {
    this.id = "PROTOCOL_HANDLER_JS_CHECK";
    this.description = __("PROTOCOL_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols";
  }

  match(astNode, astHelper, scope) {
    if (astNode.type !== 'CallExpression') return null;
    const method = astNode.callee.type === 'Identifier' ? astNode.callee.name : memberName(astNode.callee);
    const object = astNode.callee.object;
    const objectName = object && (object.name || (object.property && object.property.name)) || '';
    // protocol.handle() (Electron 25+), only on the protocol module since `handle` is a common method name (e.g. ipcMain.handle)
    const isHandle = method === 'handle' && /protocol$/i.test(objectName);
    const report = (sev, conf, reason, manualReview = true) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, description: `${this.description} (${reason})` })];

    if (method === 'setAsDefaultProtocolClient')
      return report(severity.MEDIUM, confidence.CERTAIN, 'the app registers itself as a deep link handler; every URL of this scheme reaches it');
    if (INTERCEPTIONS.includes(method))
      return report(severity.MEDIUM, confidence.CERTAIN, `${method} replaces the handling of a standard scheme`);
    if (!isHandle && !REGISTRATIONS.includes(method)) return null;

    const fn = astNode.arguments.length > 1 ? handlerFunction(astNode.arguments[1], scope) : undefined;
    if (!fn) return report(severity.LOW, confidence.FIRM, 'custom protocol registered; review what its handler serves');

    const servesFiles = callsIn(fn, (call, name) => FILE_SINKS.test(name || '') && call.arguments.some(a => dependsOnParams(a, fn) || /^file:/i.test(constantPrefix(a, scope) || ''))).length > 0 ||
      method === 'registerFileProtocol';
    if (!servesFiles) return report(severity.LOW, confidence.FIRM, 'custom protocol handler; review what it serves');

    const contained = callsIn(fn, (call, name) => CONTAINMENT.test(name || '')).length > 0 || mentionsDotDot(fn);
    if (!contained)
      return report(severity.HIGH, confidence.FIRM, 'the handler maps request URLs to files without keeping paths inside a directory (path traversal)', false);
    return report(severity.LOW, confidence.FIRM, 'the handler serves files and checks paths; review the containment check');
  }
}

function mentionsDotDot(fn) {
  let found = false;
  visit(fn.body, (n) => { if (typeof n.value === 'string' && n.value.includes('..')) found = true; return !found; });
  return found;
}
