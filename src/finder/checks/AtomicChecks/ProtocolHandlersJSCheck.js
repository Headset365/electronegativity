import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

export default class ProtocolHandlerJSCheck {
  constructor() {
    this.id = "PROTOCOL_HANDLER_JS_CHECK";
    this.description = __("PROTOCOL_HANDLER_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/JeuMz";
  }

  match(astNode){
    const methods = [
      'setAsDefaultProtocolClient',
      'registerStandardSchemes',
      'registerServiceWorkerSchemes',
      'registerFileProtocol',
      'registerHttpProtocol',
      'registerStringProtocol',
      'registerBufferProtocol',
      'registerStreamProtocol',
      'interceptFileProtocol',
      'interceptHttpProtocol',
      'interceptStringProtocol',
      'interceptBufferProtocol',
      'interceptStreamProtocol'];

    if (astNode.type !== 'CallExpression') return null;
    // protocol.handle() (Electron 25+), only on the protocol module since `handle` is a common method name (e.g. ipcMain.handle)
    const isProtocolHandle = astNode.callee.property && astNode.callee.property.name === 'handle' &&
      astNode.callee.object && /protocol$/i.test(astNode.callee.object.name || (astNode.callee.object.property && astNode.callee.object.property.name) || '');
    if (!isProtocolHandle && !methods.includes(astNode.callee.name) && !(astNode.callee.property && methods.includes(astNode.callee.property.name))) return null;

    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true }];
  }
}
