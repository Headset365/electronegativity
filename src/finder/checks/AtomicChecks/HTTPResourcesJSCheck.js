import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';

const CLEARTEXT_APIS = new Set(['loadURL', 'setSpellCheckerDictionaryDownloadURL', 'downloadURL', 'request']);

export default class HTTPResourcesJavascriptCheck {
  constructor() {
    this.id = "HTTP_RESOURCES_JS_CHECK";
    this.description = __("HTTP_RESOURCES_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#1-only-load-secure-content";
  }

  match(astNode, astHelper){
    if (astNode.type !== 'CallExpression') return null;
    const method = astNode.callee.property && astNode.callee.property.name;
    // Electron APIs that fetch what they are given: pages, and files the app or Chromium then uses (spell-check
    // dictionaries, downloads)
    if (!CLEARTEXT_APIS.has(method) || !astNode.arguments[0]) return null;
    if (method === 'request' && !/^net$/.test((astNode.callee.object && (astNode.callee.object.name || (astNode.callee.object.property && astNode.callee.object.property.name))) || '')) return null;

    switch (astNode.arguments[0].type) {
      case astHelper.StringLiteral:
        if (!astNode.arguments[0].value.trim().toUpperCase().startsWith("HTTP://"))
          return undefined;
        break;
      case "TemplateLiteral":
        if (astNode.arguments[0].type !== "TemplateLiteral" ||
            astNode.arguments[0].quasis[0].type !== "TemplateElement" ||
            !astNode.arguments[0].quasis[0].value.cooked.trim().toUpperCase().startsWith("HTTP://"))
          return undefined;
        break;
      default:
        return undefined;
    }

    const url = astNode.arguments[0].type === "TemplateLiteral" ? astNode.arguments[0].quasis[0].value.cooked.trim() : astNode.arguments[0].value.trim();
    // the app's own local server: the traffic stays on the computer, though another program could take the port first
    const loopback = /^http:\/\/(?:127(?:\.\d{1,3}){3}|localhost|\[::1\])(?::\d+)?(?:[/?#]|$)/i.test(url);
    const what = loopback ? ` (${method}(): ${url} is the application's own local server; the traffic does not leave the computer)`
      : method === 'loadURL' ? '' : ` (${method}(): ${url} is fetched over unencrypted HTTP${method === 'setSpellCheckerDictionaryDownloadURL' ? ', so someone on the network can replace the dictionaries Chromium loads' : ''})`;
    return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: `${this.description}${what}`, shortenedURL: this.shortenedURL, severity: loopback ? severity.LOW : severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: false, properties: { api: method, url, ...(loopback ? { loopback: true } : {}) } }];
  }
}
