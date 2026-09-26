import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { constantValue, isCall, visit } from '../analysis.js';

const SECRET = /(pass(word|wd)?|secret|token|api[_-]?key|credential|private[_-]?key|session[_-]?key|auth)/i;
const ENCRYPTED = /(encrypt|safeStorage|cipher|keytar|setPassword|hash)/i;

// Secrets written to storage other apps and malware can read; Electron's safeStorage encrypts with the OS keychain
export default class PlaintextSecretsJSCheck {
  constructor() {
    this.id = "PLAINTEXT_SECRETS_JS_CHECK";
    this.description = __("PLAINTEXT_SECRETS_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/safe-storage";
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || astNode.arguments.length < 2) return null;
    const method = memberName(astNode.callee);
    const object = astNode.callee.object;
    const objectName = object && (object.type === 'Identifier' ? object.name : memberName(object)) || '';
    // electron-store / conf: store.set('token', value); localStorage / sessionStorage.setItem('token', value)
    const isStore = method === 'set' && /(store|config|settings|prefs|preferences|conf)$/i.test(objectName);
    const isWebStorage = method === 'setItem' && /^(localStorage|sessionStorage)$/.test(objectName);
    if (!isStore && !isWebStorage) return null;

    const key = constantValue(astNode.arguments[0], scope);
    if (typeof key !== 'string' || !SECRET.test(key)) return null;
    if (mentions(astNode.arguments[1], ENCRYPTED)) return null;
    return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} ("${key}" is stored in plaintext; use safeStorage.encryptString())`, properties: { key } })];
  }
}

function mentions(node, pattern) {
  let found = false;
  visit(node, (n) => {
    if ((n.type === 'Identifier' && pattern.test(n.name)) || (isCall(n) && pattern.test(memberName(n.callee) || ''))) found = true;
    return !found;
  });
  return found;
}
