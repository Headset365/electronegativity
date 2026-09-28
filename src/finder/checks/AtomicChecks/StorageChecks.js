// How the app stores secrets: files written in plaintext, electron-store without (or with a hard-coded) encryptionKey,
// cookies set in code without their security flags, and an inventory of every place the code reads, writes or deletes a
// credential, with how it is protected (the "Saved credentials" table of the HTML report).
import { createRequire } from 'node:module';
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding, keyName, objectProperties, literalValue, resolveIdentifier } from '../helpers.js';
import { constantValue, isCall, visit, programOf } from '../analysis.js';

const require = createRequire(import.meta.url);
const { isSensitiveParam, findSecrets } = require('../../../traffic/secrets.cjs');

const FS_WRITE = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'outputFile', 'outputFileSync', 'writeJson', 'writeJSON', 'writeJsonSync', 'outputJson', 'outputJsonSync']);
const FS_READ = new Set(['readFile', 'readFileSync', 'createReadStream', 'readJson', 'readJSON', 'readJsonSync']);
const CREDENTIAL_FILE = /credential|password|secret|token|\.env\b|apikey|api[_-]?key|\.pem$|\.key$|id[_-]?rsa|keystore|\.pfx$|\.p12$/i;
const CREDENTIAL_WORDS = /remember|login|creds?\b|credential|passw|pwd|secret|token|auth(?!or)/i;
const ENCRYPTED = /encrypt|decrypt|safeStorage|cipher|keytar/i;
const CONFIG_RECEIVER = /(store|config|conf|settings|prefs|preferences|storage|keychain|vault|db)$/i;
const WEB_STORAGE_OPS = { getItem: 'read', setItem: 'write', removeItem: 'delete' };
const CONFIG_STORE_OPS = { get: 'read', set: 'write', delete: 'delete', has: 'read' };
// OS-protected credential APIs: receiver.method -> [operation, store]
const OS_APIS = {
  'safeStorage.encryptString': ['write', 'Electron safeStorage (DPAPI / Keychain / libsecret encrypted)'],
  'safeStorage.decryptString': ['read', 'Electron safeStorage (DPAPI / Keychain / libsecret encrypted)'],
  'keytar.setPassword': ['write', 'OS credential store via keytar'],
  'keytar.getPassword': ['read', 'OS credential store via keytar'],
  'keytar.findPassword': ['read', 'OS credential store via keytar'],
  'keytar.findCredentials': ['read', 'OS credential store via keytar'],
  'keytar.deletePassword': ['delete', 'OS credential store via keytar'],
  'dpapi.protectData': ['write', 'Windows DPAPI'],
  'dpapi.unprotectData': ['read', 'Windows DPAPI'],
};

const credentialKey = (key) => typeof key === 'string' && key !== '' && (isSensitiveParam(key) || CREDENTIAL_WORDS.test(key));
const objectNameOf = (node) => !node ? '' : node.type === 'Identifier' ? node.name : node.type === 'ThisExpression' ? 'this' : (memberName(node) || '');

// the text of a node, for the "does it go through encryption" test
function mentions(node, pattern) {
  let found = false;
  visit(node, (n) => {
    if (found) return false;
    if ((n.type === 'Identifier' && pattern.test(n.name)) || (isCall(n) && pattern.test(memberName(n.callee) || (n.callee.type === 'Identifier' ? n.callee.name : '')))) found = true;
    return !found;
  });
  return found;
}

/** A secret named or embedded in an expression: the name ('token', 'password') or the kind of an embedded key, or undefined. */
export function secretReference(node) {
  let found;
  visit(node, (n) => {
    if (found) return false;
    if ((n.type === 'Property' || n.type === 'ObjectProperty') && isSensitiveParam(keyName(n.key) || '')) found = keyName(n.key);
    else if (n.type === 'Identifier' && isSensitiveParam(n.name)) found = n.name;
    else if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && !n.computed && isSensitiveParam(memberName(n) || '')) found = memberName(n);
    else {
      const value = literalValue(n);
      if (typeof value === 'string' && value.length >= 12) {
        const hit = findSecrets(value).find(h => !h.kind.startsWith('Hard-coded'));
        if (hit) found = hit.kind;
      }
    }
    return !found;
  });
  return found;
}

/** fs.writeFile(...) and friends writing a secret, or to a credentials-looking path, without visible encryption. */
export class SecretFileWriteJSCheck {
  constructor() {
    this.id = 'SECRET_FILE_WRITE_JS_CHECK';
    this.description = __('SECRET_FILE_WRITE_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/safe-storage';
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || astNode.arguments.length < 2) return null;
    const method = memberName(astNode.callee) || (astNode.callee.type === 'Identifier' ? astNode.callee.name : undefined);
    if (!FS_WRITE.has(method)) return null;
    const [target, data] = astNode.arguments;
    if (mentions(astNode, ENCRYPTED)) return null;
    const secret = secretReference(data);
    const file = constantValue(target, scope);
    const credentialPath = typeof file === 'string' && CREDENTIAL_FILE.test(file);
    if (!secret && !credentialPath) return null;
    const what = secret ? `a secret (${secret})` : 'data';
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: secret ? confidence.FIRM : confidence.TENTATIVE, manualReview: true,
      description: `${this.description}: ${method}() writes ${what}${credentialPath ? ` to a credentials-looking path (${file})` : ''} without visible encryption; use safeStorage.encryptString() first`,
      properties: { method, secret, path: typeof file === 'string' ? file : undefined } })];
  }
}

// how electron-store (or conf) is imported in a program: the local names of its constructor
const storeBindings = new WeakMap();
function electronStoreNames(program) {
  if (!program) return new Set();
  if (storeBindings.has(program)) return storeBindings.get(program);
  const names = new Set();
  visit(program, (n) => {
    if (n.type === 'ImportDeclaration' && /^(electron-store|conf)$/.test(n.source.value)) {
      for (const s of n.specifiers) if (s.type === 'ImportDefaultSpecifier' || (s.type === 'ImportSpecifier' && keyName(s.imported) === 'default')) names.add(s.local.name);
    } else if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init) {
      // const Store = require('electron-store') / require('electron-store').default
      let init = n.init;
      if ((init.type === 'MemberExpression') && memberName(init) === 'default') init = init.object;
      if (isCall(init) && init.callee.type === 'Identifier' && init.callee.name === 'require' && /^(electron-store|conf)$/.test(literalValue(init.arguments[0]) || '')) names.add(n.id.name);
    }
  });
  storeBindings.set(program, names);
  return names;
}

/** new Store() from electron-store: plaintext JSON without an encryptionKey; a hard-coded key ships with the app. */
export class ElectronStoreEncryptionJSCheck {
  constructor() {
    this.id = 'ELECTRON_STORE_ENCRYPTION_JS_CHECK';
    this.description = __('ELECTRON_STORE_ENCRYPTION_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://github.com/sindresorhus/electron-store#encryptionkey';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'NewExpression' || astNode.callee.type !== 'Identifier') return null;
    if (!electronStoreNames(programOf(context.ancestors)).has(astNode.callee.name)) return null;
    const options = astNode.arguments[0] ? resolveIdentifier(astNode.arguments[0], scope) : undefined;
    if (options && options.type !== 'ObjectExpression') return null; // options built elsewhere: can't tell
    // the variable the store is kept in, to link the credentials read and written through it
    const parent = context.ancestors[context.ancestors.length - 1];
    const variable = parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier' ? parent.id.name
      : parent && parent.type === 'AssignmentExpression' ? (parent.left.type === 'Identifier' ? parent.left.name : memberName(parent.left)) : undefined;
    const key = objectProperties(options).find(([name]) => name === 'encryptionKey');
    if (!key) return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true, properties: { issue: 'no-encryption', variable },
      description: `${this.description}: no encryptionKey, so the store is plaintext JSON in the profile folder; keep secrets in safeStorage instead` })];
    if (typeof constantValue(key[1], scope) === 'string') return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.CERTAIN, properties: { issue: 'hardcoded-key', variable },
      description: `${this.description}: the encryptionKey is a constant shipped with the app, so it only obfuscates the file; keep secrets in safeStorage instead` })];
    return null;
  }
}

/** session.cookies.set({...}) without secure / httpOnly, for an http:// URL, or with SameSite=None. */
export class CookieFlagsJSCheck {
  constructor() {
    this.id = 'COOKIE_FLAGS_JS_CHECK';
    this.description = __('COOKIE_FLAGS_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/cookies#cookiessetdetails';
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || memberName(astNode.callee) !== 'set' || memberName(astNode.callee.object) !== 'cookies' || !astNode.arguments[0]) return null;
    const details = resolveIdentifier(astNode.arguments[0], scope);
    if (!details || details.type !== 'ObjectExpression') return null;
    const props = Object.fromEntries(objectProperties(details).map(([name, value]) => [name, value]));
    const value = (name) => props[name] ? constantValue(props[name], scope) : undefined;
    const missing = ['secure', 'httpOnly'].filter(flag => value(flag) !== true);
    const url = value('url');
    const cleartext = typeof url === 'string' && /^http:/i.test(url);
    const sameSite = value('sameSite');
    const lax = sameSite === 'no_restriction';
    const longLived = !!props.expirationDate;
    const name = value('name');
    if (missing.length === 0 && !cleartext && !lax) return null;
    const problems = [missing.length ? `without ${missing.join(' and ')}` : '', cleartext ? 'for an http:// URL' : '', lax ? 'with SameSite=None' : '', longLived ? 'kept past the session' : ''].filter(Boolean);
    const sensitive = typeof name === 'string' && (isSensitiveParam(name) || /session|auth/i.test(name));
    return [finding(this, astNode, { severity: sensitive || cleartext ? severity.MEDIUM : severity.LOW, confidence: confidence.FIRM, manualReview: !sensitive,
      description: `${this.description}: cookie '${typeof name === 'string' ? name : '?'}' is set ${problems.join(', ')}`, properties: { name, missing, cleartext, sameSite, longLived } })];
  }
}

/**
 * Every place the code reads, writes or deletes a credential and how it is protected: the OS credential store
 * (safeStorage, keytar, DPAPI), web storage (plaintext), config stores such as electron-store (protection depends on its
 * encryptionKey) and credential files. Informational: listed in the "Saved credentials" table.
 */
export class CredentialAccessJSCheck {
  constructor() {
    this.id = 'CREDENTIAL_ACCESS_JS_CHECK';
    this.description = __('CREDENTIAL_ACCESS_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/safe-storage';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    const row = isCall(astNode) ? this.callRow(astNode, scope) : this.memberRow(astNode, context.ancestors);
    if (!row) return null;
    return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, properties: row,
      description: `${this.description}: ${row.op} ${row.key ? `'${row.key}' ` : ''}via ${row.api}, ${row.store} (${row.protected === true ? 'protected' : row.protected === false ? 'not protected' : 'check'})` })];
  }

  callRow(call, scope) {
    const method = memberName(call.callee);
    if (!method) return undefined;
    const receiver = objectNameOf(call.callee.object);
    const api = `${receiver}.${method}`;
    const key = call.arguments[0] ? constantValue(call.arguments[0], scope) : undefined;
    const keyText = typeof key === 'string' ? key : undefined;
    if (OS_APIS[api]) return { op: OS_APIS[api][0], store: OS_APIS[api][1], protected: true, api, key: receiver === 'keytar' ? keyText : undefined };
    if (/^(localStorage|sessionStorage)$/.test(receiver) && WEB_STORAGE_OPS[method] && credentialKey(keyText))
      return { op: WEB_STORAGE_OPS[method], store: receiver === 'localStorage' ? 'localStorage (plaintext on disk)' : 'sessionStorage (plaintext in memory)', protected: false, api, key: keyText };
    if (CONFIG_STORE_OPS[method] && CONFIG_RECEIVER.test(receiver) && !/^(localStorage|sessionStorage)$/.test(receiver) && credentialKey(keyText))
      return { op: CONFIG_STORE_OPS[method], store: `config store '${receiver}' (electron-store or similar)`, protected: null, api, key: keyText, configStore: true };
    if ((FS_WRITE.has(method) || FS_READ.has(method)) && call.arguments[0]) {
      const file = constantValue(call.arguments[0], scope);
      const text = typeof file === 'string' ? file : '';
      if (!text || !(CREDENTIAL_FILE.test(text) || CREDENTIAL_WORDS.test(text))) return undefined;
      const write = FS_WRITE.has(method);
      const encrypted = mentions(call, ENCRYPTED);
      // a read alone doesn't show whether the file's contents are protected
      return { op: write ? 'write' : 'read', store: `file ${text.slice(0, 120)}`, protected: encrypted ? true : write ? false : null, api };
    }
    return undefined;
  }

  // localStorage.password as a property: read, written or deleted
  memberRow(node, ancestors) {
    if ((node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') || node.computed) return undefined;
    const receiver = objectNameOf(node.object);
    const key = memberName(node);
    if (!/^(localStorage|sessionStorage)$/.test(receiver) || WEB_STORAGE_OPS[key] || ['length', 'key', 'clear'].includes(key) || !credentialKey(key)) return undefined;
    const parent = ancestors[ancestors.length - 1];
    if (parent && isCall(parent) && parent.callee === node) return undefined;
    const op = parent && parent.type === 'AssignmentExpression' && parent.left === node ? 'write'
      : parent && parent.type === 'UnaryExpression' && parent.operator === 'delete' ? 'delete' : 'read';
    return { op, store: receiver === 'localStorage' ? 'localStorage (plaintext on disk)' : 'sessionStorage (plaintext in memory)', protected: false, api: `${receiver}.${key}`, key };
  }
}

/** Config-store rows are protected only if the store is encrypted: mark them from the electron-store findings of the same file. */
export function linkCredentialStores(issues) {
  const byFile = new Map();
  for (const issue of issues.filter(i => i.id === 'ELECTRON_STORE_ENCRYPTION_JS_CHECK' && i.properties)) byFile.set(issue.file, [...(byFile.get(issue.file) || []), issue.properties]);
  for (const issue of issues.filter(i => i.id === 'CREDENTIAL_ACCESS_JS_CHECK' && i.properties && i.properties.configStore)) {
    const stores = byFile.get(issue.file) || [];
    // the store kept in the variable the call goes through; a file with a single store: that one
    const receiver = String(issue.properties.api || '').split('.')[0];
    const match = stores.find(s => s.variable === receiver) || (stores.length === 1 ? stores[0] : undefined);
    const store = match && match.issue;
    if (store === 'hardcoded-key') issue.properties = { ...issue.properties, protected: false, store: `${issue.properties.store}, hard-coded encryptionKey` };
    else if (store === 'no-encryption') issue.properties = { ...issue.properties, protected: false, store: `${issue.properties.store}, no encryptionKey: plaintext JSON` };
  }
  return issues;
}
