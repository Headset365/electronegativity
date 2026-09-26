import { gte, coerce } from 'semver';
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, isProperty, isWindowConstructor, webPreferencesOf, findProperty, resolveIdentifier, finding } from '../helpers.js';
import { constantValue, isCall, resolveLocal } from '../analysis.js';

const SETTINGS = ['nodeIntegration', 'contextIsolation', 'sandbox', 'webSecurity', 'nodeIntegrationInSubFrames', 'webviewTag', 'allowRunningInsecureContent'];

/**
 * Inventory of the windows the app creates and their effective security settings (explicit values, or the defaults
 * of the Electron version in use), for the "Renderer attack surface" section of the report.
 */
export class WindowSummaryJSCheck {
  constructor() {
    this.id = "WINDOW_SUMMARY_JS_CHECK";
    this.description = __("WINDOW_SUMMARY_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/structures/web-preferences";
  }

  match(astNode, astHelper, scope, defaults, electronVersion) {
    if (!isWindowConstructor(astNode)) return null;
    // options passed from elsewhere (a parameter, a computed value) can't be read
    const options = astNode.arguments.length > 0 ? scope.resolveVarValue(astNode) : undefined;
    const optionsKnown = !options || options.type === 'ObjectExpression';
    const prefs = webPreferencesOf(astNode, scope);
    const unknownOptions = !optionsKnown || (!!findProperty(options, 'webPreferences') && (!prefs || prefs.type !== 'ObjectExpression'));
    const settings = {};
    for (const name of SETTINGS) {
      const property = findProperty(prefs, name);
      if (property) {
        const value = constantValue(property[1], scope);
        settings[name] = value === undefined ? { value: 'dynamic', source: 'explicit' } : { value: !!value, source: 'explicit' };
      } else if (unknownOptions) {
        settings[name] = { value: 'unknown', source: 'default' };
      } else {
        settings[name] = { value: defaults[name] ?? false, source: 'default' };
      }
    }
    // renderers without nodeIntegration are sandboxed by default since Electron 20
    if (settings.sandbox.source === 'default' && settings.sandbox.value !== 'unknown')
      settings.sandbox.value = gte(coerce(electronVersion) || '0.1.0', '20.0.0') && settings.nodeIntegration.value !== true;
    const preloadProperty = findProperty(prefs, 'preload');
    const preload = preloadProperty ? (constantValue(preloadProperty[1], scope) ?? preloadFileName(preloadProperty[1], scope) ?? 'dynamic path') : undefined;

    const kind = astNode.callee.type === 'Identifier' ? astNode.callee.name : memberName(astNode.callee);
    const describe = (name) => {
      const { value, source } = settings[name];
      const text = value === true ? 'on' : value === false ? 'off' : value;
      return `${name} ${text}${source === 'default' && value !== 'unknown' ? ' (default)' : ''}`;
    };
    const summary = ['nodeIntegration', 'contextIsolation', 'sandbox', 'webSecurity'].map(describe).join(', ') + (preload ? `, preload ${preload}` : '');
    return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN,
      description: `${this.description}: ${kind} (${summary})`, properties: { window: kind, settings, preload } })];
  }
}

// The file name of a preload built at runtime: path.join(__dirname, 'preload.js'), path.resolve(dir, 'dist/preload.js'),
// `${__dirname}/preload.js`, __dirname + '/preload.js'. The directory depends on where the app is installed, the file
// name doesn't, and is what links a window in the code to the same window observed at runtime.
function preloadFileName(node, scope, depth = 0) {
  if (!node || depth > 3) return undefined;
  const base = (value) => typeof value === 'string' && /\.[cm]?js$/i.test(value) ? value.split(/[\\/]/).pop() : undefined;
  if (node.type === 'Identifier') {
    const resolved = resolveLocal(node, scope);
    return resolved !== node ? (base(constantValue(resolved, scope)) ?? preloadFileName(resolved, scope, depth + 1)) : undefined;
  }
  if (isCall(node) && ['join', 'resolve'].includes(memberName(node.callee)) && node.arguments.length > 0)
    return base(constantValue(node.arguments[node.arguments.length - 1], scope));
  if (node.type === 'TemplateLiteral') return base(node.quasis[node.quasis.length - 1].value.cooked);
  if (node.type === 'BinaryExpression' && node.operator === '+') return base(constantValue(node.right, scope));
  return undefined;
}

// Names of the members of an exposed object: { openFile: ..., settings: { get, set } } -> ['openFile', 'settings.get', 'settings.set']
function memberNames(node, scope, prefix = '', depth = 0) {
  node = resolveIdentifier(node, scope);
  if (!node || node.type !== 'ObjectExpression' || depth > 2) return [];
  const names = [];
  for (const property of node.properties) {
    if (!isProperty(property)) continue;
    const name = keyName(property.key);
    if (!name) continue;
    const value = resolveIdentifier(property.value, scope);
    if (value && value.type === 'ObjectExpression') names.push(...memberNames(value, scope, `${prefix}${name}.`, depth + 1));
    else names.push(`${prefix}${name}`);
  }
  return names;
}

// What preload scripts expose to web content: contextBridge.exposeInMainWorld('api', { ... })
export class ExposedApiJSCheck {
  constructor() {
    this.id = "EXPOSED_API_JS_CHECK";
    this.description = __("EXPOSED_API_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#20-do-not-expose-electron-apis-to-untrusted-web-content";
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || astNode.type === 'NewExpression') return null;
    const method = memberName(astNode.callee);
    if (method !== 'exposeInMainWorld' && method !== 'exposeInIsolatedWorld') return null;
    const offset = method === 'exposeInIsolatedWorld' ? 1 : 0;
    const key = constantValue(astNode.arguments[offset], scope);
    const api = astNode.arguments[offset + 1];
    if (typeof key !== 'string' || !api) return null;
    const members = memberNames(api, scope);
    const shown = members.length > 0 ? members.join(', ') : (resolveIdentifier(api, scope).type === 'ObjectExpression' ? '(empty)' : 'value that can\'t be listed statically');
    return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: members.length > 0 ? confidence.CERTAIN : confidence.FIRM,
      description: `${this.description}: window.${key} (${shown})`, properties: { world: key, members } })];
  }
}
