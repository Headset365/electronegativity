// Breaking changes of Electron 12 and later (https://www.electronjs.org/docs/latest/breaking-changes), run with -u/--upgrade.
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, calleeObjectName, calleeMethodName, keyName, isProperty, literalValue, isWindowConstructor, webPreferencesOf, findProperty, finding } from '../helpers.js';

const isCall = (node) => node.type === 'CallExpression' || node.type === 'OptionalCallExpression';
const isMember = (node) => node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression';
const isRequireElectron = (node) => node && isCall(node) && node.callee.type === 'Identifier' && node.callee.name === 'require' && literalValue(node.arguments[0]) === 'electron';
const propertyNamed = (node, names) => isProperty(node) && !node.computed && names.includes(keyName(node.key));
const eventListener = (node, events) => isCall(node) && ['on', 'once', 'addListener'].includes(memberName(node.callee)) && events.includes(literalValue(node.arguments[0]));

const UPGRADE_CHECKS = [
  { version: 12, className: 'ContextIsolationDefaultChange', id: 'CONTEXT_ISOLATION_DEFAULT_CHANGE',
    description: 'contextIsolation defaults to true since Electron 12: preload scripts can no longer share globals with the page, use contextBridge',
    match: (node, scope) => isWindowConstructor(node) && !findProperty(webPreferencesOf(node, scope), 'contextIsolation') },

  { version: 14, className: 'RemoteModuleRemoval', id: 'REMOTE_MODULE_REMOVAL',
    description: "The remote module was removed in Electron 14, use @electron/remote or (better) IPC",
    match: (node) =>
      (isMember(node) && memberName(node) === 'remote' && ((node.object.type === 'Identifier' && node.object.name === 'electron') || isRequireElectron(node.object))) ||
      (node.type === 'VariableDeclarator' && isRequireElectron(node.init) && node.id.type === 'ObjectPattern' && node.id.properties.some(p => p.key && keyName(p.key) === 'remote')) ||
      propertyNamed(node, ['enableRemoteModule']) },

  { version: 14, className: 'AllowRendererProcessReuseRemoval', id: 'ALLOW_RENDERER_PROCESS_REUSE_REMOVAL',
    description: 'app.allowRendererProcessReuse was removed in Electron 14, renderer processes are always reused',
    match: (node) => isMember(node) && memberName(node) === 'allowRendererProcessReuse' },

  { version: 14, className: 'WorldSafeExecuteJavaScriptRemoval', id: 'WORLD_SAFE_EXECUTE_JAVASCRIPT_REMOVAL',
    description: 'The worldSafeExecuteJavaScript option was removed in Electron 14 and is always enabled',
    match: (node) => propertyNamed(node, ['worldSafeExecuteJavaScript']) },

  { version: 14, className: 'AffinityRemoval', id: 'AFFINITY_REMOVAL',
    description: 'The affinity option was removed in Electron 14',
    match: (node) => propertyNamed(node, ['affinity']) },

  { version: 18, className: 'NativeWindowOpenRemoval', id: 'NATIVE_WINDOW_OPEN_REMOVAL',
    description: 'The nativeWindowOpen option was removed in Electron 18, window.open always uses the native implementation',
    match: (node) => propertyNamed(node, ['nativeWindowOpen']) },

  { version: 20, className: 'SandboxDefaultChange', id: 'SANDBOX_DEFAULT_CHANGE',
    description: 'Renderers are sandboxed by default since Electron 20: preload scripts can only require a limited set of modules',
    match: (node, scope) => {
      if (!isWindowConstructor(node)) return false;
      const prefs = webPreferencesOf(node, scope);
      const nodeIntegration = findProperty(prefs, 'nodeIntegration');
      return !findProperty(prefs, 'sandbox') && !(nodeIntegration && literalValue(nodeIntegration[1]) === true);
    } },

  { version: 22, className: 'NewWindowEventRemoval', id: 'NEW_WINDOW_EVENT_REMOVAL',
    description: "The webContents 'new-window' event was removed in Electron 22, use webContents.setWindowOpenHandler",
    match: (node) => eventListener(node, ['new-window']) },

  { version: 23, className: 'ScrollTouchEventsRemoval', id: 'SCROLL_TOUCH_EVENTS_REMOVAL',
    description: "The BrowserWindow 'scroll-touch-*' events were removed in Electron 23, listen to 'input-event' on webContents",
    match: (node) => eventListener(node, ['scroll-touch-begin', 'scroll-touch-end', 'scroll-touch-edge']) },

  { version: 25, className: 'ProtocolRegisterDeprecation', id: 'PROTOCOL_REGISTER_DEPRECATION',
    description: 'protocol.register*Protocol and protocol.intercept*Protocol are deprecated since Electron 25, use protocol.handle',
    match: (node) => isCall(node) && /^(register|intercept)(File|Http|String|Buffer|Stream)Protocol$/.test(memberName(node.callee) || '') },

  { version: 28, className: 'IpcRendererSendToRemoval', id: 'IPC_RENDERER_SEND_TO_REMOVAL',
    description: 'ipcRenderer.sendTo was removed in Electron 28, use MessageChannel between renderers',
    match: (node) => isCall(node) && memberName(node.callee) === 'sendTo' && calleeObjectName(node.callee) === 'ipcRenderer' },

  { version: 29, className: 'IpcRendererContextBridgeRemoval', id: 'IPC_RENDERER_CONTEXT_BRIDGE_REMOVAL',
    description: 'ipcRenderer can no longer be sent over contextBridge since Electron 29, expose wrapper functions instead',
    match: (node) => isCall(node) && calleeMethodName(node) === 'exposeInMainWorld' && node.arguments[1] &&
      ((node.arguments[1].type === 'Identifier' && node.arguments[1].name === 'ipcRenderer') ||
       (node.arguments[1].type === 'ObjectExpression' && node.arguments[1].properties.some(p => isProperty(p) && p.value && p.value.type === 'Identifier' && p.value.name === 'ipcRenderer'))) },

  { version: 30, className: 'BrowserViewDeprecation', id: 'BROWSER_VIEW_DEPRECATION',
    description: 'BrowserView is deprecated since Electron 30, use WebContentsView',
    match: (node) => node.type === 'NewExpression' && (node.callee.name === 'BrowserView' || memberName(node.callee) === 'BrowserView') },

  { version: 32, className: 'FilePathRemoval', id: 'FILE_PATH_REMOVAL',
    description: 'The non-standard File.path property was removed in Electron 32, use webUtils.getPathForFile(file)',
    match: (node) => isMember(node) && memberName(node) === 'path' &&
      ((node.object.type === 'Identifier' && /file$/i.test(node.object.name)) ||
       (isMember(node.object) && isMember(node.object.object || {}) && memberName(node.object.object) === 'files')) },
];

function makeCheck({ className, id, description, match }) {
  const cls = class {
    constructor() {
      this.id = id;
      this.description = description;
      this.type = sourceTypes.JAVASCRIPT;
      this.shortenedURL = 'https://www.electronjs.org/docs/latest/breaking-changes';
    }

    match(astNode, astHelper, scope) {
      if (!match(astNode, scope)) return null;
      return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: true })];
    }
  };
  Object.defineProperty(cls, 'name', { value: className });
  return cls;
}

// { 14: [RemoteModuleRemoval, ...], ... }
export const MODERN_UPGRADE_CHECKS = UPGRADE_CHECKS.reduce((byVersion, spec) => {
  (byVersion[spec.version] ||= []).push(makeCheck(spec));
  return byVersion;
}, {});
