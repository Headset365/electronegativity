import { gte, coerce } from 'semver';
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, isFunction, isProperty, resolveIdentifier, visit, finding } from '../helpers.js';
import { isConditional, identifiersIn } from '../analysis.js';

// is `name` tested by a condition of the function, e.g. `if (!CHANNELS.includes(channel)) return;`
function mentions(fn, name) {
  let found = false;
  visit(fn.body, (n) => {
    if (found) return false;
    if ((n.type === 'IfStatement' || n.type === 'ConditionalExpression') && identifiersIn(n.test).has(name)) found = true;
    return true;
  });
  return found;
}

// is `name` passed to a validation helper before use, e.g. `validateIPC(channel); return ipcRenderer.invoke(channel)`
const VALIDATOR = /(valid|check|assert|allow|verif|ensure|guard|permit)/i;
function validatedByCall(fn, name, sink) {
  let found = false;
  visit(fn.body, (n) => {
    if (found || n === sink) return false;
    if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && n.callee.type === 'Identifier' && VALIDATOR.test(n.callee.name) &&
        n.arguments.some(a => a.type === 'Identifier' && a.name === name)) found = true;
    return true;
  });
  return found;
}

// Values that must never reach the renderer through contextBridge
const DANGEROUS_IDENTIFIERS = ['ipcRenderer', 'require', 'process', 'shell', 'fs', 'child_process', 'childProcess', 'remote', 'webFrame', 'Buffer', 'module', 'exec', 'execSync', 'spawn', 'spawnSync', 'eval'];
const IPC_SEND_METHODS = ['send', 'sendSync', 'invoke', 'postMessage', 'sendToHost', 'on', 'once', 'addListener'];
// plain data that is fine to hand to the page: process.platform, process.versions, ...
const HARMLESS_MEMBERS = { process: ['platform', 'arch', 'versions', 'version', 'type', 'contextIsolated', 'sandboxed', 'pid'] };

// Electron docs: "Do not expose Electron APIs to untrusted web content" (context isolation tutorial)
export default class ContextBridgeExposureJSCheck {
  constructor() {
    this.id = "CONTEXT_BRIDGE_EXPOSURE_JS_CHECK";
    this.description = __("CONTEXT_BRIDGE_EXPOSURE_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/context-isolation#security-considerations";
  }

  match(astNode, astHelper, scope, defaults, electronVersion) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    const method = memberName(astNode.callee);
    let apiArg;
    if (method === 'exposeInMainWorld') apiArg = astNode.arguments[1];
    else if (method === 'exposeInIsolatedWorld') apiArg = astNode.arguments[2];
    else return null;
    if (!apiArg) return null;

    const api = resolveIdentifier(apiArg, scope);
    const eventSenderStripped = electronVersion && gte(coerce(electronVersion) || '0.1.0', '29.0.0');
    const issues = [];
    const report = (node, sev, conf, reason) => issues.push(finding(this, node, {
      severity: sev, confidence: conf, manualReview: true,
      description: `${this.description} (${reason})`, properties: { reason }
    }));

    // exposeInMainWorld('x', ipcRenderer) / exposeInMainWorld('x', require)
    if (api.type === 'Identifier' && DANGEROUS_IDENTIFIERS.includes(api.name)) {
      report(apiArg, severity.HIGH, confidence.CERTAIN, `exposes ${api.name}`);
      return issues;
    }

    // Walk the exposed API, tracking the parameters of the wrapper functions it defines
    const paramScopes = [];
    const isParam = (name) => paramScopes.some(params => params.has(name));

    const walk = (node) => visit(node, (n, ancestors) => {
      // leave the parameter scope of functions we've exited
      while (paramScopes.length > 0 && !ancestors.includes(paramScopes[paramScopes.length - 1].owner)) paramScopes.pop();

      if (isFunction(n)) {
        const params = new Set();
        params.owner = n;
        for (const p of n.params || []) {
          const target = p.type === 'RestElement' ? p.argument : (p.type === 'AssignmentPattern' ? p.left : p);
          if (target && target.type === 'Identifier') params.add(target.name);
        }
        paramScopes.push(params);
        return true;
      }

      // { invoke: ipcRenderer.invoke } or { ipc: ipcRenderer } or { req: require }
      if (isProperty(n) && n.value) {
        const value = n.value;
        if (value.type === 'Identifier' && DANGEROUS_IDENTIFIERS.includes(value.name)) {
          report(n, severity.HIGH, confidence.CERTAIN, `exposes ${value.name}`);
          return false;
        }
        if ((value.type === 'MemberExpression' || value.type === 'OptionalMemberExpression') &&
            value.object.type === 'Identifier' && DANGEROUS_IDENTIFIERS.includes(value.object.name) &&
            !(HARMLESS_MEMBERS[value.object.name] || []).includes(memberName(value))) {
          report(n, severity.HIGH, confidence.FIRM, `exposes ${value.object.name}.${memberName(value)} without a wrapper`);
          return false;
        }
      }

      if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
        const calleeMethod = memberName(n.callee);
        const calleeObject = n.callee.object && n.callee.object.type === 'Identifier' ? n.callee.object.name : undefined;
        const first = n.arguments[0];

        // (channel, ...args) => ipcRenderer.invoke(channel, ...args): the renderer picks any channel
        if (calleeObject === 'ipcRenderer' && IPC_SEND_METHODS.includes(calleeMethod) &&
            first && first.type === 'Identifier' && isParam(first.name)) {
          const wrapper = [...ancestors].reverse().find(isFunction);
          if (wrapper && ((isConditional(n, [...ancestors], wrapper) && mentions(wrapper, first.name)) || validatedByCall(wrapper, first.name, n)))
            report(n, severity.LOW, confidence.FIRM, `forwards a channel to ipcRenderer.${calleeMethod} after checking it; review the allowlist`);
          else
            report(n, severity.HIGH, confidence.FIRM, `forwards an arbitrary channel to ipcRenderer.${calleeMethod}`);
        }

        // ipcRenderer.on('x', callback): the callback receives the IpcRendererEvent, which exposes ipcRenderer itself
        // (until Electron 29, which stopped ipcRenderer from crossing contextBridge)
        const listener = n.arguments[1];
        if (calleeObject === 'ipcRenderer' && ['on', 'once', 'addListener'].includes(calleeMethod) &&
            listener && listener.type === 'Identifier' && isParam(listener.name)) {
          if (eventSenderStripped) report(n, severity.LOW, confidence.FIRM, 'passes the IPC event object to renderer callbacks; Electron 29+ no longer sends ipcRenderer (event.sender) over contextBridge, but pass only the arguments');
          else report(n, severity.MEDIUM, confidence.FIRM, 'passes the IPC event object to renderer callbacks');
        }

        // () => require(name), (cmd) => exec(cmd)
        const calleeName = n.callee.type === 'Identifier' ? n.callee.name : undefined;
        if (['require', 'exec', 'execSync', 'spawn', 'spawnSync', 'eval'].includes(calleeName) &&
            first && first.type === 'Identifier' && isParam(first.name)) {
          report(n, severity.HIGH, confidence.FIRM, `lets the renderer control ${calleeName}()`);
        }
        if (calleeObject === 'shell' && ['openExternal', 'openPath'].includes(calleeMethod) &&
            first && first.type === 'Identifier' && isParam(first.name)) {
          report(n, severity.HIGH, confidence.FIRM, `lets the renderer control shell.${calleeMethod}()`);
        }
      }
      return true;
    });

    walk(api);
    return issues;
  }
}
