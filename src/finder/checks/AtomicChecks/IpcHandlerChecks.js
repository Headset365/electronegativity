// What IPC handlers do with the data a renderer sends them: files read, written or deleted at paths the page chose, the
// capabilities each handler uses and whether it checks its arguments, credentials handed back to the page, and which
// channels each preload (and so each window) can reach.
import path from 'node:path';
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding, literalValue, isFunction } from '../helpers.js';
import { constantValue, enclosingFunction, untrustedSource, dependsOnParams, taintedNames, moduleBindings, programOf, callsIn, returnedValues,
  handlerFunction, paramNames, identifiersIn, hasUrlValidation, visit, isCall, isMember } from '../analysis.js';
import { secretReference } from './StorageChecks.js';
import { ipcDefinition, ipcContext, ipcListener, ipcObject, operationPathControl } from '../ipc_context.js';

const FS_MODULE = /^(node:)?(fs|fs\/promises|original-fs|graceful-fs|fs-extra|fs-jetpack)$/;
const FS_OPS = {
  read: ['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync', 'readJson', 'readJSON', 'readJsonSync', 'opendir', 'opendirSync', 'open', 'openSync'],
  write: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'outputFile', 'outputFileSync', 'writeJson', 'writeJSON',
    'writeJsonSync', 'outputJson', 'outputJsonSync', 'mkdir', 'mkdirSync', 'symlink', 'symlinkSync', 'link', 'linkSync', 'chmod', 'chmodSync'],
  copy: ['copyFile', 'copyFileSync', 'cp', 'cpSync', 'copy', 'copySync', 'rename', 'renameSync', 'move', 'moveSync'],
  delete: ['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'remove', 'removeSync', 'emptyDir', 'emptyDirSync'],
};
const FS_OPERATION = new Map(Object.entries(FS_OPS).flatMap(([op, names]) => names.map(name => [name, op])));
// ways to keep a path inside a directory: path.relative, realpath or startsWith on the resolved path, basename, or a helper
// named for it (isInside, ensureWithin, isAllowedPath, validatePath, safeJoin). Not isAbsolute, which says nothing about the
// folder, nor any name that merely contains the word (invalidate, unsafeOpen).
export const CONTAINMENT = /^(startsWith|relative|realpath|realpathSync|basename)$|[a-z0-9](Inside|Within|Contain|Allowed|Safe|Valid)|^(inside|within|contain|allowed|safe|valid)|_(inside|within|contain|allowed|safe|valid)/;
// file-name sanitizers that also deal with Windows reserved names, streams and trailing dots
const NAME_SANITIZER = /sanitiz|filenamify|slugify|safe.?(file)?name|clean.?(file)?name|valid.?(file)?name/i;
const CHILD_PROCESS = /^(node:)?child_process$/;
const SHELL_METHODS = ['openExternal', 'openPath', 'showItemInFolder', 'trashItem', 'writeShortcutLink'];
const NETWORK = /^(fetch|request|get|post|put|patch|delete|head)$/;
const NETWORK_OBJECTS = /^(net|axios|got|superagent|https?|request|needle|undici|ky)$/;
const WINDOW_LOOKUPS = ['fromId', 'fromWebContents', 'fromBrowserView', 'fromFrame', 'getAllWindows', 'getFocusedWindow', 'getAllWebContents'];
const WINDOW_ACTIONS = ['loadURL', 'loadFile', 'executeJavaScript', 'close', 'destroy', 'setBounds', 'focus', 'show', 'hide', 'reload', 'send', 'openDevTools'];
const CREDENTIAL_READS = { decryptString: 'safeStorage', getPassword: 'keytar', findPassword: 'keytar', findCredentials: 'keytar', unprotectData: 'dpapi' };
const SENSITIVE_PARAM = /pass|pwd|secret|token|api.?key|auth|credential|session|cookie|private.?key/i;
const RENDERER_METHODS = ['invoke', 'send', 'sendSync', 'sendTo', 'sendToHost', 'on', 'once', 'addListener', 'postMessage'];

const calleeName = (callee) => callee.type === 'Identifier' ? callee.name : memberName(callee);

// The module a callee comes from: readFile (imported from fs), fs.readFile, fs.promises.readFile, require('fs').readFile
function moduleOf(callee, ancestors) {
  const program = programOf(ancestors);
  const bindings = program ? moduleBindings(program) : new Map();
  if (callee.type === 'Identifier') {
    const binding = bindings.get(callee.name);
    return binding && binding.imported !== '*' ? binding.module : undefined;
  }
  let object = callee.object;
  while (object && isMember(object) && memberName(object) === 'promises') object = object.object;
  if (object && object.type === 'Identifier') {
    const binding = bindings.get(object.name);
    if (binding) return binding.imported === '*' || binding.imported === 'promises' || binding.imported === 'default' ? binding.module : undefined;
    // a bare `fs` global (bundled code), common enough to count
    return /^(fs|fsp|fse|fsExtra|originalFs)$/.test(object.name) ? 'fs' : undefined;
  }
  if (object && isCall(object) && object.callee.type === 'Identifier' && object.callee.name === 'require') return literalValue(object.arguments[0]);
  return undefined;
}

export function fsOperation(call, ancestors) {
  const name = calleeName(call.callee);
  const op = FS_OPERATION.get(name);
  if (!op) return undefined;
  return FS_MODULE.test(moduleOf(call.callee, ancestors) || '') ? { name, op } : undefined;
}

// The names in `fn` that carry a path value: the untrusted names in the path expressions, what was assigned from them
// (`const resolved = path.resolve(base, file)`) and what they were assigned from, followed until nothing changes
function pathNames(fn, paths) {
  const tainted = taintedNames(fn);
  const related = new Set(paths.flatMap(p => [...identifiersIn(p)]).filter(name => tainted.has(name)));
  const assignments = [];
  visit(fn.body, (n) => {
    if (n.type === 'VariableDeclarator' && n.init && n.id.type === 'Identifier') assignments.push([n.id.name, n.init]);
    if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier') assignments.push([n.left.name, n.right]);
    return true;
  });
  for (let changed = true; changed;) {
    changed = false;
    for (const [name, init] of assignments) {
      const sources = [...identifiersIn(init)].filter(source => tainted.has(source));
      if (!related.has(name) && sources.some(source => related.has(source))) { related.add(name); changed = true; }
      if (related.has(name)) for (const source of sources) if (!related.has(source)) { related.add(source); changed = true; }
    }
  }
  return related;
}

// Does the function hold its path to a folder? path.basename is noted apart: it keeps the file in the folder but lets
// Windows reserved names (CON, NUL), alternate data streams (name:stream) and trailing dots or spaces through.
// With `paths` (the path expressions reaching the file system), only checks that operate on that path count: a sender
// check (validateSender(event)), a URL check or a log message saying "Reading..." does not keep a path in a folder.
function containment(fn, paths) {
  const related = paths ? pathNames(fn, paths) : undefined;
  const onPath = (call) => !related || [call.callee, ...call.arguments].some(node => [...identifiersIn(node)].some(name => related.has(name)));
  const calls = callsIn(fn, (call, name) => CONTAINMENT.test(name || '') && onPath(call)).map(({ call }) => calleeName(call.callee));
  let dotDot = false;
  const hasDotDot = (node) => {
    let found = false;
    visit(node, (n) => {
      // '..' as a path segment ('..', '../', '..\\'), not an ellipsis in a message
      if ((typeof n.value === 'string' && /(^|[\\/])\.\.([\\/]|$)/.test(n.value)) || (n.regex && /\\\.\\\.|\.\./.test(n.regex.pattern)) ||
        (n.type === 'RegExpLiteral' && /\\\.\\\.|\.\./.test(n.pattern))) found = true;
      return !found;
    });
    return found;
  };
  if (related) dotDot = callsIn(fn, (call) => onPath(call) && [call.callee, ...call.arguments].some(hasDotDot)).length > 0;
  else visit(fn.body, (n) => { if (typeof n.value === 'string' && n.value.includes('..')) dotDot = true; return !dotDot; });
  const sanitized = callsIn(fn, (call, name) => NAME_SANITIZER.test(name || '') ||
    (name === 'replace' && call.arguments[0] && call.arguments[0].type === 'RegExpLiteral' && /[:<>|?*]/.test(call.arguments[0].pattern))).length > 0 ||
    callsIn(fn, (call) => call.arguments.some(a => a.regex && /[:<>|?*]/.test(a.regex.pattern))).length > 0;
  return { any: calls.length > 0 || dotDot, basenameOnly: calls.length > 0 && calls.every(n => n === 'basename') && !dotDot, sanitized };
}

/** File system calls whose path comes from a renderer (IPC, contextBridge), a navigation or a deep link. */
export class IpcFileAccessJSCheck {
  constructor() {
    this.id = 'IPC_FILE_ACCESS_JS_CHECK';
    this.description = __('IPC_FILE_ACCESS_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://owasp.org/www-community/attacks/Path_Traversal';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (!isCall(astNode) || astNode.type === 'NewExpression' || astNode.arguments.length === 0) return null;
    const operation = fsOperation(astNode, context.ancestors);
    if (!operation) return null;
    const paths = operation.op === 'copy' ? astNode.arguments.slice(0, 2) : [astNode.arguments[0]];
    const fn = enclosingFunction(context.ancestors);
    if (!fn) return null;
    const tainted = paths.filter(p => p && constantValue(p, scope) === undefined && dependsOnParams(p, fn));
    if (tainted.length === 0) return null;
    const source = untrustedSource(context.ancestors, fn);
    if (!source) return null;
    const verb = { read: 'reads', write: 'writes', copy: 'copies or moves', delete: 'deletes' }[operation.op];
    const kept = operationPathControl(fn, astNode, context.ancestors, tainted);
    const properties = { source, operation: operation.op, call: operation.name, pathControl: kept.status };
    if (kept.status !== 'recognized-unverified')
      return [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false, properties,
        description: `${this.description} (${operation.name} ${verb} a path from ${source} with nothing keeping it inside a folder: ../ traversal, absolute paths and UNC paths such as \\\\host\\share reach the file system)` })];
    if (kept.basenameOnly && !containment(fn, tainted).sanitized && operation.op !== 'read')
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true, properties: { ...properties, hygiene: true },
        description: `${this.description} (${operation.name} ${verb} a file named by ${source}; path.basename keeps it in the folder, but Windows reserved names (CON, NUL), alternate data streams (name:stream), trailing dots or spaces and double extensions are not rejected)` })];
    return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true, properties,
      description: `${this.description} (${operation.name} ${verb} a path from ${source}; the handler checks paths, review the check)` })];
  }
}

// Is anything in the function checking the type or shape of its arguments?
function validatesArguments(fn) {
  let found = false;
  visit(fn.body, (n) => {
    if (found) return false;
    // An unused `typeof` expression does not protect the operation. Only count checks in a branch
    // that can reject an input; helper names by themselves are hints, not validation proof.
    if (n.type !== 'IfStatement') return;
    let checks = false;
    visit(n.test, test => {
      if (test.type === 'UnaryExpression' && test.operator === 'typeof') checks = true;
      else if (test.type === 'BinaryExpression' && test.operator === 'instanceof') checks = true;
      else if (isCall(test) && /^(isArray|isFinite|isInteger|valid\w*|assert\w*|check\w*|is[A-Z]\w*)$/i.test(calleeName(test.callee) || '')) checks = true;
    });
    let rejects = false;
    if (n.consequent) visit(n.consequent, child => { if (child.type === 'ReturnStatement' || child.type === 'ThrowStatement') rejects = true; });
    if (n.alternate) visit(n.alternate, child => { if (child.type === 'ReturnStatement' || child.type === 'ThrowStatement') rejects = true; });
    if (checks && rejects) found = true;
    return !found;
  });
  return found;
}

// A credential in an expression: a secret-named value, store.get('token'), safeStorage.decryptString(...), keytar.getPassword(...)
export function credentialIn(node) {
  const named = secretReference(node);
  if (named) return named;
  let found;
  visit(node, (n) => {
    if (found) return false;
    if (isCall(n)) {
      const name = calleeName(n.callee);
      if (CREDENTIAL_READS[name]) found = `${CREDENTIAL_READS[name]}.${name}()`;
      else if (/^(get|getItem|getSync)$/.test(name || '') && typeof literalValue(n.arguments[0]) === 'string' && SENSITIVE_PARAM.test(literalValue(n.arguments[0]))) found = literalValue(n.arguments[0]);
    }
    return !found;
  });
  return found;
}

// What a function can do: files, processes, shell, network, windows, credentials, and the IPC channels it uses
export function capabilities(fn, ancestors) {
  const found = new Set();
  const channels = new Set();
  let targetsWindow = false;
  const argNames = new Set(paramNames(fn).slice(1));
  callsIn(fn, () => true).forEach(({ call, ancestors: path }) => {
    const name = calleeName(call.callee) || '';
    const chain = [...ancestors, ...path.slice(1)];
    const module = moduleOf(call.callee, chain) || '';
    const object = call.callee.object && (call.callee.object.name || memberName(call.callee.object));
    if (FS_OPERATION.has(name) && FS_MODULE.test(module)) found.add('files');
    else if (CHILD_PROCESS.test(module)) found.add('processes');
    else if (SHELL_METHODS.includes(name)) found.add('shell');
    else if (object === 'ipcRenderer' && RENDERER_METHODS.includes(name)) {
      found.add('ipc');
      const channel = literalValue(call.arguments[0]);
      channels.add(typeof channel === 'string' ? channel : '*');
    } else if ((name === 'fetch' && call.callee.type === 'Identifier') || (NETWORK.test(name) && NETWORK_OBJECTS.test(object || ''))) found.add('network');
    else if (WINDOW_LOOKUPS.includes(name) || WINDOW_ACTIONS.includes(name) || (name === 'open' && object === 'window')) {
      found.add('windows');
      if (['fromId', 'fromWebContents', 'fromFrame', 'fromBrowserView'].includes(name) && call.arguments.some(a => [...identifiersIn(a)].some(id => argNames.has(id)))) targetsWindow = true;
    } else if (object === 'clipboard') found.add('clipboard');
    if (CREDENTIAL_READS[name]) found.add('credentials');
  });
  if ([...identifiersIn(fn.body)].includes('XMLHttpRequest')) found.add('network');
  return { list: [...found], targetsWindow, channels: [...channels] };
}

// The values a handler sends back: its return value, event.reply(ch, value), event.sender.send(ch, value), event.returnValue = value
function repliedValues(fn) {
  const values = returnedValues(fn).map(r => r.value);
  callsIn(fn, (call, name) => ['reply', 'send'].includes(name) && isMember(call.callee)).forEach(({ call }) => values.push(...call.arguments.slice(1)));
  visit(fn.body, (n) => {
    if (n.type === 'AssignmentExpression' && isMember(n.left) && memberName(n.left) === 'returnValue') values.push(n.right);
    return true;
  });
  return values;
}

/**
 * One entry per ipcMain handler: its channel, what it can do (files, processes, shell, network, windows, credentials) and
 * whether it checks the arguments the page sends. Raised when renderer-supplied arguments drive a sensitive capability
 * unchecked, when the page picks which window to act on, and when a credential is sent back to the page.
 */
export class IpcHandlerJSCheck {
  constructor() {
    this.id = 'IPC_HANDLER_JS_CHECK';
    this.description = __('IPC_HANDLER_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/tutorial/security#17-validate-the-sender-of-all-ipc-messages';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (!isCall(astNode) || astNode.type === 'NewExpression' || astNode.arguments.length < 2) return null;
    if (!ipcListener(astNode, scope)) return null;
    const channel = constantValue(astNode.arguments[0], scope);
    const handler = astNode.arguments[astNode.arguments.length - 1];
    const definition = ipcDefinition(handler, scope, context.ancestors);
    const fn = definition?.node || handlerFunction(handler, scope, context.ancestors);
    if (!fn || !isFunction(fn)) return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.TENTATIVE,
      manualReview: true, properties: { channel: typeof channel === 'string' ? channel : '*', context: ipcContext(undefined) },
      description: `${this.description}: handler body could not be resolved; behavior and validation are unknown` })];
    const details = ipcContext(definition?.node && isFunction(definition.node) ? definition : undefined);
    const args = paramNames(fn).slice(1);
    const used = [...identifiersIn(fn.body)].filter(name => args.includes(name));
    // a path held to a folder or a URL checked against an allowlist counts as checking the argument
    const checked = details.arguments.filter(arg => arg.operations.length);
    const validated = details.status === 'incomplete' ? false : checked.length ? checked.every(arg => arg.validation === 'recognized-unverified') :
      validatesArguments(fn) || containment(fn).any || hasUrlValidation(fn);
    const { list, targetsWindow } = capabilities(fn, [...context.ancestors, astNode]);
    const secret = repliedValues(fn).map(value => isCall(value) && isFunction(ipcDefinition(value.callee, scope, context.ancestors)?.node) ? undefined : credentialIn(value)).find(Boolean);
    if (!details.effects.some(effect => effect.capability === 'shell') && details.helpers.some(helper => SHELL_METHODS.includes(helper.call))) {
      const index = list.indexOf('shell');
      if (index !== -1) list.splice(index, 1);
    }
    list.push(...details.effects.map(effect => effect.capability));
    if (secret || details.credentials.length) list.push('credentials');
    const caps = [...new Set(list)];
    const label = typeof channel === 'string' ? `'${channel}'` : 'a dynamic channel';
    const properties = { channel: typeof channel === 'string' ? channel : '*', capabilities: caps, argumentsUsed: used.length > 0,
      validatesArguments: validated, context: details };
    const results = [];
    // picking a window by id is reported on its own
    const sensitive = caps.filter(c => ['files', 'processes', 'shell'].includes(c) || (c === 'windows' && !targetsWindow));
    if (used.length > 0 && !validated && sensitive.length > 0)
      results.push(finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { ...properties, issue: 'unvalidated' },
        description: `${this.description}: ${label} uses ${sensitive.join(', ')} with arguments from the page (${used.join(', ')}); no rejecting input guard was recognized by this analysis` }));
    if (targetsWindow)
      results.push(finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { ...properties, issue: 'window-target' },
        description: `${this.description}: ${label} acts on a window the page chooses by id, so one window can drive another` }));
    if (secret || details.credentials.length)
      results.push(finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { ...properties, issue: 'credential', credential: secret },
        description: `${this.description}: ${label} returns a credential-like value (${secret || details.credentials[0].reference}) to the page; inspect the returned fields and intended callers` }));
    // write, then open: a file whose name and content the page chooses, handed to the operating system to open with
    // its default program (a .bat, .lnk or .hta runs) — code execution in one message
    const writes = details.effects.filter(effect => effect.kind === 'file-write');
    const opens = details.effects.filter(effect => /^shell-(openPath|openExternal)$/.test(effect.kind));
    const opensDirect = callsIn(fn, (call, name) => ['openPath', 'openExternal'].includes(name)).length > 0;
    const writesDirect = callsIn(fn, (call, name) => /^(writeFile|writeFileSync|createWriteStream|copyFile|copyFileSync|rename|renameSync|outputFile)$/.test(name || '')).length > 0;
    if (used.length > 0 && !validated && (writes.length || writesDirect) && (opens.length || opensDirect))
      results.unshift(finding(this, astNode, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: true, properties: { ...properties, issue: 'write-then-open' },
        description: `${this.description}: ${label} writes a file at a path built from the page's arguments (${used.join(', ')}), then opens it with its default program; a page that sends a script or shortcut file name runs code on the user's computer` }));
    if (results.length === 0)
      results.push(finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, properties,
        description: `${this.description}: ${label}${caps.length ? ` (${caps.join(', ')})` : ''}${used.length ? (validated ? ', contains a validation-like guard (effectiveness unverified)' : ', uses page arguments (validation unverified)') : ''}${details.status === 'incomplete' ? '; helper analysis is incomplete' : ''}` }));
    for (const result of results) {
      if (details.helpers.length) result.description += `; follows ${details.helpers.length} helper call(s)`;
      if (details.effects.length) result.description += `; operations: ${details.effects.slice(0, 5).map(effect => `${effect.kind} at ${path.basename(effect.file || '')}:${effect.line}`).join(', ')}${details.effects.length > 5 ? ', …' : ''}`;
      if (details.arguments.length) result.description += `; argument checks: ${details.arguments.slice(0, 6).map(arg => `${arg.name} ${arg.validation}`).join(', ')}${details.arguments.length > 6 ? ', …' : ''}`;
      if (details.status === 'incomplete') result.description += `; incomplete analysis: ${[...new Set(details.unresolved.map(item => item.reason))].join(', ')}`;
      const paths = details.effects.filter(effect => effect.pathControl === 'not-recognized');
      if (paths.length) result.description += `; path containment not recognized for ${[...new Set(paths.flatMap(effect => effect.pathArguments))].join(', ')}`;
    }
    return results;
  }
}

/** Channels renderer code (preloads, pages) sends or listens on: the raw material of the channel map. */
export class IpcRendererChannelJSCheck {
  constructor() {
    this.id = 'IPC_RENDERER_CHANNEL_JS_CHECK';
    this.description = __('IPC_RENDERER_CHANNEL_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/ipc-renderer';
  }

  match(astNode, astHelper, scope) {
    if (!isCall(astNode) || astNode.type === 'NewExpression' || astNode.arguments.length === 0) return null;
    const method = memberName(astNode.callee);
    if (!RENDERER_METHODS.includes(method)) return null;
    const object = astNode.callee.object;
    if (!ipcObject(object, 'ipcRenderer', scope)) return null;
    const channel = constantValue(astNode.arguments[0], scope);
    return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN,
      properties: { channel: typeof channel === 'string' ? channel : '*', method,
        direction: ['on', 'once', 'addListener'].includes(method) ? 'receive' : 'send' },
      description: `${this.description}: ${typeof channel === 'string' ? `'${channel}'` : 'any channel the caller names'} (${method})` })];
  }
}
