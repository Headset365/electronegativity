// Where the app goes, decided by a page: an IPC handler stores what a renderer sent in the main process's state, and
// that state later says which address windows load, or where requests carrying the user's token are sent.
//   ipcMain.handle('session-ready', (e, model) => setSessionModel(model));        // endpoints = model.endpoints
//   mainWindow.loadURL(getEndpoints().ui);                                       // the page chose it
//   axios.post(getEndpoints().api + 'upload', form, { headers: { Authorization: 'Bearer ' + token } });
// A page that can send the message (an injected script, a less trusted origin in an allowed window) redirects every
// window, with its preload, and the bearer token to a server of its choosing.
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue, finding, isFunction } from '../helpers.js';
import { callsIn, paramNames, functionDefinition, dependsOnParams, returnedValues, visit, isCall, isMember, currentAnalysisContext, moduleBindings } from '../analysis.js';
import { ipcListener } from '../ipc_context.js';

const HTTP_CALLS = /^(get|post|put|patch|delete|request|fetch|head)$/;
const parsedPrograms = new WeakMap();
const roots = new WeakMap();

// a file as the report shows it: relative to the application's folder (the one holding its package.json), with /
function appPath(index, file) {
  if (!roots.has(index)) {
    const manifests = [...(index.files || [])].filter(f => /(?:^|[\\/])package\.json$/.test(f)).sort((a, b) => a.length - b.length);
    roots.set(index, manifests.length ? manifests[0].replace(/[\\/]?package\.json$/, '') : '');
  }
  const root = roots.get(index);
  const relative = root && file.startsWith(root) ? file.slice(root.length).replace(/^[\\/]/, '') : file;
  return relative.split(/[\\/]/).join('/');
}

const calleeName = (callee) => callee.type === 'Identifier' ? callee.name : isMember(callee) ? memberName(callee) : undefined;
const callsTo = (node, names) => {
  let found = false;
  visit(node, (n) => { if (!found && isCall(n) && names.has(calleeName(n.callee))) found = true; return !found; });
  return found;
};

// module-level variables a setter writes from its parameters: endpoints = onLogin.endpoints
function stateWrites(setter, program) {
  const topLevel = new Set();
  for (const statement of (program && program.body) || []) {
    if (statement.type === 'VariableDeclaration' && statement.kind !== 'const')
      for (const d of statement.declarations) if (d.id.type === 'Identifier') topLevel.add(d.id.name);
  }
  const written = [];
  visit(setter.body || setter, (node) => {
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && topLevel.has(node.left.name) && dependsOnParams(node.right, setter) && !written.includes(node.left.name))
      written.push(node.left.name);
    return true;
  });
  return written;
}

// exported functions of the module that hand that state out: getEndpoints() { return { ...endpoints } }
function getters(program, state) {
  const names = [];
  visit(program, (node) => {
    if (!isFunction(node)) return true;
    const name = node.id && node.id.name;
    if (!name) return true;
    if (returnedValues(node).some(({ value }) => { let hit = false; visit(value, n => { if (n.type === 'Identifier' && state.includes(n.name)) hit = true; return !hit; }); return hit; }))
      names.push(name);
    return true;
  });
  return names;
}

function programOfFile(index, file) {
  let cache = parsedPrograms.get(index);
  if (!cache) parsedPrograms.set(index, cache = new Map());
  if (cache.has(file)) return cache.get(file);
  let program;
  try {
    const [, data] = index.parser.parse(file, index.text(file));
    program = data && (data.type === 'File' ? data.program : data);
  } catch {
    program = undefined;
  }
  cache.set(file, program);
  return program;
}

// where the getters' values are used: loadURL(getEndpoints().ui), and HTTP requests that carry an Authorization header
function destinations(index, names) {
  const set = new Set(names);
  const uses = { load: [], credentialed: [] };
  const files = new Set(names.flatMap(name => index.filesMentioning(name)));
  for (const file of [...files].slice(0, 40)) {
    const program = programOfFile(index, file);
    if (!program) continue;
    const short = appPath(index, file);
    const sendsToken = /Authorization|Bearer/.test(index.text(file));
    visit(program, (node) => {
      if (isCall(node) && calleeName(node.callee) === 'loadURL' && node.arguments[0] && callsTo(node.arguments[0], set)) {
        if (!uses.load.includes(short)) uses.load.push(short);
      }
      if (sendsToken && isFunction(node) && callsTo(node.body || node, set)) {
        const requests = callsIn(node, (call, name) => HTTP_CALLS.test(name || ''));
        if (requests.length && !uses.credentialed.includes(short)) uses.credentialed.push(short);
      }
      return true;
    });
  }
  return uses;
}

// a function called directly, or through a module namespace: auth_1.setSessionModel(model) after require('../auth')
function definitionOf(callee, scope) {
  if (callee.type === 'Identifier') return functionDefinition(callee, scope);
  if (!isMember(callee) || callee.object.type !== 'Identifier') return undefined;
  const { index, file, program } = currentAnalysisContext();
  const binding = program && moduleBindings(program).get(callee.object.name);
  if (!binding || !index || (binding.imported !== '*' && binding.imported !== 'default')) return undefined;
  return index.lookup(file, binding.module, memberName(callee));
}

export default class IpcStateDestinationJSCheck {
  constructor() {
    this.id = 'IPC_STATE_DESTINATION_JS_CHECK';
    this.description = __('IPC_STATE_DESTINATION_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/tutorial/security#17-validate-the-sender-of-all-ipc-messages';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (!isCall(astNode) || astNode.type === 'NewExpression' || astNode.arguments.length < 2) return null;
    if (!ipcListener(astNode, scope)) return null;
    const { index } = currentAnalysisContext();
    if (!index || typeof index.filesMentioning !== 'function') return null;
    const handler = astNode.arguments[astNode.arguments.length - 1];
    const fn = isFunction(handler) ? handler : functionDefinition(handler, scope)?.node;
    if (!fn || !isFunction(fn) || paramNames(fn).length < 2) return null;
    const channel = literalValue(astNode.arguments[0]);

    for (const { call } of callsIn(fn, () => true)) {
      if (!call.arguments.some(arg => dependsOnParams(arg, fn))) continue;
      const definition = definitionOf(call.callee, scope);
      if (!definition || !isFunction(definition.node)) continue;
      const state = stateWrites(definition.node, definition.program);
      if (!state.length) continue;
      const exposed = getters(definition.program, state);
      if (!exposed.length) continue;
      const uses = destinations(index, exposed);
      if (!uses.load.length && !uses.credentialed.length) continue;
      const setter = calleeName(call.callee);
      const parts = [];
      if (uses.load.length) parts.push(`the address windows load (loadURL in ${uses.load.join(', ')})`);
      if (uses.credentialed.length) parts.push(`where requests carrying the user's token are sent (${uses.credentialed.join(', ')})`);
      return [finding(this, astNode, { severity: uses.credentialed.length || uses.load.length ? severity.HIGH : severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
        properties: { channel, setter, state, getters: exposed, loads: uses.load, credentialed: uses.credentialed },
        description: `${this.description}: the '${channel}' handler stores what the page sends (${setter} → ${state.join(', ')}), which decides ${parts.join(' and ')}; nothing checks the value against the app's own addresses` })];
    }
    return null;
  }
}
