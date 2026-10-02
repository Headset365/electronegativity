// Procedures an IPC framework (electron-trpc, and routers built the same way) exposes to the renderer:
//   saveFile: t.procedure.input(z.object({ filePath: z.string() })).query(({ input }) => writeFileSync(input.filePath, …))
// Such a router answers on one ipcMain channel, so the ipcMain checks see one handler and none of the procedures behind
// it. Each procedure is an IPC handler in its own right: any page that can reach the bridge can call it with any input
// its schema accepts. Raised for procedures that write or delete files, open paths, start processes, change the
// network setup or hand back credentials.
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, finding, isFunction } from '../helpers.js';
import { moduleBindings, programOf, callsIn, paramNames, identifiersIn, isMember } from '../analysis.js';

const RESOLVERS = ['query', 'mutation', 'subscription'];
const FS_MODULE = /^(node:)?(fs|fs\/promises|original-fs|graceful-fs|fs-extra|fs-jetpack)$/;
// a bundled or renamed fs binding: import_fs9, import_promises3, fsp, fse
const FS_NAME = /^(?:import_)?(?:fs|fsp|fse|fsExtra|originalFs|promises|fs_promises|fs_extra)\d*$/;
const FILE_CHANGES = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'outputFile', 'outputFileSync',
  'writeJson', 'writeJSON', 'writeJsonSync', 'outputJson', 'outputJsonSync', 'mkdir', 'mkdirSync', 'symlink', 'symlinkSync', 'chmod', 'chmodSync',
  'copyFile', 'copyFileSync', 'cp', 'cpSync', 'copy', 'copySync', 'rename', 'renameSync', 'move', 'moveSync',
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'remove', 'removeSync', 'emptyDir', 'emptyDirSync']);
const DELETES = /^(unlink|rm|rmdir|remove|emptyDir)(Sync)?$/;
const SHELL = ['openPath', 'openExternal', 'showItemInFolder', 'trashItem', 'writeShortcutLink'];
const PROCESSES = /^(node:)?child_process$/;
const NETWORK_SETUP = ['setProxy', 'setCertificateVerifyProc', 'setSSLConfig', 'enableNetworkEmulation', 'setUserAgent'];
const CREDENTIALS = ['decryptString', 'getPassword', 'findPassword', 'findCredentials', 'unprotectData'];

// (0, fs.rm)(x) is how bundlers call an imported function
const unwrap = (callee) => callee.type === 'SequenceExpression' ? callee.expressions[callee.expressions.length - 1] : callee;
const nameOf = (callee) => callee.type === 'Identifier' ? callee.name : isMember(callee) ? memberName(callee) : undefined;

// the procedure builder chain: t.procedure.input(…).use(…).query → true when `.procedure` is in it
function isProcedureChain(node) {
  for (let current = node; current;) {
    if (isMember(current)) {
      if (memberName(current) === 'procedure' || memberName(current) === 'publicProcedure' || memberName(current) === 'protectedProcedure') return true;
      current = current.object;
    } else if (current.type === 'CallExpression' || current.type === 'OptionalCallExpression') current = current.callee;
    else return current.type === 'Identifier' && /^(publicProcedure|protectedProcedure|procedure)$/.test(current.name);
  }
  return false;
}

// what a resolver can do: [{ capability, call }]
function resolverEffects(fn, ancestors) {
  const program = programOf(ancestors);
  const bindings = program ? moduleBindings(program) : new Map();
  const moduleOfObject = (object) => {
    if (!object) return undefined;
    if (object.type === 'Identifier') return bindings.get(object.name)?.module || (FS_NAME.test(object.name) ? 'fs' : undefined);
    if (isMember(object) && memberName(object) === 'promises') return moduleOfObject(object.object);
    return undefined;
  };
  const effects = [];
  callsIn(fn, () => true).forEach(({ call }) => {
    const callee = unwrap(call.callee);
    const name = nameOf(callee);
    if (!name) return;
    const object = isMember(callee) ? callee.object : undefined;
    const module = callee.type === 'Identifier' ? bindings.get(name)?.module : moduleOfObject(object);
    const objectName = object && (object.type === 'Identifier' ? object.name : isMember(object) ? memberName(object) : undefined);
    if (FILE_CHANGES.has(name) && FS_MODULE.test(module || '')) effects.push({ capability: DELETES.test(name) ? 'deletes files' : 'writes files', call: name });
    else if (PROCESSES.test(module || '')) effects.push({ capability: 'starts processes', call: name });
    else if (SHELL.includes(name) && (!objectName || objectName === 'shell' || /electron/.test(module || ''))) effects.push({ capability: 'opens paths or links', call: name });
    else if (NETWORK_SETUP.includes(name)) effects.push({ capability: 'changes the network setup', call: name });
    else if (CREDENTIALS.includes(name)) effects.push({ capability: 'returns decrypted secrets', call: name });
  });
  return effects;
}

// where the procedure sits: the router variable it belongs to (osIntegrationRouter), if any
function routerName(ancestors) {
  for (let i = ancestors.length - 1; i > 0; i--) {
    const node = ancestors[i];
    if ((node.type === 'CallExpression' || node.type === 'OptionalCallExpression') && nameOf(node.callee) === 'router') {
      const holder = ancestors[i - 1];
      return holder && holder.type === 'VariableDeclarator' && holder.id.type === 'Identifier' ? holder.id.name : undefined;
    }
  }
  return undefined;
}

export default class IpcRpcProcedureJSCheck {
  constructor() {
    this.id = 'IPC_RPC_PROCEDURE_JS_CHECK';
    this.description = __('IPC_RPC_PROCEDURE_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/tutorial/security#17-validate-the-sender-of-all-ipc-messages';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'ObjectProperty' && astNode.type !== 'Property') return null;
    const call = astNode.value;
    if (!call || (call.type !== 'CallExpression' && call.type !== 'OptionalCallExpression') || !isMember(call.callee)) return null;
    const kind = memberName(call.callee);
    if (!RESOLVERS.includes(kind) || !isProcedureChain(call.callee.object)) return null;
    const resolver = call.arguments[call.arguments.length - 1];
    if (!resolver || !isFunction(resolver)) return null;
    const procedure = keyName(astNode.key);
    if (!procedure) return null;
    const ancestors = [...(context.ancestors || []), astNode, call];
    const effects = resolverEffects(resolver, ancestors);
    if (!effects.length) return null;

    // the page's input reaches the resolver as its first parameter's `input` ({ input }, { input: { link } })
    const params = paramNames(resolver);
    const used = [...identifiersIn(resolver.body)];
    const takesInput = params.length > 0 && params.some(name => used.includes(name));
    const capabilities = [...new Set(effects.map(effect => effect.capability))];
    const calls = [...new Set(effects.map(effect => effect.call))];
    const router = routerName(context.ancestors || []);
    const label = `'${router ? `${router}.` : ''}${procedure}'`;
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: takesInput ? confidence.FIRM : confidence.TENTATIVE, manualReview: true,
      properties: { procedure, router, kind, capabilities, calls, takesInput },
      description: `${this.description}: the ${kind} ${label} ${capabilities.join(', ')} (${calls.join(', ')})${takesInput ? ' with input from the page' : ''}; any page that reaches the IPC bridge can call it` })];
  }
}
