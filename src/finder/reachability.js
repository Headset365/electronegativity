// Conservative production reachability. Positive references are followed; absence
// is used to reduce a rating only in a closed, bounded graph. Dynamic code,
// exported plugin modules, missing entry points and ambiguous bindings stay open.
import path from 'node:path';
import { isFunction, memberName, literalValue, visit } from './checks/helpers.js';
import { moduleBindings } from './checks/analysis.js';
import { severity } from './attributes.js';

export const REACHABILITY_LABELS = { called: 'Called', exposed: 'Exposed but not called', 'development-only': 'Development-only',
  unreferenced: 'Unreferenced', unresolved: 'Unresolved' };
const key = (file, node) => `${file}:${node.loc?.start.line}:${node.loc?.start.column}`;
const programKey = file => `${file}:program`;
const productionBool = (node, bindings) => {
  if (!node) return undefined;
  if (node.type === 'UnaryExpression' && node.operator === '!') { const v = productionBool(node.argument, bindings); return v === undefined ? v : !v; }
  if (node.type === 'Identifier' && bindings.get(node.name)?.module === 'electron-is-dev') return false;
  if (memberName(node) === 'isPackaged') {
    const object = node.object;
    const b = bindings.get(object?.name);
    if (b?.module === 'electron' && b.imported === 'app') return true;
    if (memberName(object) === 'app' && bindings.get(object.object?.name)?.module === 'electron') return true;
  }
  return undefined;
};
function developmentGuard(node, ancestors, bindings) {
  const chain = [...ancestors, node];
  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i], child = chain[i + 1];
    if (!['IfStatement', 'ConditionalExpression'].includes(parent.type)) continue;
    const value = productionBool(parent.test, bindings);
    if (value === false && parent.consequent === child || value === true && parent.alternate === child) return true;
  }
  return false;
}
function identifierReference(node, parent) {
  if (!parent) return false;
  if ((/Function/.test(parent.type) && (parent.id === node || parent.params.includes(node))) || parent.type === 'VariableDeclarator' && parent.id === node) return false;
  if (/^Import/.test(parent.type)) return false;
  if (parent.property === node && !parent.computed && /MemberExpression$/.test(parent.type)) return false;
  if (parent.key === node && !parent.computed && parent.value !== node) return false;
  return true;
}

export class ReachabilityIndex {
  constructor(index, { remoteFiles = new Set(), maxNodes = 150000 } = {}) {
    this.index = index; this.remoteFiles = remoteFiles; this.maxNodes = maxNodes;
    this.files = new Map(); this.anchors = new WeakMap(); this.nodes = new Map(); this.edges = new Map();
  }
  edge(from, to) { if (!this.edges.has(from)) this.edges.set(from, new Set()); this.edges.get(from).add(to); }
  collect(file, ast, content) {
    if (this.files.has(file)) return; // HTML may have several script blocks: keep it unresolved.
    const program = ast.type === 'File' ? ast.program : ast;
    const info = { file, program: programKey(file), functions: new Map(), names: new Map(), imports: [], sends: [], calls: new Set(),
      loaded: [], preload: false, bridge: false, exports: false, open: false, bindings: new Map(), nodeOwners: new WeakMap(), dev: new WeakSet() };
    this.files.set(file, info); this.nodes.set(info.program, { file });
    if (String(content).length > 3000000 || /\.html?$/i.test(file)) { info.open = true; return; }
    try {
      info.bindings = moduleBindings(program);
      let count = 0;
      visit(program, (node, ancestors) => {
        if (++count > this.maxNodes) { info.open = true; return false; }
        const enclosing = [...ancestors].reverse().find(isFunction);
        const owner = enclosing ? key(file, enclosing) : info.program;
        info.nodeOwners.set(node, isFunction(node) ? key(file, node) : owner);
        if (developmentGuard(node, ancestors, info.bindings)) info.dev.add(node);
        if (isFunction(node)) {
          const parent = ancestors.at(-1);
          const name = node.id?.name || (parent?.type === 'VariableDeclarator' ? parent.id?.name : undefined);
          const id = key(file, node);
          info.functions.set(id, { id, name, node: undefined, parent: owner }); this.nodes.set(id, { file });
          if (name) {
            if (info.names.has(name) || info.bindings.has(name)) info.open = true;
            info.names.set(name, id);
          } else this.edge(owner, id); // registered callbacks and object methods escape conservatively
        }
        if (['ExportNamedDeclaration', 'ExportDefaultDeclaration'].includes(node.type)) info.exports = true;
        if (/^ImportDeclaration$/.test(node.type) || /^Export.*Declaration$/.test(node.type) && node.source) {
          const spec = literalValue(node.source); if (typeof spec === 'string') info.imports.push({ owner, spec }); else info.open = true;
        }
        if (node.type === 'WithStatement' || node.type === 'ImportExpression' && typeof literalValue(node.source) !== 'string') info.open = true;
        if (node.type === 'ImportExpression' && typeof literalValue(node.source) === 'string') info.imports.push({ owner, spec: literalValue(node.source) });
        if (node.type === 'AssignmentExpression') {
          const left = node.left;
          if (left?.object?.name === 'exports' || left?.object?.name === 'module' && memberName(left) === 'exports') info.exports = true;
          if (left.type === 'Identifier' && info.bindings.has(left.name)) info.open = true;
        }
        if (!/^(?:CallExpression|OptionalCallExpression|NewExpression)$/.test(node.type)) return true;
        const callee = node.callee, method = memberName(callee), object = callee?.object;
        if (callee?.name === 'eval' || callee?.name === 'Function') info.open = true;
        // Global framework registration can be loaded by HTML, a remote UI or a
        // plugin asset loader omitted from the package graph. Absence of an ES/CJS
        // importer is not evidence that such a browser script is dead.
        if (['controller', 'directive', 'component', 'factory', 'service'].includes(method)) info.open = true;
        if (callee?.name === 'require') {
          const spec = literalValue(node.arguments[0]);
          if (typeof spec === 'string') info.imports.push({ owner, spec }); else info.open = true;
        }
        if (method === 'exposeInMainWorld') { info.bridge = true; info.preload = true; }
        if (['send', 'sendSync', 'invoke', 'sendToHost'].includes(method) && (object?.name === 'ipcRenderer' || memberName(object) === 'ipcRenderer' || info.bindings.get(object?.name)?.imported === 'ipcRenderer')) {
          const channel = literalValue(node.arguments[0]); info.sends.push({ channel, owner });
        }
        if (['loadFile', 'loadURL'].includes(method)) {
          const target = literalValue(node.arguments[0]);
          if (typeof target === 'string' && !/^https?:/.test(target)) info.loaded.push(target);
        }
        return true;
      });
      // References and imports may precede their declarations.
      count = 0;
      visit(program, (node, ancestors) => {
        if (++count > this.maxNodes) { info.open = true; return false; }
        const owner = info.nodeOwners.get(node) || info.program;
        if (node.type === 'Identifier' && identifierReference(node, ancestors.at(-1))) {
          const to = info.names.get(node.name); if (to) this.edge(owner, to);
        }
        if (node.type === 'Property' || node.type === 'ObjectProperty') if (literalValue(node.key) === 'preload' || node.key?.name === 'preload') {
          // Resolve common literal and path.join(__dirname, 'preload.js') forms.
          const value = node.value;
          const strings = typeof literalValue(value) === 'string' ? [literalValue(value)] :
            /^(?:CallExpression|NewExpression)$/.test(value?.type) && ['join', 'resolve'].includes(memberName(value.callee)) ? value.arguments.map(literalValue).filter(v => typeof v === 'string') : [];
          const target = strings.length ? this.index.resolvePath(path.join(path.dirname(file), ...strings)) || this.index.resolvePath(path.resolve(path.dirname(file), ...strings)) : undefined;
          if (target) info.loaded.push(target); else info.open = true;
        }
        // Shadowed local function names prevent a negative call-graph conclusion.
        if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && info.names.has(node.id.name) && !isFunction(node.init)) info.open = true;
        if (isFunction(node) && node.params.some(p => p.type === 'Identifier' && (info.names.has(p.name) || info.bindings.has(p.name)))) info.open = true;
        return true;
      });
    } catch { info.open = true; }
  }
  anchor(issue, file, node) {
    const info = this.files.get(file);
    if (info) this.anchors.set(issue, { file, owner: info.nodeOwners.get(node), development: info.dev.has(node) });
  }
  annotate(issues) {
    const roots = new Set(); let entryKnown = false, openGraph = false;
    const manifests = [...this.index.files].filter(f => /(?:^|[\\/])package\.json$/.test(f)).sort((a, b) => a.length - b.length);
    if (manifests.length) try {
      const manifest = JSON.parse(this.index.loader.load_buffer(manifests[0]).toString());
      const entry = this.index.resolvePath(path.join(path.dirname(manifests[0]), manifest.main || 'index.js'));
      if (entry && this.files.has(entry)) { roots.add(programKey(entry)); entryKnown = true; }
    } catch { /* entry is not known */ }
    const preloadFiles = new Set();
    for (const info of this.files.values()) {
      if (info.open) openGraph = true;
      if (this.remoteFiles.has(info.file)) roots.add(info.program);
      for (const dep of info.imports) {
        const target = this.index.resolve(info.file, dep.spec);
        if (target && this.files.has(target)) this.edge(dep.owner, programKey(target));
        else if (/^\./.test(dep.spec)) openGraph = true;
      }
      for (const value of info.loaded) {
        const target = this.files.has(value) ? value : this.index.resolvePath(path.join(path.dirname(info.file), value));
        if (target && this.files.has(target)) { this.edge(info.program, programKey(target)); preloadFiles.add(target); }
      }
      if (info.bridge) preloadFiles.add(info.file);
    }
    // Packaged HTML scripts are renderer roots, even if the loadFile expression
    // could not be resolved. This deliberately favors retaining a rating.
    for (const file of this.index.files) if (/\.html?$/i.test(file)) try {
      const text = this.index.loader.load_buffer(file).toString();
      for (const match of text.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
        const target = this.index.resolvePath(path.join(path.dirname(file), match[1])); if (target && this.files.has(target)) roots.add(programKey(target));
      }
    } catch { openGraph = true; }
    const reached = new Set(roots), queue = [...roots];
    for (let i = 0; i < queue.length; i++) for (const target of this.edges.get(queue[i]) || []) if (!reached.has(target)) { reached.add(target); queue.push(target); }
    const calledChannels = new Set(), exposedChannels = new Set(); let genericBridge = false;
    for (const info of this.files.values()) for (const send of info.sends) {
      const exposed = preloadFiles.has(info.file) && send.owner !== info.program;
      if (typeof send.channel === 'string') {
        if (exposed) exposedChannels.add(send.channel);
        else if (reached.has(send.owner)) calledChannels.add(send.channel);
      } else if (exposed && info.bridge) genericBridge = true;
    }
    for (const issue of issues) {
      if (/^RUNTIME_|^TRAFFIC_|^STORAGE_|^WINDOWS_/.test(issue.id) || issue.constructorName === 'Runtime') continue;
      const anchor = this.anchors.get(issue), info = anchor && this.files.get(anchor.file);
      let status = 'unresolved', reason = 'Reachability could not be established from the available entry points and bindings; retain the rating.';
      const channel = issue.properties?.channel;
      if (info && anchor.development && !info.open) {
        status = 'development-only'; reason = 'An Electron production-state guard excludes this statement in a packaged build. Present in development code; remove it if unused.';
      } else if (/^IPC_/.test(issue.id) && channel && calledChannels.has(channel)) {
        status = 'called'; reason = `Packaged reachable code sends IPC channel '${channel}'. Session use is recorded separately.`;
      } else if (/^IPC_/.test(issue.id) && (channel && exposedChannels.has(channel) || genericBridge && /^(?:IPC_HANDLER|IPC_RPC_PROCEDURE|IPC_STATE_DESTINATION|IPC_FILE_ACCESS|IPC_SENDER_VALIDATION)/.test(issue.id))) {
        status = 'exposed'; reason = 'The preload exposes this IPC capability, but a packaged caller was not established. A remote UI or injected script may still call it without an app update. Retain the rating and remove the API if unused.';
      } else if (anchor?.owner && reached.has(anchor.owner)) {
        status = 'called'; reason = 'Reachable from an app entry point or registered callback through static references. This does not establish session execution.';
      } else if (info && entryKnown && !openGraph && !info.exports && anchor?.owner) {
        status = 'unreferenced'; reason = 'Present but not reachable in the closed static reference graph: no reachable registration, import or caller was found. Remove it if unused.';
      }
      setReachability(issue, status, reason);
    }
    return issues;
  }
}
export function setReachability(issue, status, reason) {
  const prior = issue.reachability;
  const originalSeverity = prior?.originalSeverity || issue.severity.name;
  issue.reachability = { staticStatus: status, label: REACHABILITY_LABELS[status], reason, exercised: prior?.exercised || false, originalSeverity };
  if (['development-only', 'unreferenced'].includes(status)) issue.severity = severity.INFORMATIONAL;
}
export function applyRuntimeReachability(issues, summary = {}) {
  const channels = new Set(summary.usedChannelNames || []), procedures = new Set(summary.usedProcedures || []);
  for (const issue of issues.filter(i => i.reachability)) {
    const r = issue.reachability;
    const ipc = /^IPC_/.test(issue.id) && issue.properties?.channel && channels.has(issue.properties.channel);
    const rpc = issue.id === 'IPC_RPC_PROCEDURE_JS_CHECK' && (procedures.has(issue.properties?.procedurePath) ||
      [...procedures].some(p => p.split('.').at(-1) === issue.properties?.procedure && issues.filter(i => i.id === issue.id && i.properties?.procedure === issue.properties.procedure).length === 1));
    if (ipc || rpc) { r.exercised = true; r.exercisedScope = rpc ? 'rpc-procedure-dispatch' : 'ipc-channel-dispatch'; }
    // Temporal correlation is not evidence that the particular static statement ran.
    if (r.exercised && r.exercisedScope !== 'temporal-correlation') {
      r.label = 'Exercised';
      if (r.staticStatus === 'development-only' && summary.packaged === false) {
        r.label = 'Development-only'; r.exercisedScope = `${r.exercisedScope} (unpackaged development session)`;
      } else if (['development-only', 'unreferenced'].includes(r.staticStatus)) {
        issue.severity = severity[r.originalSeverity] || issue.severity;
        r.contradiction = 'Runtime evidence contradicts the static reachability conclusion; original rating restored.';
        r.staticStatus = 'unresolved';
      }
    }
  }
}
