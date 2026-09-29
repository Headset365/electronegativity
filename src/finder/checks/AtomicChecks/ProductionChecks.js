// Production build review in code: development tooling and local dev servers left in, behavior switched on by an
// environment variable anyone launching the app can set, verbose logging; how the app launches Microsoft Word; and the
// libraries that parse documents (DOCX, XML, ZIP, Markdown) with the options that make them risky.
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding, literalValue, findProperty } from '../helpers.js';
import { constantValue, constantPrefix, possibleValues, enclosingFunction, untrustedSource, dependsOnParams, moduleBindings, programOf,
  identifiersIn, callsIn, visit, isCall, isMember, resolveLocal } from '../analysis.js';
import { fsOperation, CONTAINMENT } from './IpcHandlerChecks.js';

const calleeName = (callee) => callee.type === 'Identifier' ? callee.name : memberName(callee);
const LOCAL_SERVER = /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])([:/]|$)/i;
const DEV_MODULES = /^(electron-reload|electron-reloader|electron-devtools-installer|electron-debug|webpack-dev-server|electron-connect|devtron|vite|webpack-hot-middleware|electron-hot-reload)$/;

// The text of an expression: identifiers, member names and strings, for matching conditions
function words(node) {
  const parts = [...identifiersIn(node)];
  visit(node, (n) => {
    if (isMember(n)) parts.push(memberName(n));
    if (typeof n.value === 'string') parts.push(n.value);
    return true;
  });
  return parts.join(' ');
}

// The conditions guarding a node: if tests, ternaries, the left side of && and early-return ifs before it
function guards(node, ancestors) {
  const chain = [...ancestors, node];
  const tests = [];
  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i];
    const child = chain[i + 1];
    if ((parent.type === 'IfStatement' || parent.type === 'ConditionalExpression') && child !== parent.test) tests.push(parent.test);
    if (parent.type === 'LogicalExpression' && child === parent.right) tests.push(parent.left);
    if (parent.type === 'BlockStatement' || parent.type === 'Program') {
      const index = parent.body.indexOf(child);
      parent.body.slice(0, index).filter(s => s.type === 'IfStatement' && s.consequent &&
        (s.consequent.type === 'ReturnStatement' || (s.consequent.body || []).some(b => b.type === 'ReturnStatement'))).forEach(s => tests.push(s.test));
    }
  }
  return tests;
}

/**
 * How a piece of code is limited to development builds: 'packaged' (app.isPackaged, which a user can't change),
 * 'env' (an environment variable or command-line flag, which whoever starts the app sets, electron-is-dev included:
 * ELECTRON_IS_DEV overrides it), 'flag' (a dev-looking variable of unknown origin) or undefined (not limited).
 */
export function developmentGate(node, ancestors, scope) {
  const program = programOf(ancestors);
  const bindings = program ? moduleBindings(program) : new Map();
  let gate;
  for (const test of guards(node, ancestors)) {
    let text = words(test);
    // follow `const isDev = ...` once
    for (const name of identifiersIn(test)) {
      const binding = bindings.get(name);
      if (binding && /electron-is-dev/.test(binding.module || '')) text += ' process.env ELECTRON_IS_DEV';
      const init = resolveLocal({ type: 'Identifier', name }, scope);
      if (init && init.type !== 'Identifier') text += ` ${words(init)}`;
    }
    if (/\bisPackaged\b/.test(text)) return 'packaged';
    if (/\b(env|argv)\b/.test(text) && /NODE_ENV|DEV|DEBUG|development|inspect/i.test(text)) gate = 'env';
    else if (!gate && /(^|[^a-z])(is_?dev|dev(elopment|mode)?|debug)/i.test(text)) gate = 'flag';
  }
  return gate;
}

/** Development tooling, local dev servers, extension installers and dev-only IPC or preload APIs in the shipped code. */
export class DevelopmentCodeJSCheck {
  constructor() {
    this.id = 'DEVELOPMENT_CODE_JS_CHECK';
    this.description = __('DEVELOPMENT_CODE_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/app#appispackaged-readonly';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    let what;
    let alwaysBad = false;
    if (astNode.type === 'ImportDeclaration' && DEV_MODULES.test(literalValue(astNode.source) || '')) {
      what = `loads the development tool ${literalValue(astNode.source)}`;
      alwaysBad = true;
    } else if (isCall(astNode) && astNode.type !== 'NewExpression') {
      const name = calleeName(astNode.callee) || '';
      const module = (name === 'require' || astNode.type === 'ImportExpression') ? literalValue(astNode.arguments[0]) : undefined;
      if (module && DEV_MODULES.test(module)) { what = `loads the development tool ${module}`; alwaysBad = true; }
      else if (name === 'loadURL' && astNode.arguments[0]) {
        const values = possibleValues(astNode.arguments[0], scope);
        const value = constantValue(astNode.arguments[0], scope) ?? constantPrefix(astNode.arguments[0], scope) ?? values.find(v => typeof v === 'string' && LOCAL_SERVER.test(v));
        if (typeof value === 'string' && LOCAL_SERVER.test(value)) { what = `loads the local development server ${value.replace(/^(https?:\/\/[^/]+).*/, '$1')}`; alwaysBad = true; }
      } else if (['installExtension', 'loadExtension'].includes(name)) { what = 'installs browser extensions'; alwaysBad = name === 'installExtension'; }
      else if (['handle', 'handleOnce', 'on'].includes(name) && /^ipcMain$/.test((astNode.callee.object && astNode.callee.object.name) || '')) {
        const channel = constantValue(astNode.arguments[0], scope);
        what = `registers the IPC channel ${typeof channel === 'string' ? `'${channel}'` : '(dynamic)'} only in development`;
      } else if (['exposeInMainWorld', 'exposeInIsolatedWorld'].includes(name)) what = 'exposes a preload API only in development';
      else if (name === 'appendSwitch' && /^(remote-debugging-port|remote-debugging-pipe|inspect|enable-logging|v|vmodule)$/.test(literalValue(astNode.arguments[0]) || ''))
        what = `adds the Chromium switch --${literalValue(astNode.arguments[0])}`;
    }
    if (!what) return null;
    const gate = developmentGate(astNode, context.ancestors, scope);
    if (gate === 'packaged') return null;
    if (gate === 'env')
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true, properties: { gate, behavior: what },
        description: `${this.description}: ${what}, switched on by an environment variable or command-line flag that whoever starts the app can set (NODE_ENV, ELECTRON_IS_DEV, --dev); test app.isPackaged instead` })];
    if (gate === 'flag')
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.TENTATIVE, manualReview: true, properties: { gate, behavior: what },
        description: `${this.description}: ${what} behind a development flag; check that it can't be turned on in the shipped app` })];
    if (!alwaysBad) return null; // IPC channels and preload APIs outside a dev condition are the app's normal surface
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { gate: 'none', behavior: what },
      description: `${this.description}: ${what} unconditionally, so the shipped app does too${/local development server/.test(what) ? ': any local program listening on that port serves the app\'s UI, with its preload' : ''}` })];
  }
}

const VERBOSE = /^(debug|silly|verbose|trace|all)$/i;

/** Logging turned up in the shipped app: electron-log, winston, pino or Chromium's own log. */
export class DebugLoggingJSCheck {
  constructor() {
    this.id = 'DEBUG_LOGGING_JS_CHECK';
    this.description = __('DEBUG_LOGGING_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://cwe.mitre.org/data/definitions/532.html';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    let what;
    if (astNode.type === 'AssignmentExpression' && isMember(astNode.left)) {
      const target = memberName(astNode.left);
      const value = constantValue(astNode.right, scope);
      // log.transports.file.level = 'debug' (electron-log), logger.level = 'debug'
      if (target === 'level' && typeof value === 'string' && VERBOSE.test(value)) what = `sets the log level to '${value}'`;
      // process.env.ELECTRON_ENABLE_LOGGING = '1'
      else if (target === 'ELECTRON_ENABLE_LOGGING' && value !== undefined && value !== '' && value !== '0' && value !== false) what = 'sets ELECTRON_ENABLE_LOGGING';
    } else if (isCall(astNode) && astNode.type !== 'NewExpression') {
      const name = calleeName(astNode.callee) || '';
      const options = astNode.arguments[0];
      if (/^(createLogger|pino|configure)$/.test(name) && options && options.type === 'ObjectExpression') {
        const level = findProperty(options, 'level');
        const value = level && constantValue(level[1], scope);
        if (typeof value === 'string' && VERBOSE.test(value)) what = `creates a logger at level '${value}'`;
      } else if (name === 'appendSwitch' && ['enable-logging', 'v', 'vmodule'].includes(literalValue(astNode.arguments[0])))
        what = `turns on Chromium logging (--${literalValue(astNode.arguments[0])})`;
    }
    if (!what) return null;
    const gate = developmentGate(astNode, context.ancestors, scope);
    if (gate === 'packaged' || gate === 'flag') return null;
    return [finding(this, astNode, { severity: severity.LOW, confidence: gate === 'env' ? confidence.TENTATIVE : confidence.CERTAIN, manualReview: true,
      properties: { gate: gate || 'none' },
      description: `${this.description}: ${what}${gate === 'env' ? ' when an environment variable is set' : ''}; verbose logs on disk can hold tokens, URLs with credentials and document content` })];
  }
}

const WORD = /(^|[\\/"'\s])(winword(\.exe)?|soffice(\.exe|\.bin)?|Microsoft Word(\.app)?)(["'\s]|$)/i;
const OFFICE_URI = /^ms-(word|excel|powerpoint|visio|access|project|publisher|spd|infopath):/i;
const WORD_FLAGS = /^\/(m|t|f|n|mfile\d|a|r|w|x|vo|safe|q|embedding)\b/i;
const DOCUMENT_EXT = /\.(docx?|docm|dotx?|dotm|rtf|odt)$/i;
const CHILD_PROCESS = /^(node:)?child_process$/;
const SHELLS = /(^|[\\/])(cmd|cmd\.exe|powershell|powershell\.exe|pwsh|sh|bash)$/i;

function childProcessCall(call, ancestors) {
  const program = programOf(ancestors);
  const bindings = program ? moduleBindings(program) : new Map();
  const callee = call.callee;
  if (callee.type === 'Identifier') { const b = bindings.get(callee.name); return b && CHILD_PROCESS.test(b.module || '') ? b.imported : undefined; }
  const object = callee.object;
  if (object && object.type === 'Identifier') { const b = bindings.get(object.name); return b && CHILD_PROCESS.test(b.module || '') ? memberName(callee) : undefined; }
  if (object && isCall(object) && object.callee.type === 'Identifier' && object.callee.name === 'require' && CHILD_PROCESS.test(literalValue(object.arguments[0]) || '')) return memberName(callee);
  return undefined;
}

// How the app finds Word: a fixed path, the registry, the PATH or App Paths, or a computed value
function wordLocation(executable, scope, fn) {
  const value = constantValue(executable, scope);
  if (typeof value === 'string') {
    if (/^([a-z]:\\|\/|\\\\)/i.test(value)) return { how: 'at a fixed path', value };
    return { how: 'looked up on PATH / App Paths (a folder earlier on PATH can supply its own)', value };
  }
  const registry = fn && callsIn(fn, (call, name) => /reg(Query|edit)?|winreg|getValue|queryValue/i.test(name || '') ||
    call.arguments.some(a => /reg(\.exe)?\s+query|App Paths|\\Winword/i.test(String(literalValue(a) || '')))).length > 0;
  return { how: registry ? 'read from the registry' : 'computed at runtime' };
}

/** How the app starts Microsoft Word (or LibreOffice) on a document: executable, command line, ms-word: URIs. */
export class WordLaunchJSCheck {
  constructor() {
    this.id = 'WORD_LAUNCH_JS_CHECK';
    this.description = __('WORD_LAUNCH_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://learn.microsoft.com/en-us/office/client-developer/office-uri-schemes';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (!isCall(astNode) || astNode.type === 'NewExpression' || astNode.arguments.length === 0) return null;
    const ancestors = context.ancestors;
    const fn = enclosingFunction(ancestors);
    const source = fn && untrustedSource(ancestors, fn);
    const fromContent = (node) => !!(source && node && dependsOnParams(node, fn));
    const report = (sev, conf, text, properties, manualReview = true) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, properties, description: `${this.description}: ${text}` })];
    const name = calleeName(astNode.callee) || '';

    // shell.openExternal('ms-word:ofe|u|https://...')
    if (name === 'openExternal') {
      const arg = astNode.arguments[0];
      const prefix = constantValue(arg, scope) ?? constantPrefix(arg, scope);
      if (typeof prefix !== 'string' || !OFFICE_URI.test(prefix)) return null;
      const constant = typeof constantValue(arg, scope) === 'string';
      if (constant) return report(severity.INFORMATIONAL, confidence.CERTAIN, `opens the constant Office URI ${prefix}`, { launcher: 'uri' }, false);
      if (fromContent(arg))
        return report(severity.HIGH, confidence.FIRM, `builds an Office URI (${prefix}...) from ${source}: content chooses the document Word downloads and opens, including remote templates and file:// or UNC locations`, { launcher: 'uri', source }, false);
      return report(severity.MEDIUM, confidence.TENTATIVE, `builds an Office URI (${prefix}...) from a value; check that only the app's own document URLs get there`, { launcher: 'uri' });
    }
    // shell.openPath(file.docx): the default program, usually Word
    if (name === 'openPath') {
      const arg = astNode.arguments[0];
      const text = words(arg);
      if (!DOCUMENT_EXT.test(String(constantValue(arg, scope) || '')) && !/\.(docx?|docm|dotx?|rtf)\b/i.test(text)) return null;
      const extensionChecked = fn && callsIn(fn, (call, n) => ['extname', 'endsWith'].includes(n)).length > 0;
      return report(fromContent(arg) ? severity.HIGH : severity.LOW, fromContent(arg) ? confidence.FIRM : confidence.TENTATIVE,
        `opens a document with its default program (Word)${fromContent(arg) ? ` at a path from ${source}` : ''}${extensionChecked ? '' : '; the extension is not checked, so another file type would open with its own program'}`,
        { launcher: 'default program', source }, !fromContent(arg));
    }
    // child_process: exec('start winword "..."'), spawn('C:\\...\\WINWORD.EXE', [file]), execFile('soffice', [...])
    const cp = childProcessCall(astNode, ancestors);
    if (!cp) return null;
    const args = astNode.arguments;
    const list = args[1] && args[1].type === 'ArrayExpression' ? args[1].elements : [];
    const commandText = [constantValue(args[0], scope), constantPrefix(args[0], scope), ...list.map(a => a && constantValue(a, scope))].filter(v => typeof v === 'string').join(' ');
    const executableText = String(constantValue(args[0], scope) ?? constantPrefix(args[0], scope) ?? '');
    if (!WORD.test(` ${commandText} `) && !WORD.test(` ${executableText} `)) return null;
    const options = args.length > 1 && args[args.length - 1].type === 'ObjectExpression' ? args[args.length - 1] : undefined;
    const shellOption = options && findProperty(options, 'shell');
    const viaShell = ['exec', 'execSync'].includes(cp) || (shellOption && literalValue(shellOption[1]) !== false) || SHELLS.test(executableText);
    const location = ['exec', 'execSync'].includes(cp) ? { how: 'named in a shell command (resolved on PATH / App Paths)' } : wordLocation(args[0], scope, fn);
    const dynamic = ['exec', 'execSync'].includes(cp) ? [args[0]].filter(a => constantValue(a, scope) === undefined) : list.filter(a => a && constantValue(a, scope) === undefined);
    const flags = list.map(a => a && constantValue(a, scope)).filter(v => typeof v === 'string' && WORD_FLAGS.test(v));
    const tainted = dynamic.filter(fromContent);
    const properties = { launcher: cp, locate: location.how, shell: !!viaShell, flags, source: tainted.length ? source : undefined };
    const flagNote = flags.length ? `; passes ${flags.join(' ')} (/m runs a macro, /t and /f use a template)` : '';
    const where = `Word is ${location.how}${location.value ? ` (${location.value})` : ''}`;
    if (tainted.length && viaShell)
      return report(severity.HIGH, confidence.FIRM, `runs Word through a shell with a document name from ${source}: quotes, & or | in the name run other commands. ${where}${flagNote}`, properties, false);
    if (tainted.length)
      return report(severity.MEDIUM, confidence.FIRM, `starts Word on a document path from ${source}: content chooses what Word opens (another folder, a UNC path, a file with a remote template). ${where}${flagNote}`, properties);
    if (dynamic.length && viaShell)
      return report(severity.MEDIUM, confidence.FIRM, `runs Word through a shell with a computed document name: quotes, & or | in a file name run other commands; pass arguments without a shell. ${where}${flagNote}`, properties);
    if (/PATH/.test(location.how))
      return report(severity.LOW, confidence.FIRM, `${where}${flagNote}`, properties);
    return report(severity.INFORMATIONAL, confidence.FIRM, `${where}${dynamic.length ? ', document passed as a separate argument' : ''}${flagNote}`, properties, false);
  }
}

// Libraries that parse documents and archives, and what each one is used for
const PARSERS = {
  mammoth: 'DOCX to HTML', docx4js: 'DOCX', docxtemplater: 'DOCX templates', 'docx-preview': 'DOCX to HTML', 'docx-parser': 'DOCX', officeparser: 'Office documents',
  'word-extractor': 'Word documents', 'libxmljs': 'XML', 'libxmljs2': 'XML', xml2js: 'XML', 'fast-xml-parser': 'XML', xmldom: 'XML', '@xmldom/xmldom': 'XML',
  sax: 'XML', 'xml-js': 'XML', 'xpath': 'XML', jszip: 'ZIP', pizzip: 'ZIP', 'adm-zip': 'ZIP', yauzl: 'ZIP', unzipper: 'ZIP', 'extract-zip': 'ZIP', 'decompress': 'archives',
  tar: 'TAR', marked: 'Markdown', 'markdown-it': 'Markdown', showdown: 'Markdown', remark: 'Markdown', 'remark-html': 'Markdown', turndown: 'HTML to Markdown',
  'pdfjs-dist': 'PDF', 'pdf-parse': 'PDF', sharp: 'images and SVG', 'svg2png': 'SVG', canvg: 'SVG', 'html-to-docx': 'HTML to DOCX', docx: 'DOCX generation',
};
const ARCHIVES = /^(jszip|pizzip|adm-zip|yauzl|yauzl-promise|unzipper|node-stream-zip|tar|tar-stream|decompress|extract-zip|7zip-min|node-7z)$/;
const processCache = new WeakMap();

// Which process a file runs in: its Electron imports and globals tell
export function processOf(program) {
  if (!program) return 'unknown';
  if (processCache.has(program)) return processCache.get(program);
  const names = new Set();
  for (const [, binding] of moduleBindings(program)) if (/^electron(\/(main|renderer))?$/.test(binding.module || '')) names.add(binding.imported);
  let kind = 'unknown';
  if (['BrowserWindow', 'ipcMain', 'app', 'protocol', 'session'].some(n => names.has(n))) kind = 'main';
  else if (['contextBridge', 'ipcRenderer', 'webFrame'].some(n => names.has(n))) kind = 'preload';
  else {
    const ids = identifiersIn(program);
    if (ids.has('document') || ids.has('window')) kind = 'renderer';
  }
  processCache.set(program, kind);
  return kind;
}

/**
 * The document pipeline: every library that parses documents or archives, in which process, and the options that open
 * it up (mammoth reading external files, libxml2 expanding entities, markdown-it passing raw HTML). Archive entries
 * written to disk under their own name without a folder check (zip slip) are reported too.
 */
export class DocumentPipelineJSCheck {
  constructor() {
    this.id = 'DOCUMENT_PIPELINE_JS_CHECK';
    this.description = __('DOCUMENT_PIPELINE_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    const ancestors = context.ancestors;
    const report = (sev, conf, text, properties, manualReview = true) =>
      [finding(this, astNode, { severity: sev, confidence: conf, manualReview, properties, description: `${this.description}: ${text}` })];
    // inventory: import mammoth from 'mammoth', require('libxmljs')
    let module;
    if (astNode.type === 'ImportDeclaration') module = literalValue(astNode.source);
    else if (isCall(astNode) && astNode.callee.type === 'Identifier' && astNode.callee.name === 'require') module = literalValue(astNode.arguments[0]);
    if (typeof module === 'string' && PARSERS[module]) {
      const where = processOf(programOf(ancestors) || ancestors[0]);
      const note = where === 'main' ? ' in the main process (a parser bug runs with full privileges)' : where === 'preload' ? ' in a preload' : where === 'renderer' ? ' in a renderer' : '';
      return report(severity.INFORMATIONAL, confidence.CERTAIN, `${module} (${PARSERS[module]})${note}`, { library: module, purpose: PARSERS[module], process: where }, false);
    }
    if (!isCall(astNode)) return null;
    const name = calleeName(astNode.callee) || '';
    // new MarkdownIt({ html: true }), markdownit({ html: true })
    if (/^(markdownit|MarkdownIt|markdownIt)$/.test(name)) {
      const settings = astNode.arguments.find(a => a && a.type === 'ObjectExpression');
      const html = settings && findProperty(settings, 'html');
      if (html && constantValue(html[1], scope) === true)
        return report(severity.LOW, confidence.CERTAIN, 'markdown-it passes raw HTML through (html: true): its output needs sanitizing before it reaches the page', { library: 'markdown-it' });
      return null;
    }
    if (astNode.type === 'NewExpression') return null;
    const objectName = (astNode.callee.object && (astNode.callee.object.name || memberName(astNode.callee.object))) || '';
    // the options object is the last object argument: mammoth.convertToHtml({ buffer }, { ...options })
    const options = astNode.arguments.filter(a => a && a.type === 'ObjectExpression').pop();
    const option = (key) => { const p = options && findProperty(options, key); return p ? constantValue(p[1], scope) : undefined; };
    // mammoth.convertToHtml(input, { externalFileAccess: true })
    if (/^(convertToHtml|convertToMarkdown|extractRawText|convert)$/.test(name) && /mammoth/i.test(objectName) && option('externalFileAccess') === true)
      return report(severity.MEDIUM, confidence.CERTAIN, 'mammoth may read files the document links to (externalFileAccess: true): a crafted DOCX pulls local or UNC files into its output', { library: 'mammoth' }, false);
    // libxmljs.parseXml(text, { noent: true })
    if (/^(parseXml|parseXmlString|parseXmlAsync)$/.test(name) && options) {
      if (option('noent') === true)
        return report(severity.HIGH, confidence.CERTAIN, 'libxml2 expands external entities (noent: true): a document can read local files and make network requests (XXE)', { library: 'libxmljs', option: 'noent' }, false);
      if (option('dtdload') === true || option('nonet') === false)
        return report(severity.MEDIUM, confidence.CERTAIN, 'libxml2 loads external DTDs or may use the network while parsing: documents can make the app fetch URLs', { library: 'libxmljs' }, false);
    }
    // zip slip: an archive entry written under its own name
    const operation = fsOperation(astNode, ancestors);
    if (operation && ['write', 'copy'].includes(operation.op)) {
      const target = astNode.arguments[operation.op === 'copy' ? 1 : 0];
      const program = programOf(ancestors);
      const readsArchives = program && [...moduleBindings(program).values()].some(b => ARCHIVES.test(b.module || ''));
      if (!readsArchives || !target) return null;
      let entryName = false;
      visit(target, (n) => {
        if (isMember(n) && ['fileName', 'entryName', 'filename', 'path', 'name', 'relativePath'].includes(memberName(n)) && n.object.type === 'Identifier' && /entry|zip|item|header|file/i.test(n.object.name)) entryName = true;
        if (n.type === 'Identifier' && /^(relativePath|entryName|entryPath|fileName|filename)$/.test(n.name)) entryName = true;
        return !entryName;
      });
      if (!entryName) return null;
      const fn = enclosingFunction(ancestors);
      // (path.resolve or normalize alone keep ../ escapes: the resolved path still has to be checked against the folder)
      const held = fn && callsIn(fn, (call, n) => CONTAINMENT.test(n || '')).length > 0;
      if (held) return null;
      return report(severity.HIGH, confidence.FIRM, `${operation.name} writes an archive entry under its own name without checking it stays in the target folder (zip slip): an entry named ../../x overwrites any file the user can write`, { issue: 'zip-slip' }, false);
    }
    if (/^(extractAllTo|extractEntryTo)$/.test(name) && astNode.arguments.length > 0)
      return report(severity.INFORMATIONAL, confidence.FIRM, 'adm-zip extracts archives itself: keep it current (versions before 0.4.11 allow zip slip) and check the archive\'s origin', { library: 'adm-zip' }, false);
    return null;
  }
}

