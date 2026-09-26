import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, findProperty, literalValue, finding, resolveIdentifier } from '../helpers.js';
import { constantValue, enclosingFunction, untrustedSource, dependsOnParams, moduleBindings, programOf } from '../analysis.js';

// child_process functions that run their input through a shell
const SHELL_COMMANDS = ['exec', 'execSync'];
const PROCESS_COMMANDS = ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'];
const SHELLS = /(^|[\\/])(sh|bash|zsh|dash|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)$/i;

const CHILD_PROCESS = /^(node:)?child_process$/;

// The child_process function called, if the callee resolves to one: exec(), cp.exec(), require('child_process').exec()
function childProcessFunction(callee, ancestors) {
  const program = programOf(ancestors);
  const bindings = program ? moduleBindings(program) : new Map();
  if (callee.type === 'Identifier') {
    const binding = bindings.get(callee.name);
    return binding && CHILD_PROCESS.test(binding.module || '') && binding.imported !== '*' ? binding.imported : undefined;
  }
  const method = memberName(callee);
  const object = callee.object;
  if (object && object.type === 'Identifier') {
    const binding = bindings.get(object.name);
    return binding && CHILD_PROCESS.test(binding.module || '') && binding.imported === '*' ? method : undefined;
  }
  if (object && object.type === 'CallExpression' && object.callee.type === 'Identifier' && object.callee.name === 'require' && CHILD_PROCESS.test(literalValue(object.arguments[0]) || ''))
    return method;
  return undefined;
}

// Command injection in the main process gives code execution on the user's machine
export default class CommandInjectionJSCheck {
  constructor() {
    this.id = "COMMAND_INJECTION_JS_CHECK";
    this.description = __("COMMAND_INJECTION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression') return null;
    // `exec` is a common name (RegExp.prototype.exec, app helpers...): only calls resolved to child_process count
    const name = childProcessFunction(astNode.callee, context.ancestors);
    if (!name) return null;
    const args = astNode.arguments;
    if (args.length === 0) return null;

    let input;
    let usesShellFlag = false;
    if (SHELL_COMMANDS.includes(name)) input = args[0];
    else if (PROCESS_COMMANDS.includes(name)) {
      // spawn(command, [args], options): the options object is the last argument after the command
      const last = args.length > 1 ? resolveIdentifier(args[args.length - 1], scope) : undefined;
      const options = last && last.type === 'ObjectExpression' ? last : undefined;
      const shell = options && findProperty(options, 'shell');
      // running a shell executable (sh -c ..., cmd /c ...) is the same as { shell: true }
      const executable = constantValue(args[0], scope);
      const usesShell = (shell && literalValue(shell[1]) !== false) || SHELLS.test(String(executable || ''));
      usesShellFlag = usesShell;
      const argList = args[1] && resolveIdentifier(args[1], scope);
      const candidates = usesShell ? [args[0], ...(argList && argList.type === 'ArrayExpression' ? argList.elements : [argList])] : [args[0]];
      // with a shell every argument is interpreted; without one only the executable matters
      input = candidates.find(c => c && c.type !== 'SpreadElement' && constantValue(c, scope) === undefined) ||
        candidates.find(c => c && c.type === 'SpreadElement');
    } else return null;
    if (!input || constantValue(input, scope) !== undefined) return null;

    const fn = enclosingFunction(context.ancestors);
    const source = fn && untrustedSource(context.ancestors, fn);
    if (source && dependsOnParams(input, fn)) {
      return [finding(this, astNode, { severity: severity.HIGH, confidence: confidence.FIRM, manualReview: false,
        description: `${this.description} (${name} receives data from ${source})`, properties: { source } })];
    }
    // without a shell only the executable is dynamic, which is rarely attacker-controlled
    const throughShell = SHELL_COMMANDS.includes(name) || usesShellFlag;
    return [finding(this, astNode, { severity: throughShell ? severity.MEDIUM : severity.LOW, confidence: confidence.FIRM, manualReview: true,
      description: throughShell ? `${this.description} (${name} runs a dynamic command through a shell; make sure no untrusted data reaches it)`
        : `${this.description} (${name} starts a dynamic executable; review where the path comes from)` })];
  }
}
