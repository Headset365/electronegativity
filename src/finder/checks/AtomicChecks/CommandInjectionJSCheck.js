import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, findProperty, literalValue, finding, resolveIdentifier } from '../helpers.js';
import { constantValue, enclosingFunction, untrustedSource, dependsOnParams } from '../analysis.js';

// child_process functions that run their input through a shell
const SHELL_COMMANDS = ['exec', 'execSync'];
const PROCESS_COMMANDS = ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'];
const SHELLS = /(^|[\\/])(sh|bash|zsh|dash|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)$/i;

// Command injection in the main process gives code execution on the user's machine
export default class CommandInjectionJSCheck {
  constructor() {
    this.id = "COMMAND_INJECTION_JS_CHECK";
    this.description = __("COMMAND_INJECTION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://nodejs.org/api/child_process.html#spawning-shell-scripts";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression') return null;
    const name = astNode.callee.type === 'Identifier' ? astNode.callee.name : memberName(astNode.callee);
    const objectName = astNode.callee.object && astNode.callee.object.type === 'Identifier' ? astNode.callee.object.name : undefined;
    // `exec` is a common name, only consider child_process-looking calls
    if (objectName && !/^(child_?process|cp|childProcess|proc)$/i.test(objectName)) return null;
    const args = astNode.arguments;
    if (args.length === 0) return null;

    let input;
    if (SHELL_COMMANDS.includes(name)) input = args[0];
    else if (PROCESS_COMMANDS.includes(name)) {
      // spawn(command, [args], options): the options object is the last argument after the command
      const last = args.length > 1 ? resolveIdentifier(args[args.length - 1], scope) : undefined;
      const options = last && last.type === 'ObjectExpression' ? last : undefined;
      const shell = options && findProperty(options, 'shell');
      // running a shell executable (sh -c ..., cmd /c ...) is the same as { shell: true }
      const executable = constantValue(args[0], scope);
      const usesShell = (shell && literalValue(shell[1]) !== false) || SHELLS.test(String(executable || ''));
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
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} (${name} with a dynamic command; make sure no untrusted data reaches it)` })];
  }
}
