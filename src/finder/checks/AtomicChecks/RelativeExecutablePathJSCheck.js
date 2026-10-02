// Programs and scripts named by a path relative to the working directory:
//   ADODB.PATH = './resources/adodb.js'      (node-adodb runs it with cscript)
//   spawn('./bin/helper.exe', args)
// The working directory is wherever the app was started from: a shortcut's "Start in", a document opened through a file
// association, another program that launched it. A file of the same name planted there runs instead of the shipped one.
import path from 'node:path';
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { isCall, moduleBindings, programOf, constantValue } from '../analysis.js';

const SPAWNERS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork', 'exec', 'execSync']);
const CHILD_PROCESS = /^(node:)?child_process$/;
// properties that name a program or script another library starts: ADODB.PATH, execa's cwd-less binPath, binaryPath
const PROGRAM_PROPERTY = /^(?:PATH|(?:exe|exec|bin|binary|executable|script|cli|tool|helper|cscript|wscript)Path)$/i;
const PROGRAM_FILE = /\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|wsh|sh|py|dll)$/i;

// relative: ./x, .\x, ../x, or a bare folder path (resources/x.js); not absolute, not a bare command name looked up on PATH
const relative = (value) => typeof value === 'string' && !path.isAbsolute(value) && !/^[a-z]:[\\/]/i.test(value) && !/^\\\\/.test(value)
  && (/^\.{1,2}[\\/]/.test(value) || /[\\/]/.test(value));

function childProcessCall(call, ancestors) {
  const callee = call.callee;
  const name = callee.type === 'Identifier' ? callee.name : memberName(callee);
  if (!SPAWNERS.has(name)) return undefined;
  const program = programOf(ancestors);
  const bindings = program ? moduleBindings(program) : new Map();
  const binding = callee.type === 'Identifier' ? bindings.get(callee.name) : callee.object && callee.object.type === 'Identifier' ? bindings.get(callee.object.name) : undefined;
  return binding && CHILD_PROCESS.test(binding.module || '') ? name : undefined;
}

export default class RelativeExecutablePathJSCheck {
  constructor() {
    this.id = 'RELATIVE_EXECUTABLE_PATH_JS_CHECK';
    this.description = __('RELATIVE_EXECUTABLE_PATH_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://cwe.mitre.org/data/definitions/427.html';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    // ADODB.PATH = './resources/adodb.js'
    if (astNode.type === 'AssignmentExpression' && astNode.left && (astNode.left.type === 'MemberExpression' || astNode.left.type === 'OptionalMemberExpression')) {
      const property = memberName(astNode.left);
      const value = constantValue(astNode.right, scope);
      if (!PROGRAM_PROPERTY.test(property || '') || !relative(value) || !PROGRAM_FILE.test(value)) return null;
      return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { path: value, property },
        description: `${this.description}: ${property} is set to '${value}', resolved against the working directory the app was started in; build it from process.resourcesPath or __dirname` })];
    }
    // spawn('./bin/helper.exe') and the like
    if (isCall(astNode) && astNode.type !== 'NewExpression' && astNode.arguments.length) {
      const name = childProcessCall(astNode, context.ancestors);
      if (!name) return null;
      const value = constantValue(astNode.arguments[0], scope);
      const program = typeof value === 'string' ? (/^exec(Sync)?$/.test(name) ? value.trim().split(/\s+/)[0].replace(/^["']|["']$/g, '') : value) : undefined;
      if (!relative(program)) return null;
      return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { path: program, call: name },
        description: `${this.description}: ${name} starts '${program}', resolved against the working directory the app was started in; build the path from process.resourcesPath or __dirname` })];
    }
    return null;
  }
}
