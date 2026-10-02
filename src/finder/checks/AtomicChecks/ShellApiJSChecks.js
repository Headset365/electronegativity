import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { constantValue } from '../analysis.js';
import { memberName, calleeObjectName } from '../helpers.js';
import { assessUrlSink } from './OpenExternalJSCheck.js';

// writeShortcutLink options whose target is the app's own executable (or a constant) and whose arguments are constant
function fixedShortcut(options, scope) {
  if (!options || options.type !== 'ObjectExpression') return false;
  const value = (name) => { const p = options.properties.find(prop => prop.type !== 'SpreadElement' && (prop.key.name === name || prop.key.value === name)); return p && p.value; };
  const target = value('target');
  const own = target && ((target.type === 'MemberExpression' && target.object.name === 'process' && memberName(target) === 'execPath')
    || (target.type === 'CallExpression' && memberName(target.callee) === 'getPath' && constantValue(target.arguments[0], scope) === 'exe') || constantValue(target, scope) !== undefined);
  const args = value('args');
  return !!own && (!args || constantValue(args, scope) !== undefined);
}

// shell APIs that act on paths: passing attacker-influenced values can execute files or plant shortcuts
function shellCallCheck({ className, id, methods, sev, reference }) {
  const cls = class {
    constructor() {
      this.id = id;
      this.description = __(id);
      this.type = sourceTypes.JAVASCRIPT;
      this.shortenedURL = reference;
    }

    match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
      if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
      if (!methods.includes(memberName(astNode.callee)) || calleeObjectName(astNode.callee) !== 'shell') return null;
      if (astNode.arguments.length === 0) return null;
      // a shortcut to the app itself with fixed arguments (target: process.execPath, args: '--quick-calc'): what it runs
      // is the developer's choice, wherever the shortcut is written
      if (methods.includes('writeShortcutLink') && fixedShortcut(astNode.arguments[astNode.arguments.length - 1], scope))
        return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, shortenedURL: this.shortenedURL,
          description: `${this.description} (a shortcut to the application itself, with fixed arguments)`, severity: severity.INFORMATIONAL, confidence: confidence.FIRM, manualReview: false }];
      // any constant path is the developer's choice, so only non-constant ones are rated
      const result = assessUrlSink(this, astNode, astNode.arguments[0], scope, context.ancestors, /^/, { trustPrefix: false });
      if (result && (result.severity === severity.MEDIUM || (result.severity === severity.HIGH && sev === severity.LOW))) result.severity = sev;
      return result ? [result] : null;
    }
  };
  Object.defineProperty(cls, 'name', { value: className });
  return cls;
}

export const OpenPathJSCheck = shellCallCheck({ className: 'OpenPathJSCheck', id: 'OPEN_PATH_JS_CHECK', methods: ['openPath', 'openItem'], sev: severity.MEDIUM,
  reference: 'https://www.electronjs.org/docs/latest/api/shell#shellopenpathpath' });
export const ShowItemInFolderJSCheck = shellCallCheck({ className: 'ShowItemInFolderJSCheck', id: 'SHOWITEMINFOLDER_JS_CHECK', methods: ['showItemInFolder'], sev: severity.LOW,
  reference: 'https://www.electronjs.org/docs/latest/api/shell#shellshowiteminfolderfullpath' });
export const WriteShortcutJSCheck = shellCallCheck({ className: 'WriteShortcutJSCheck', id: 'WRITE_SHORTCUT_JS_CHECK', methods: ['writeShortcutLink'], sev: severity.MEDIUM,
  reference: 'https://www.electronjs.org/docs/latest/api/shell#shellwriteshortcutlinkshortcutpath-operation-options-windows' });
