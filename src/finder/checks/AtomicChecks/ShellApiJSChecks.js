import { sourceTypes } from '../../../parser/types.js';
import { severity } from '../../attributes.js';
import { memberName, calleeObjectName } from '../helpers.js';
import { assessUrlSink } from './OpenExternalJSCheck.js';

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
      // any constant path is the developer's choice, so only non-constant ones are rated
      const result = assessUrlSink(this, astNode, astNode.arguments[0], scope, context.ancestors, /^/, { trustPrefix: false });
      if (result && result.severity === severity.MEDIUM) result.severity = sev;
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
