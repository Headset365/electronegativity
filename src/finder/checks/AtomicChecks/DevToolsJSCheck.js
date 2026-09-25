import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, finding } from '../helpers.js';
import { identifiersIn, isConditional, visit, isMember } from '../analysis.js';

// Conditions that restrict code to development builds
const DEV_ONLY = /(^|[^a-z])(is_?dev|dev(elopment|mode)?|debug|packaged|isPackaged|NODE_ENV|electron-is-dev|VITE_DEV_SERVER_URL|MAIN_WINDOW_VITE_DEV_SERVER_URL|DEV_SERVER)/i;

// DevTools left reachable in production builds give full control over the renderer (and the IPC it can reach)
export default class DevToolsJSCheck {
  constructor() {
    this.id = "DEVTOOLS_JS_CHECK";
    this.description = __("DEVTOOLS_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/api/web-contents#contentsopendevtoolsoptions";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'CallExpression' && astNode.type !== 'OptionalCallExpression') return null;
    const method = memberName(astNode.callee);
    if (!['openDevTools', 'toggleDevTools', 'setDevToolsWebContents'].includes(method)) return null;

    const ancestors = context.ancestors;
    // look at every condition guarding the call, up to the top of the file
    if (isConditional(astNode, ancestors, null)) {
      if (guards(astNode, ancestors).some(test => DEV_ONLY.test(test))) return null; // development builds only
      return [finding(this, astNode, { severity: severity.LOW, confidence: confidence.FIRM, manualReview: true,
        description: `${this.description} (opened under a condition that doesn't look development-only)` })];
    }
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: confidence.CERTAIN, manualReview: false,
      description: `${this.description} (always opened, including in production builds)` })];
  }
}

// Text of the conditions (if tests, ternaries, `&&` left sides) that guard a node
function guards(node, ancestors) {
  const chain = [...ancestors, node];
  const tests = [];
  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i];
    const child = chain[i + 1];
    let test;
    if ((parent.type === 'IfStatement' || parent.type === 'ConditionalExpression') && child !== parent.test) test = parent.test;
    if (parent.type === 'LogicalExpression' && child === parent.right) test = parent.left;
    if (parent.type === 'BlockStatement' || parent.type === 'Program') {
      const index = parent.body.indexOf(child);
      parent.body.slice(0, index).filter(s => s.type === 'IfStatement').forEach(s => tests.push(describe(s.test)));
    }
    if (test) tests.push(describe(test));
  }
  return tests;
}

function describe(test) {
  const parts = [...identifiersIn(test)];
  visit(test, (n) => {
    if (isMember(n)) parts.push(memberName(n));
    if (typeof n.value === 'string') parts.push(n.value);
    return true;
  });
  return parts.join(' ');
}
