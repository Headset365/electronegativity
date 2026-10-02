import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { finding, memberName, keyName, visit } from '../helpers.js';
import { constantValue, isCall, enclosingFunction } from '../analysis.js';

const URL = "https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#sandbox";

// compiled JSX element factories
const COMPILED_JSX = new Set(['jsx', 'jsxs', '_jsx', '_jsxs', 'jsxDEV', 'h']);

// With both flags the framed page can remove its own sandbox, so it is as good as none
const isEffective = (sandbox) => !(/\ballow-scripts\b/i.test(sandbox) && /\ballow-same-origin\b/i.test(sandbox));

// Frames showing documents or user content without the sandbox attribute can script the embedding page, and through it
// reach preload APIs or, with nodeIntegration, Node.js itself (e.g. Joplin's note viewer, CVE-2022-35131)
function assess(sandbox) {
  if (sandbox === undefined) return 'the iframe has no sandbox attribute';
  if (typeof sandbox === 'string' && !isEffective(sandbox)) return 'sandbox allows both allow-scripts and allow-same-origin, which lets the frame remove it';
  return undefined;
}

export class IframeSandboxHTMLCheck {
  constructor() {
    this.id = "IFRAME_SANDBOX_HTML_CHECK";
    this.description = __("IFRAME_SANDBOX_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = URL;
  }

  match(cheerioObj, content) {
    const locations = [];
    const self = this;
    cheerioObj('iframe').each(function (i, elem) {
      const problem = assess(cheerioObj(this).attr('sandbox'));
      if (problem) locations.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: `${self.description} (${problem})`,
        shortenedURL: self.shortenedURL, severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true });
    });
    return locations;
  }
}

// <iframe src={...} /> in React and other JSX renderers
export class IframeSandboxJSCheck {
  constructor() {
    this.id = "IFRAME_SANDBOX_JS_CHECK";
    this.description = __("IFRAME_SANDBOX_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = URL;
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context) {
    // compiled code: jsx("iframe", props) / React.createElement("iframe", props), and document.createElement("iframe")
    if (isCall(astNode) && astNode.type !== 'NewExpression') return this.compiled(astNode, scope, context);
    if (astNode.type !== 'JSXOpeningElement' || !astNode.name || astNode.name.name !== 'iframe') return null;
    // {...props} may carry the attribute
    if (astNode.attributes.some(a => a.type === 'JSXSpreadAttribute')) return null;
    const attribute = astNode.attributes.find(a => a.name && a.name.name === 'sandbox');
    let sandbox;
    if (attribute) {
      const value = attribute.value && (attribute.value.type === 'JSXExpressionContainer' ? attribute.value.expression : attribute.value);
      sandbox = value ? constantValue(value, scope) : '';
      if (sandbox === undefined) return null; // dynamic, can't tell
    }
    const problem = assess(sandbox);
    return problem ? [finding(this, astNode, { severity: severity.LOW, confidence: confidence.CERTAIN, manualReview: true, description: `${this.description} (${problem})` })] : null;
  }

  // an iframe made in compiled code, and what it is given to show: srcdoc (a document in the window's own origin) or src
  compiled(astNode, scope, context) {
    const callee = astNode.callee;
    const name = callee.type === 'Identifier' ? callee.name : memberName(callee);
    if (constantValue(astNode.arguments[0], scope) !== 'iframe') return null;
    // jsx("iframe", { src, sandbox }) and createElement("iframe", { srcDoc })
    const props = astNode.arguments[1];
    // (document.createElement takes at most an { is } options object; React.createElement takes the props)
    const reactProps = name === 'createElement' && props && props.type === 'ObjectExpression' && !props.properties.some(p => keyName(p.key) === 'is');
    if ((COMPILED_JSX.has(name) || reactProps) && props && props.type === 'ObjectExpression') {
      if (props.properties.some(p => p.type === 'SpreadElement' || p.type === 'SpreadProperty')) return null;
      const property = (key) => props.properties.find(p => new RegExp(`^${key}$`, 'i').test(keyName(p.key) || ''));
      const sandbox = property('sandbox');
      const value = sandbox ? constantValue(sandbox.value, scope) : undefined;
      if (sandbox && value === undefined) return null; // dynamic, can't tell
      const problem = assess(sandbox ? value : undefined);
      const content = property('srcdoc') ? 'srcdoc' : property('src') ? 'src' : undefined;
      return problem ? [this.compiledFinding(astNode, problem, content)] : null;
    }
    // const frame = document.createElement("iframe"); frame.srcdoc = html; (no frame.sandbox / setAttribute("sandbox"))
    if (name !== 'createElement') return null;
    const ancestors = (context && context.ancestors) || [];
    const parent = ancestors[ancestors.length - 1];
    const variable = parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier' ? parent.id.name
      : parent && parent.type === 'AssignmentExpression' && parent.left.type === 'Identifier' ? parent.left.name : undefined;
    const body = enclosingFunction(ancestors) || ancestors[0];
    if (!variable || !body) return null;
    let sandbox;
    let dynamicSandbox = false;
    let content;
    const on = (node) => node && node.type === 'Identifier' && node.name === variable;
    visit(body, (node) => {
      if (node.type === 'AssignmentExpression' && (node.left.type === 'MemberExpression') && on(node.left.object)) {
        const property = memberName(node.left);
        if (property === 'sandbox') { const v = constantValue(node.right, scope); if (v === undefined) dynamicSandbox = true; else sandbox = v; }
        if (property === 'srcdoc') content = 'srcdoc';
        else if (property === 'src' && !content) content = 'src';
      }
      if (isCall(node) && node.callee.type === 'MemberExpression') {
        const method = memberName(node.callee);
        // frame.setAttribute("sandbox", v), frame.sandbox.add(...)
        if (method === 'setAttribute' && on(node.callee.object)) {
          const attribute = String(constantValue(node.arguments[0], scope)).toLowerCase();
          if (attribute === 'sandbox') { const v = constantValue(node.arguments[1], scope); if (v === undefined) dynamicSandbox = true; else sandbox = v; }
          if (attribute === 'srcdoc') content = 'srcdoc';
          else if (attribute === 'src' && !content) content = 'src';
        }
        if (['add', 'value'].includes(method) && node.callee.object.type === 'MemberExpression' && memberName(node.callee.object) === 'sandbox' && on(node.callee.object.object)) dynamicSandbox = true;
      }
    });
    if (dynamicSandbox || !content) return null;
    const problem = assess(sandbox);
    return problem ? [this.compiledFinding(astNode, problem, content)] : null;
  }

  compiledFinding(astNode, problem, content) {
    // a srcdoc document has the window's origin: without a sandbox it can reach everything the window can
    const sameOrigin = content === 'srcdoc';
    return finding(this, astNode, { severity: sameOrigin ? severity.MEDIUM : severity.LOW, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} (${problem}; created in code${content ? `, content set through ${content}` : ''}${sameOrigin ? ', so the frame shares the window’s origin' : ''})`,
      properties: { content, sameOrigin } });
  }
}
