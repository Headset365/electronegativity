import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, keyName, finding } from '../helpers.js';
import { constantValue, isCall } from '../analysis.js';

// Elements that run script or change where the page's resources and links resolve, and attributes that run script
const SCRIPT_TAGS = new Set(['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base', 'meta']);
const SCRIPT_ATTR = /^(on[a-z]+|srcdoc|formaction|xlink:href)$/i;
const ANGULAR_URL = 'https://docs.angularjs.org/api/ngSanitize/provider/$sanitizeProvider';

// A literal value: strings, booleans, numbers, arrays of them, and regular expressions ({ regex: RegExp })
function valueOf(node, scope) {
  if (!node) return undefined;
  if (node.type === 'RegExpLiteral' || (node.type === 'Literal' && node.regex)) {
    const { pattern, flags } = node.regex || node;
    try {
      return { regex: new RegExp(pattern, flags) };
    } catch {
      return undefined;
    }
  }
  if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'RegExp') {
    const source = constantValue(node.arguments[0], scope);
    try {
      return typeof source === 'string' ? { regex: new RegExp(source, constantValue(node.arguments[1], scope) || '') } : undefined;
    } catch {
      return undefined;
    }
  }
  if (node.type === 'ArrayExpression') return node.elements.map(element => valueOf(element, scope)).filter(v => v !== undefined);
  if (node.type === 'ObjectExpression') return node;
  if (node.type === 'BooleanLiteral' || (node.type === 'Literal' && typeof node.value === 'boolean')) return node.value;
  return constantValue(node, scope);
}

const strings = (value) => (Array.isArray(value) ? value : [value]).filter(v => typeof v === 'string').map(v => v.trim());
const dangerousTags = (value) => strings(value).filter(tag => SCRIPT_TAGS.has(tag.toLowerCase()));
const dangerousAttrs = (value) => strings(value).filter(attr => SCRIPT_ATTR.test(attr));
const acceptsScriptUrls = (value) => !!value && value.regex instanceof RegExp && value.regex.test('javascript:void(0)');

// TinyMCE / CKEditor 4 content rules: 'a[href|target],*[*]', 'script[src]', 'div[onclick]'
function tinyRuleProblems(rules) {
  const problems = [];
  for (const rule of strings(rules).flatMap(r => r.split(/[,;\s]+(?![^[]*\])/))) {
    const match = rule.match(/^[+#-]?([\w*:-]+)(?:\[([^\]]*)\])?/);
    if (!match) continue;
    const [, element, attributes = ''] = match;
    if (SCRIPT_TAGS.has(element.toLowerCase())) problems.push(`<${element}>`);
    const attributeList = attributes.split(/[|,\s]+/).map(a => a.replace(/^[!=:<>+-]+/, '').split(/[=:<]/)[0]).filter(Boolean);
    if (attributeList.includes('*')) problems.push(`${element}[*]`);
    attributeList.filter(a => SCRIPT_ATTR.test(a) || /^on/.test(a)).forEach(a => problems.push(`${element}[${a}]`));
  }
  return [...new Set(problems)];
}

// key -> (value, scope) => { severity, library, reason } | undefined. Keys are distinctive enough to identify the library
const RULES = {
  // DOMPurify
  ADD_TAGS: (v) => dangerousTags(v).length ? { severity: severity.HIGH, library: 'DOMPurify', reason: `adds ${dangerousTags(v).map(t => `<${t}>`).join(', ')}` } : undefined,
  ALLOWED_TAGS: (v) => dangerousTags(v).length ? { severity: severity.HIGH, library: 'DOMPurify', reason: `allows ${dangerousTags(v).map(t => `<${t}>`).join(', ')}` } : undefined,
  ADD_ATTR: (v) => dangerousAttrs(v).length ? { severity: severity.HIGH, library: 'DOMPurify', reason: `adds the ${dangerousAttrs(v).join(', ')} attribute` } : undefined,
  ALLOWED_ATTR: (v) => dangerousAttrs(v).length ? { severity: severity.HIGH, library: 'DOMPurify', reason: `allows the ${dangerousAttrs(v).join(', ')} attribute` } : undefined,
  ALLOW_UNKNOWN_PROTOCOLS: (v) => v === true ? { severity: severity.MEDIUM, library: 'DOMPurify', reason: 'keeps links with any URL scheme, including the app\'s own privileged schemes' } : undefined,
  ALLOWED_URI_REGEXP: (v) => acceptsScriptUrls(v) ? { severity: severity.HIGH, library: 'DOMPurify', reason: 'the URL pattern accepts javascript: URLs' } : undefined,
  // TinyMCE
  valid_elements: (v) => tinyRuleProblems(v).length ? { severity: severity.HIGH, library: 'TinyMCE', reason: `allows ${tinyRuleProblems(v).join(', ')}` } : undefined,
  extended_valid_elements: (v) => tinyRuleProblems(v).length ? { severity: severity.HIGH, library: 'TinyMCE', reason: `allows ${tinyRuleProblems(v).join(', ')}` } : undefined,
  allow_script_urls: (v) => v === true ? { severity: severity.HIGH, library: 'TinyMCE', reason: 'keeps javascript: URLs' } : undefined,
  xss_sanitization: (v) => v === false ? { severity: severity.HIGH, library: 'TinyMCE', reason: 'turns XSS sanitization off' } : undefined,
  verify_html: (v) => v === false ? { severity: severity.MEDIUM, library: 'TinyMCE', reason: 'stops filtering elements that are not in the schema' } : undefined,
  convert_unsafe_embeds: (v) => v === false ? { severity: severity.MEDIUM, library: 'TinyMCE', reason: 'keeps <object> and <embed> as they are' } : undefined,
  sandbox_iframes: (v) => v === false ? { severity: severity.MEDIUM, library: 'TinyMCE', reason: 'leaves iframes in content unsandboxed' } : undefined,
  // CKEditor 4 (allowedContent: true switches the Advanced Content Filter off) and CKEditor 5
  allowedContent: (v) => v === true ? { severity: severity.HIGH, library: 'CKEditor', reason: 'turns the Advanced Content Filter off' } : undefined,
  extraAllowedContent: (v) => tinyRuleProblems(v).length ? { severity: severity.HIGH, library: 'CKEditor', reason: `allows ${tinyRuleProblems(v).join(', ')}` } : undefined,
  htmlEmbed: (v) => {
    if (!v || v.type !== 'ObjectExpression') return undefined;
    const keys = new Map(v.properties.filter(p => p.key).map(p => [keyName(p.key), p.value]));
    const previews = keys.get('showPreviews');
    const shows = previews && (previews.value === true);
    return shows && !keys.has('sanitizeHtml') ? { severity: severity.HIGH, library: 'CKEditor', reason: 'renders embedded HTML previews without a sanitizeHtml function' } : undefined;
  },
  // Froala
  htmlExecuteScripts: (v) => v === true ? { severity: severity.HIGH, library: 'Froala', reason: 'runs scripts in the content' } : undefined,
  htmlUntouched: (v) => v === true ? { severity: severity.HIGH, library: 'Froala', reason: 'keeps the HTML as it is, without cleaning' } : undefined,
  htmlRemoveTags: (v) => Array.isArray(v) && !strings(v).includes('script') ? { severity: severity.HIGH, library: 'Froala', reason: 'no longer removes <script>' } : undefined,
  htmlAllowedTags: (v) => strings(v).some(t => t === '.*' || SCRIPT_TAGS.has(t)) ? { severity: severity.HIGH, library: 'Froala', reason: `allows ${strings(v).filter(t => t === '.*' || SCRIPT_TAGS.has(t)).join(', ')}` } : undefined,
  htmlAllowedAttrs: (v) => strings(v).some(a => a === '.*' || SCRIPT_ATTR.test(a)) ? { severity: severity.HIGH, library: 'Froala', reason: `allows ${strings(v).filter(a => a === '.*' || SCRIPT_ATTR.test(a)).join(', ')}` } : undefined,
  // Summernote
  codeviewFilter: (v) => v === false ? { severity: severity.MEDIUM, library: 'Summernote', reason: 'does not filter markup typed in code view' } : undefined,
};

// AngularJS $sanitizeProvider / $compileProvider settings
const ANGULAR_CALLS = {
  addValidElements: (args, scope) => {
    const tags = args.flatMap(a => { const v = valueOf(a, scope); return v && v.type === 'ObjectExpression' ? v.properties.flatMap(p => strings(valueOf(p.value, scope))) : strings(v); });
    const bad = tags.filter(t => SCRIPT_TAGS.has(t.toLowerCase()));
    return bad.length ? { severity: severity.HIGH, reason: `adds ${bad.map(t => `<${t}>`).join(', ')}` } : undefined;
  },
  addValidAttrs: (args, scope) => {
    const attrs = args.flatMap(a => strings(valueOf(a, scope)));
    if (dangerousAttrs(attrs).length) return { severity: severity.HIGH, reason: `adds the ${dangerousAttrs(attrs).join(', ')} attribute` };
    // style is left out of the defaults on purpose: it allows CSS injection (overlaying the UI, exfiltrating via url())
    return attrs.includes('style') ? { severity: severity.MEDIUM, reason: 'adds the style attribute' } : undefined;
  },
  enableSvg: (args) => args[0] && valueOf(args[0]) === true ? { severity: severity.LOW, reason: 'allows SVG, which the AngularJS documentation warns can be used to overlay the UI' } : undefined,
};
const URL_LISTS = /^(aHrefSanitization(Whitelist|TrustedUrlList)|imgSrcSanitization(Whitelist|TrustedUrlList))$/;

/**
 * Configuration that weakens an HTML sanitizer or a rich-text editor's content filter: DOMPurify options and hooks,
 * AngularJS $sanitize/$compile settings, TinyMCE, CKEditor, Froala and Summernote options. The client-side filter is
 * what stands between stored content and the page, so settings that let script through undo it.
 */
export default class SanitizerConfigJSCheck {
  constructor() {
    this.id = "SANITIZER_CONFIG_JS_CHECK";
    this.description = __("SANITIZER_CONFIG_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#html-sanitization";
  }

  match(astNode, astHelper, scope) {
    const report = (node, problem, library, url) => {
      const result = finding(this, node, { severity: problem.severity, confidence: confidence.CERTAIN, manualReview: true,
        description: `${this.description} (${library}: ${problem.reason})` });
      if (url) result.shortenedURL = url;
      return result;
    };

    // { ADD_ATTR: ['onclick'] }, tinymce.init({ valid_elements: '*[*]' }), $scope.tinymceOptions = { ... }
    if (astNode.type === 'ObjectExpression') {
      const results = [];
      for (const property of astNode.properties) {
        const key = property.key && keyName(property.key);
        if (!key || !Object.hasOwn(RULES, key)) continue;
        const problem = RULES[key](valueOf(property.value, scope), scope);
        if (problem) results.push(report(property, problem, problem.library));
      }
      return results.length ? results : null;
    }

    if (astNode.type === 'AssignmentExpression' && astNode.operator === '=') {
      const key = memberName(astNode.left);
      // DOMPurify hook: data.forceKeepAttr = true keeps an attribute whatever it contains
      if (key === 'forceKeepAttr' && valueOf(astNode.right, scope) === true) {
        return [report(astNode, { severity: severity.HIGH, reason: 'a hook forces attributes to be kept' }, 'DOMPurify')];
      }
      // CKEDITOR.editorConfig = function (config) { config.allowedContent = true; }
      if (key && Object.hasOwn(RULES, key) && (astNode.left.type === 'MemberExpression' || astNode.left.type === 'OptionalMemberExpression')) {
        const problem = RULES[key](valueOf(astNode.right, scope), scope);
        return problem ? [report(astNode, problem, problem.library)] : null;
      }
      return null;
    }

    if (isCall(astNode) && astNode.type !== 'NewExpression') {
      const method = memberName(astNode.callee);
      if (method && Object.hasOwn(ANGULAR_CALLS, method)) {
        const problem = ANGULAR_CALLS[method](astNode.arguments, scope);
        return problem ? [report(astNode, problem, 'AngularJS $sanitize', ANGULAR_URL)] : null;
      }
      // $compileProvider.aHrefSanitizationTrustedUrlList(/.*/) lets javascript: links through ng-href and ng-bind-html
      if (method && URL_LISTS.test(method) && astNode.arguments.length > 0 && acceptsScriptUrls(valueOf(astNode.arguments[0], scope))) {
        return [report(astNode, { severity: severity.HIGH, reason: `${method}() accepts javascript: URLs` }, 'AngularJS $compile', 'https://docs.angularjs.org/api/ng/provider/$compileProvider')];
      }
    }
    return null;
  }
}
