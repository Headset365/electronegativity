import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, calleeObjectName, finding } from '../helpers.js';
import { constantValue, isCall } from '../analysis.js';
import { isServerFed, inServerContext } from '../html.js';

const ANGULAR_URL = "https://docs.angularjs.org/api/ng/service/$sce";

// Whether the value handed to a sink is dynamic (not a static, developer-controlled constant) and, if so, whether it
// comes from the server. Returns undefined for a constant (nothing to flag) or { serverFed } otherwise.
function assess(value, scope, context) {
  if (!value || constantValue(value, scope) !== undefined) return undefined;
  return { serverFed: isServerFed(value, scope) || inServerContext(context && context.ancestors) };
}

/**
 * AngularJS bypasses of Strict Contextual Escaping and template compilation of dynamic data:
 *   $sce.trustAsHtml(x), $sce.trustAs($sce.HTML, x), $sceDelegate.trustAs('html', x)
 *   $compile(x)(scope), $interpolate(x), $parse(x) built from data the app doesn't control.
 * Trusting or compiling server-controlled markup gives it the privileges of the AngularJS application.
 */
export class AngularTrustHtmlJSCheck {
  constructor() {
    this.id = "ANGULAR_TRUST_HTML_JS_CHECK";
    this.description = __("ANGULAR_TRUST_HTML_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = ANGULAR_URL;
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context) {
    if (!isCall(astNode) || astNode.type === 'NewExpression') return null;
    const method = memberName(astNode.callee);
    const object = calleeObjectName(astNode.callee);
    let value;
    let api;
    // $sce.trustAsHtml(x) / $sceDelegate.trustAsHtml(x)
    if (method === 'trustAsHtml' && /^\$sce(Delegate)?$/.test(object || '')) { value = astNode.arguments[0]; api = `${object}.trustAsHtml`; }
    // $sce.trustAs($sce.HTML, x) — first argument names the context
    else if (method === 'trustAs' && /^\$sce(Delegate)?$/.test(object || '')) {
      const type = astNode.arguments[0];
      const typeName = constantValue(type, scope) ?? (type && memberName(type));
      if (String(typeName).toLowerCase() === 'html') { value = astNode.arguments[1]; api = `${object}.trustAs(HTML)`; }
    }
    // $compile(x)(scope), $interpolate(x), $parse(x): AngularJS compiles the markup/expression string
    else if (astNode.callee.type === 'Identifier' && ['$compile', '$interpolate', '$parse'].includes(astNode.callee.name)) {
      value = astNode.arguments[0]; api = astNode.callee.name;
    }
    if (!api) return null;
    const verdict = assess(value, scope, context);
    if (!verdict) return null;
    return [finding(this, astNode, { severity: verdict.serverFed ? severity.HIGH : severity.MEDIUM, confidence: confidence.FIRM, manualReview: true,
      description: `${this.description} (${api} with ${verdict.serverFed ? 'server-controlled data' : 'a dynamic value'})`, properties: { api, serverFed: verdict.serverFed } })];
  }
}

// Rich-text editor APIs that load an HTML string into the editor, by editor: any of these method names with a dynamic
// argument means untrusted markup could be rendered. Method names are matched loosely, so confidence stays TENTATIVE.
const EDITOR_METHODS = {
  setData: 'CKEditor',                 // editor.setData(html)
  setContent: 'TinyMCE',               // editor.setContent(html) / tinymce.activeEditor.setContent(html)
  insertContent: 'TinyMCE',            // editor.insertContent(html)
  dangerouslyPasteHTML: 'Quill',       // quill.clipboard.dangerouslyPasteHTML(html)
  pasteHTML: 'Quill/CKEditor',         // range.pasteHTML(html)
};

/**
 * HTML loaded into a rich-text editor (TinyMCE, CKEditor, Quill, Froala, Summernote). Editors render the HTML they are
 * given; markup from the server must be sanitized on the server, not only in the editor, before it reaches another user.
 */
export class RichTextEditorHtmlJSCheck {
  constructor() {
    this.id = "RICH_TEXT_EDITOR_JS_CHECK";
    this.description = __("RICH_TEXT_EDITOR_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context) {
    if (!isCall(astNode) || astNode.type === 'NewExpression') return null;
    const method = memberName(astNode.callee);
    let editor;
    let value;
    if (method && Object.hasOwn(EDITOR_METHODS, method) && astNode.arguments.length >= 1) {
      editor = EDITOR_METHODS[method]; value = astNode.arguments[0];
    }
    // Froala: editor.html.set(html) / .html.insert(html)
    else if ((method === 'set' || method === 'insert') && calleeObjectName(astNode.callee) === 'html' && astNode.arguments.length >= 1) {
      editor = 'Froala'; value = astNode.arguments[0];
    }
    // Summernote: $(...).summernote('code', html) / ('pasteHTML', html)
    else if (method === 'summernote' && ['code', 'pasteHTML'].includes(constantValue(astNode.arguments[0], scope)) && astNode.arguments.length >= 2) {
      editor = 'Summernote'; value = astNode.arguments[1];
    }
    if (!editor) return null;
    const verdict = assess(value, scope, context);
    if (!verdict) return null;
    return [finding(this, astNode, { severity: verdict.serverFed ? severity.HIGH : severity.MEDIUM, confidence: verdict.serverFed ? confidence.FIRM : confidence.TENTATIVE, manualReview: true,
      description: `${this.description} (${editor}: ${method}() with ${verdict.serverFed ? 'server-controlled data' : 'a dynamic value'})`, properties: { editor, method, serverFed: verdict.serverFed } })];
  }
}

// AngularJS ng-bind-html-unsafe (and its data- form) renders its expression as raw HTML with no escaping at all
const UNSAFE_ATTRS = ['ng-bind-html-unsafe', 'data-ng-bind-html-unsafe', 'x-ng-bind-html-unsafe'];

export class AngularBindHtmlUnsafeHTMLCheck {
  constructor() {
    this.id = "ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK";
    this.description = __("ANGULAR_BIND_HTML_UNSAFE_HTML_CHECK");
    this.type = sourceTypes.HTML;
    this.shortenedURL = ANGULAR_URL;
  }

  match(cheerioObj, content) {
    const locations = [];
    const self = this;
    cheerioObj('*').each(function (i, elem) {
      const attr = UNSAFE_ATTRS.find(name => cheerioObj(this).attr(name) !== undefined);
      if (!attr) return;
      locations.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: `${self.description} (${attr})`,
        shortenedURL: self.shortenedURL, severity: severity.HIGH, confidence: confidence.FIRM, manualReview: true });
    });
    return locations;
  }
}
