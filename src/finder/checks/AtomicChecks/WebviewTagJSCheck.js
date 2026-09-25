import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, isWindowConstructor, webPreferencesOf, findProperty, literalValue, finding } from '../helpers.js';

// Electron security checklist #12: verify WebView options before creation
export default class WebviewTagJSCheck {
  constructor() {
    this.id = "WEBVIEW_TAG_JS_CHECK";
    this.description = __("WEBVIEW_TAG_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#12-verify-webview-options-before-creation";
  }

  match(astNode, astHelper, scope) {
    if (isWindowConstructor(astNode)) {
      // <webview> is disabled by default since Electron 5, only explicit opt-ins are reported
      const prefs = webPreferencesOf(astNode, scope);
      const webviewTag = prefs && findProperty(prefs, 'webviewTag');
      if (!webviewTag || literalValue(webviewTag[1]) === false) return null;
      return [finding(this, webviewTag[2], { severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, properties: { event: 'webviewTag' } })];
    }

    // contents.on('will-attach-webview', ...) hardens the options of every <webview>
    if ((astNode.type === 'CallExpression' || astNode.type === 'OptionalCallExpression') &&
        ['on', 'once', 'addListener'].includes(memberName(astNode.callee)) &&
        astNode.arguments.length > 1 && literalValue(astNode.arguments[0]) === 'will-attach-webview') {
      return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: confidence.CERTAIN, manualReview: true,
        description: __("WEBVIEW_TAG_JS_CHECK_WILL_ATTACH"), properties: { event: 'will-attach-webview' } })];
    }
    return null;
  }
}
