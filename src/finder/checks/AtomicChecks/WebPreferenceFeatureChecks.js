import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { parseWebPreferencesFeaturesString } from '../../../util/index.js';
import { isWindowConstructor, webPreferencesOf, findProperty, literalValue, finding } from '../helpers.js';
import { electronAtLeast } from '../versions.js';

// webPreferences that increase the renderer attack surface when explicitly enabled
function featureChecks({ name, id, option, sev, reference, removedIn }) {
  const js = class {
    constructor() {
      this.id = `${id}_JS_CHECK`;
      this.description = __(`${id}_JS_CHECK`);
      this.type = sourceTypes.JAVASCRIPT;
      this.shortenedURL = reference;
    }

    match(astNode, astHelper, scope, defaults, electronVersion) {
      if (removedIn && electronAtLeast(electronVersion, removedIn)) return null;
      if (!isWindowConstructor(astNode)) return null;
      const prop = findProperty(webPreferencesOf(astNode, scope), option);
      if (!prop || literalValue(prop[1]) !== true) return null;
      return [finding(this, prop[2], { severity: sev, confidence: confidence.CERTAIN, manualReview: true })];
    }
  };

  const html = class {
    constructor() {
      this.id = `${id}_HTML_CHECK`;
      this.description = __(`${id}_JS_CHECK`);
      this.type = sourceTypes.HTML;
      this.shortenedURL = reference;
    }

    match(cheerioObj, content, defaults, electronVersion) {
      if (removedIn && electronAtLeast(electronVersion, removedIn)) return null;
      const issues = [];
      const self = this;
      cheerioObj('webview').each(function (i, elem) {
        const wp = cheerioObj(this).attr('webpreferences');
        if (wp && parseWebPreferencesFeaturesString(wp)[option] === true)
          issues.push({ line: content.substr(0, elem.startIndex).split('\n').length, column: 0, id: self.id, description: self.description, shortenedURL: self.shortenedURL, severity: sev, confidence: confidence.CERTAIN, manualReview: true });
      });
      return issues;
    }
  };

  Object.defineProperty(js, 'name', { value: `${name}JSCheck` });
  Object.defineProperty(html, 'name', { value: `${name}HTMLCheck` });
  return [js, html];
}

export const [WebGLJSCheck, WebGLHTMLCheck] = featureChecks({ name: 'WebGL', id: 'WEBGL', option: 'webgl', sev: severity.LOW,
  reference: 'https://www.electronjs.org/docs/latest/api/structures/web-preferences' });
// WebSQL support was removed in Electron 31
export const [WebSQLJSCheck, WebSQLHTMLCheck] = featureChecks({ name: 'WebSQL', id: 'WEBSQL', option: 'enableWebSQL', sev: severity.LOW, removedIn: '31.0.0',
  reference: 'https://www.electronjs.org/docs/latest/api/structures/web-preferences' });
export const [PluginsJSCheck, PluginsHTMLCheck] = featureChecks({ name: 'Plugins', id: 'PLUGINS', option: 'plugins', sev: severity.MEDIUM,
  reference: 'https://www.electronjs.org/docs/latest/api/structures/web-preferences' });
export const [NavigateOnDragDropJSCheck, NavigateOnDragDropHTMLCheck] = featureChecks({ name: 'NavigateOnDragDrop', id: 'NAVIGATE_ON_DRAG_DROP', option: 'navigateOnDragDrop', sev: severity.MEDIUM,
  reference: 'https://www.electronjs.org/docs/latest/api/structures/web-preferences' });
