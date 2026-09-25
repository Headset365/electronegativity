import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { electronAtLeast, ELECTRON_CHANGES } from '../versions.js';

export default class LimitNavigationJSCheck {
  constructor() {
    this.id = "LIMIT_NAVIGATION_JS_CHECK";
    this.description = __("LIMIT_NAVIGATION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/JeuM3";
  }

  match(astNode, astHelper, scope, defaults, electronVersion){

    if (astNode.type !== 'CallExpression') return null;
    if (astNode.callee.property && astNode.callee.property.name === "on") {
      if (astNode.arguments && astNode.arguments.length > 1) {
        var eventValue = astNode.arguments[0].value;
        if (astNode.arguments[0].type === astHelper.StringLiteral && eventValue === "new-window" && electronAtLeast(electronVersion, ELECTRON_CHANGES.NEW_WINDOW_EVENT_REMOVED)) {
          // the event no longer fires, so it doesn't limit anything
          return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, title: this.title, description: __("LIMIT_NAVIGATION_JS_CHECK_NEW_WINDOW_REMOVED"), shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.CERTAIN, properties: { "event" : "new-window-removed" }, manualReview: false }];
        }
        if (astNode.arguments[0].type === astHelper.StringLiteral && (eventValue === "will-navigate" || eventValue === "will-frame-navigate" || eventValue === "new-window")) {
          return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, title: this.title, description: this.description, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.TENTATIVE, properties: { "event" : eventValue }, manualReview: true }];
        }
      }
    } else if (astNode.callee.property && astNode.callee.property.name === "setWindowOpenHandler") {
      return [{ line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, title: this.title, description: this.description, shortenedURL: this.shortenedURL, severity: severity.HIGH, confidence: confidence.TENTATIVE, properties: { "event" : "setWindowOpenHandler" }, manualReview: true }];
    }
  }

}
