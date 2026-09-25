import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { electronAtLeast, ELECTRON_CHANGES } from '../versions.js';
import { memberName, findProperty, literalValue } from '../helpers.js';
import { handlerFunction, callsIn, isConditional, hasUrlValidation, returnedValues } from '../analysis.js';

const NAVIGATION_EVENTS = ['will-navigate', 'will-frame-navigate', 'new-window'];

// Electron security checklist #13 and #14: disable or limit navigation and the creation of new windows
export default class LimitNavigationJSCheck {
  constructor() {
    this.id = "LIMIT_NAVIGATION_JS_CHECK";
    this.description = __("LIMIT_NAVIGATION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#13-disable-or-limit-navigation";
  }

  match(astNode, astHelper, scope, defaults, electronVersion) {
    if (astNode.type !== 'CallExpression') return null;
    const method = memberName(astNode.callee);
    const report = (event, sev, conf, reason, manualReview = true) => [{
      line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id,
      description: reason ? `${this.description}: ${reason}` : this.description, shortenedURL: this.shortenedURL,
      severity: sev, confidence: conf, properties: { event }, manualReview
    }];

    if (method === 'on' && astNode.arguments.length > 1) {
      const event = literalValue(astNode.arguments[0]);
      if (!NAVIGATION_EVENTS.includes(event)) return null;

      if (event === 'new-window' && electronAtLeast(electronVersion, ELECTRON_CHANGES.NEW_WINDOW_EVENT_REMOVED)) {
        // the event no longer fires, so it doesn't limit anything
        return [{ ...report('new-window-removed', severity.HIGH, confidence.CERTAIN, '', false)[0], description: __("LIMIT_NAVIGATION_JS_CHECK_NEW_WINDOW_REMOVED") }];
      }

      const fn = handlerFunction(astNode.arguments[1], scope);
      if (!fn) return report(event, severity.MEDIUM, confidence.TENTATIVE, `the ${event} handler is defined elsewhere; review it`);

      const blocks = callsIn(fn, (call, name) => name === 'preventDefault');
      if (blocks.length === 0)
        // doesn't count as a limit for LimitNavigationGlobalCheck
        return report(`${event}-noop`, severity.HIGH, confidence.CERTAIN, `the ${event} handler never calls event.preventDefault(), so it blocks nothing`, false);
      if (blocks.some(({ call, ancestors }) => !isConditional(call, ancestors, fn)))
        return report(event, severity.INFORMATIONAL, confidence.CERTAIN, `the ${event} handler blocks every navigation`, false);
      if (hasUrlValidation(fn))
        return report(event, severity.LOW, confidence.FIRM, `the ${event} handler allows some URLs; review the allowlist`);
      return report(event, severity.MEDIUM, confidence.FIRM, `the ${event} handler allows navigation without inspecting the URL`);
    }

    if (method === 'setWindowOpenHandler' && astNode.arguments.length > 0) {
      const fn = handlerFunction(astNode.arguments[0], scope);
      if (!fn) return report('setWindowOpenHandler', severity.MEDIUM, confidence.TENTATIVE, 'the window open handler is defined elsewhere; review it');
      const actions = returnedValues(fn).map(({ value }) => {
        const action = findProperty(value, 'action');
        return action ? literalValue(action[1]) : undefined;
      });
      if (actions.length > 0 && actions.every(a => a === 'deny'))
        return report('setWindowOpenHandler', severity.INFORMATIONAL, confidence.CERTAIN, 'every new window is denied', false);
      // allowed windows are rated by WINDOW_OPEN_HANDLER_JS_CHECK
      return report('setWindowOpenHandler', severity.LOW, confidence.FIRM, 'some new windows are allowed; see WINDOW_OPEN_HANDLER_JS_CHECK');
    }
    return null;
  }
}
