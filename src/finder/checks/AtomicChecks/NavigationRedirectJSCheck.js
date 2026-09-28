import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue, findProperty, finding } from '../helpers.js';
import { handlerFunction, callsIn, isCall } from '../analysis.js';

// events and filters that see where a navigation ends up after server redirects
const EVENTS = ['will-redirect', 'did-start-navigation', 'did-redirect-navigation'];

/**
 * Handlers that can stop a window following a server redirect: will-redirect (event.preventDefault()),
 * did-start-navigation / did-redirect-navigation (webContents.stop()) and webRequest.onBeforeRequest/onBeforeRedirect
 * (callback({ cancel: true })). Informational: NAVIGATION_REDIRECT_GLOBAL_CHECK compares them with the will-navigate allowlist.
 */
export default class NavigationRedirectJSCheck {
  constructor() {
    this.id = 'NAVIGATION_REDIRECT_JS_CHECK';
    this.description = __('NAVIGATION_REDIRECT_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://www.electronjs.org/docs/latest/api/web-contents#event-will-redirect';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (!isCall(astNode) || astNode.type === 'NewExpression' || astNode.arguments.length < 1) return null;
    const method = memberName(astNode.callee);
    let event;
    if (['on', 'once', 'addListener'].includes(method) && EVENTS.includes(literalValue(astNode.arguments[0]))) event = literalValue(astNode.arguments[0]);
    else if (['onBeforeRequest', 'onBeforeRedirect'].includes(method)) event = method;
    if (!event) return null;
    const fn = handlerFunction(astNode.arguments[astNode.arguments.length - 1], scope, context.ancestors);
    let blocks = false;
    if (fn) {
      if (event === 'will-redirect') blocks = callsIn(fn, (call, name) => name === 'preventDefault').length > 0;
      else if (event.startsWith('did-')) blocks = callsIn(fn, (call, name) => ['stop', 'loadURL', 'close', 'destroy'].includes(name)).length > 0;
      else blocks = callsIn(fn, (call) => call.arguments.some(a => a.type === 'ObjectExpression' && (findProperty(a, 'cancel') || findProperty(a, 'redirectURL')))).length > 0;
    }
    return [finding(this, astNode, { severity: severity.INFORMATIONAL, confidence: fn ? confidence.FIRM : confidence.TENTATIVE,
      properties: { event, blocks }, description: `${this.description}: ${event}${blocks ? ' (can block)' : fn ? ' (never blocks)' : ''}` })];
  }
}
