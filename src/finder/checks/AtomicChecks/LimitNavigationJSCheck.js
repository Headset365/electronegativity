import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { electronAtLeast, ELECTRON_CHANGES } from '../versions.js';
import { memberName, findProperty, literalValue, visit } from '../helpers.js';
import { handlerFunction, callsIn, isConditional, hasUrlValidation, returnedValues, paramNames, functionDefinition } from '../analysis.js';

const NAVIGATION_EVENTS = ['will-navigate', 'will-frame-navigate', 'new-window'];

// Electron security checklist #13 and #14: disable or limit navigation and the creation of new windows
export default class LimitNavigationJSCheck {
  constructor() {
    this.id = "LIMIT_NAVIGATION_JS_CHECK";
    this.description = __("LIMIT_NAVIGATION_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://www.electronjs.org/docs/latest/tutorial/security#13-disable-or-limit-navigation";
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
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

      const fn = handlerFunction(astNode.arguments[1], scope, context.ancestors);
      if (!fn) return report(event, severity.MEDIUM, confidence.TENTATIVE, `the ${event} handler is defined elsewhere; review it`);

      const blocks = callsIn(fn, (call, name) => name === 'preventDefault');
      if (blocks.length === 0) {
        // the event may be handed to a helper that decides: onWindowOrNavigate(event, url)
        const delegation = delegatesEvent(fn, scope, context.ancestors);
        if (delegation === 'blocks') return report(event, severity.LOW, confidence.FIRM, `the ${event} handler delegates to a function that can block navigation; review it`);
        if (delegation === 'unknown') return report(event, severity.MEDIUM, confidence.TENTATIVE, `the ${event} handler passes the event to a function defined elsewhere; review it`);
      }
      if (blocks.length === 0)
        // doesn't count as a limit for LimitNavigationGlobalCheck
        return report(`${event}-noop`, severity.HIGH, confidence.CERTAIN, `the ${event} handler never calls event.preventDefault(), so it blocks nothing`, false);
      if (blocks.some(({ call, ancestors }) => !isConditional(call, ancestors, fn)))
        return report(event, severity.INFORMATIONAL, confidence.CERTAIN, `the ${event} handler blocks every navigation`, false);
      // the decision may sit in a helper: if (!isAllowedUrl(url)) event.preventDefault()
      const helpers = urlHelpers(fn, scope);
      if (hasUrlValidation(fn) || helpers.length) {
        const facts = allowlistFacts([fn, ...helpers.map(h => h.node)], context.ancestors.find(node => node.type === 'Program'));
        const hosts = facts.hosts.length ? ` (${facts.hosts.slice(0, 5).join(', ')}${facts.hosts.length > 5 ? ', …' : ''}${facts.subdomains ? ', and every subdomain of each' : ''})` : '';
        const properties = { event, hostOnly: facts.hostOnly, subdomains: facts.subdomains, hosts: facts.hosts, helper: helpers.map(h => h.name).filter(Boolean)[0] };
        // an allowlist of host names that never looks at the scheme lets http:// (or another scheme) on an allowed host
        // through: the page then loads unencrypted, with the window's privileges
        if (facts.hostOnly)
          return [{ ...report(event, severity.MEDIUM, confidence.FIRM, `the ${event} handler compares host names only${hosts}, so any scheme on an allowed host passes (http:// loads the page unencrypted with the window's privileges)${facts.subdomains ? '; any subdomain, including one taken over or hosting user content, is trusted too' : ''}`)[0], properties }];
        if (facts.subdomains)
          return [{ ...report(event, severity.LOW, confidence.FIRM, `the ${event} handler trusts every subdomain of the allowed hosts${hosts}; a subdomain taken over or hosting user content gets the window's privileges`)[0], properties }];
        return [{ ...report(event, severity.LOW, confidence.FIRM, `the ${event} handler allows some URLs${hosts}; review the allowlist`)[0], properties }];
      }
      return report(event, severity.MEDIUM, confidence.FIRM, `the ${event} handler allows navigation without inspecting the URL`);
    }

    if (method === 'setWindowOpenHandler' && astNode.arguments.length > 0) {
      const fn = handlerFunction(astNode.arguments[0], scope, context.ancestors);
      if (!fn) return report('setWindowOpenHandler', severity.MEDIUM, confidence.TENTATIVE, 'the window open handler is defined elsewhere; review it');
      const actions = returnedValues(fn).map(({ value }) => {
        const action = findProperty(value, 'action');
        return action ? literalValue(action[1]) : undefined;
      });
      if (actions.length > 0 && actions.every(a => a === 'deny'))
        return report('setWindowOpenHandler', severity.INFORMATIONAL, confidence.CERTAIN, 'every new window is denied', false);
      // allowed windows are rated by WINDOW_OPEN_HANDLER_JS_CHECK: this one only records that the limit exists (a
      // client finding saying "new windows are allowed" next to that check's account of the allowlist would contradict it)
      return report('setWindowOpenHandler', severity.INFORMATIONAL, confidence.FIRM, 'some new windows are allowed; rated by WINDOW_OPEN_HANDLER_JS_CHECK', false);
    }
    return null;
  }
}

// When a handler passes its event to other functions: 'blocks' if one of them (followed 3 levels deep) calls
// preventDefault(), 'unknown' if one can't be resolved, undefined if the event isn't passed on
function delegatesEvent(fn, scope, ancestors, depth = 0) {
  const eventName = paramNames(fn)[0];
  if (!eventName || depth > 3) return undefined;
  let result;
  for (const { call } of callsIn(fn, (call) => call.arguments.some(a => a.type === 'Identifier' && a.name === eventName))) {
    const target = handlerFunction(call.callee, scope, ancestors);
    if (!target) { result = result || 'unknown'; continue; }
    const index = call.arguments.findIndex(a => a.type === 'Identifier' && a.name === eventName);
    const received = paramNames(target)[index];
    if (callsIn(target, (c, name) => name === 'preventDefault').length > 0) return 'blocks';
    if (received) {
      const nested = delegatesEvent({ ...target, params: [{ type: 'Identifier', name: received }] }, scope, ancestors, depth + 1);
      if (nested === 'blocks') return 'blocks';
      result = result || nested;
    }
  }
  return result;
}

// Functions a handler hands the URL to for the decision: isAllowedUrl(url), checkUrl(details.url)
export function urlHelpers(fn, scope) {
  const params = new Set(paramNames(fn));
  const helpers = [];
  for (const { call } of callsIn(fn, (call) => call.callee.type === 'Identifier')) {
    if (!call.arguments.some(arg => [...identifierNames(arg)].some(name => params.has(name)))) continue;
    const definition = functionDefinition(call.callee, scope);
    if (definition && definition.node && definition.node.body && !helpers.some(h => h.node === definition.node))
      helpers.push({ node: definition.node, name: call.callee.name });
  }
  return helpers.slice(0, 4);
}
function identifierNames(node) {
  const names = new Set();
  visit(node, n => { if (n.type === 'Identifier') names.add(n.name); return true; });
  return names;
}

// What an allowlist checks: host names without the scheme, every subdomain (host.endsWith('.' + allowed)), and the
// hosts it names (string literals that look like domains, in the functions or in arrays they read)
export function allowlistFacts(fns, program) {
  const facts = { hostOnly: false, subdomains: false, hosts: [] };
  let host = false;
  let scheme = false;
  const programArrays = new Set();
  for (const fn of fns) {
    visit(fn.body || fn, (node) => {
      if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
        const name = memberName(node);
        if (name === 'hostname' || name === 'host') host = true;
        if (name === 'protocol' || name === 'origin' || name === 'href') scheme = true;
      }
      if ((node.type === 'CallExpression' || node.type === 'OptionalCallExpression') && memberName(node.callee) === 'endsWith') {
        const arg = node.arguments[0];
        const text = arg && (literalValue(arg) ?? (arg.type === 'TemplateLiteral' ? arg.quasis.map(q => q.value.cooked).join('') : arg.type === 'BinaryExpression' ? literalValue(arg.left) : undefined));
        if (typeof text === 'string' && text.startsWith('.')) facts.subdomains = true;
      }
      const literal = literalValue(node);
      if (typeof literal === 'string') {
        if (/^(https?|file|app|wss?):?(\/\/)?/i.test(literal)) scheme = true;
        if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(literal) && !facts.hosts.includes(literal)) facts.hosts.push(literal);
      }
      if (node.type === 'Identifier') programArrays.add(node.name);
      return true;
    });
  }
  // allowlists kept in a constant next to the function: const whitelistHosts = ['app.example.com', …]
  if (program) for (const statement of program.body || []) {
    if (statement.type !== 'VariableDeclaration') continue;
    for (const declarator of statement.declarations) {
      if (declarator.id.type !== 'Identifier' || !programArrays.has(declarator.id.name) || !declarator.init || declarator.init.type !== 'ArrayExpression') continue;
      for (const element of declarator.init.elements) {
        const value = element && literalValue(element);
        if (typeof value === 'string' && /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(value) && !facts.hosts.includes(value)) facts.hosts.push(value);
      }
    }
  }
  facts.hostOnly = host && !scheme;
  return facts;
}

