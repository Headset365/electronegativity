// Authentication that a mode switch turns off:
//   const clipperMiddleware = isElectron ? [] : [auth.checkEtapiToken];
//   app.use((req, res, next) => isElectron ? next() : checkAuth(req, res, next));
// In a desktop build the routes behind it answer anyone who reaches the app's local port: another process on the
// machine, or a web page through a permissive CORS policy or DNS rebinding (Trilium's clipper API, GHSA-jcvx-vc83-cppw).
import { sourceTypes } from '../../../parser/types.js';
import { severity, confidence } from '../../attributes.js';
import { memberName, literalValue, finding } from '../helpers.js';
import { isCall, isMember, visit } from '../analysis.js';

// names of authentication middleware and checks: auth.checkEtapiToken, requireAuth, verifyToken, ensureLoggedIn
const AUTH = /auth|token|login|logged|session|guard|protect|verify|permission|password|credential|apikey|api_key|ensure(?:user|signed)|require(?:user|signed)/i;
const MODE = /electron|desktop|local|dev|debug|offline|standalone|portable|test|mock|insecure|noauth|skip/i;

// the names along a member chain or call: auth.checkEtapiToken → ['auth', 'checkEtapiToken']
function namesOf(node) {
  const names = [];
  for (let current = node; current;) {
    if (current.type === 'Identifier') { names.push(current.name); break; }
    if (isMember(current)) { const name = memberName(current); if (name) names.push(name); current = current.object; continue; }
    if (isCall(current)) { current = current.callee; continue; }
    break;
  }
  return names;
}
const isAuth = (node) => namesOf(node).some(name => AUTH.test(name));
const emptyArray = (node) => node && node.type === 'ArrayExpression' && node.elements.length === 0;
// next() in an Express-style middleware: the request passes on unchecked
const passesOn = (node) => node && isCall(node) && node.callee.type === 'Identifier' && /^(next|done|cb|callback)$/.test(node.callee.name);

function describeTest(test) {
  const names = namesOf(test.type === 'UnaryExpression' ? test.argument : test);
  const known = names.find(name => MODE.test(name));
  if (known) return known;
  if (test.type === 'MemberExpression' && namesOf(test).includes('versions')) return 'process.versions.electron';
  return undefined;
}

// the routes a middleware list is registered for: router.get("/api/clipper/notes", clipperMiddleware, handler)
function routesUsing(name, ancestors) {
  const scopeNode = [...ancestors].reverse().find(node => node.type === 'BlockStatement' || node.type === 'Program');
  if (!scopeNode) return { routes: [], readOnlyRoutes: [] };
  const routes = [], readOnlyRoutes = [];
  visit(scopeNode, (node) => {
    if (routes.length >= 12) return false;
    if (isCall(node) && node.arguments.some(arg => arg.type === 'Identifier' && arg.name === name || arg.type === 'SpreadElement' && arg.argument.type === 'Identifier' && arg.argument.name === name)) {
      const route = node.arguments.map(arg => literalValue(arg)).find(value => typeof value === 'string' && value.startsWith('/'));
      if (route && !routes.includes(route)) routes.push(route);
      // Only a declared GET on a plainly read-only route. app.use(), POST and
      // mutation-looking paths are not permission to invoke an endpoint.
      if (route && memberName(node.callee) === 'get' && /\/(?:handshake|status|health|version|info|ping)\/?$/i.test(route)) {
        let mutates = false;
        for (const arg of node.arguments) if (/Function/.test(arg.type || '')) visit(arg, child => {
          if (isCall(child) && /^(?:write|append|delete|remove|save|insert|update|exec|spawn|fork|unlink|rm|set)/i.test(memberName(child.callee) || child.callee?.name || '')) mutates = true;
          return true;
        });
        if (!mutates && !readOnlyRoutes.includes(route)) readOnlyRoutes.push(route);
      }
    }
    return true;
  });
  return { routes, readOnlyRoutes };
}

export default class AuthModeBypassJSCheck {
  constructor() {
    this.id = 'AUTH_MODE_BYPASS_JS_CHECK';
    this.description = __('AUTH_MODE_BYPASS_JS_CHECK');
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = 'https://cwe.mitre.org/data/definitions/306.html';
  }

  match(astNode, astHelper, scope, defaults, electronVersion, context = { ancestors: [] }) {
    if (astNode.type !== 'ConditionalExpression') return null;
    const { test, consequent, alternate } = astNode;
    let checked;
    // cond ? [] : [auth]  /  cond ? [auth] : []
    if (emptyArray(consequent) && alternate.type === 'ArrayExpression' && alternate.elements.some(element => element && isAuth(element))) checked = alternate;
    else if (emptyArray(alternate) && consequent.type === 'ArrayExpression' && consequent.elements.some(element => element && isAuth(element))) checked = consequent;
    // cond ? next() : auth(req, res, next)
    else if (passesOn(consequent) && isCall(alternate) && isAuth(alternate)) checked = alternate;
    else if (passesOn(alternate) && isCall(consequent) && isAuth(consequent)) checked = consequent;
    if (!checked) return null;
    const mode = describeTest(test);
    const auth = (checked.type === 'ArrayExpression' ? checked.elements.filter(Boolean).map(namesOf) : [namesOf(checked)])
      .map(names => names.slice().reverse().join('.')).filter(Boolean)[0] || 'authentication';
    const parent = context.ancestors[context.ancestors.length - 1];
    const variable = parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier' ? parent.id.name : undefined;
    const { routes, readOnlyRoutes } = variable ? routesUsing(variable, context.ancestors) : { routes: [], readOnlyRoutes: [] };
    return [finding(this, astNode, { severity: severity.MEDIUM, confidence: mode ? confidence.FIRM : confidence.TENTATIVE, manualReview: true,
      properties: { auth, mode, routes, readOnlyRoutes },
      description: `${this.description}: ${auth} is skipped${mode ? ` when ${mode} is set` : ' in one mode'}${routes.length ? `, for ${routes.slice(0, 6).join(', ')}${routes.length > 6 ? ', …' : ''}` : ''}; in that mode the routes answer anyone who reaches the app's port` })];
  }
}
