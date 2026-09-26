// Shared helpers for the HTML-injection checks: recognizing server-controlled data and HTML-shaped strings.
// A renderer that turns server-controlled data into live HTML is the stored-content threat model behind most
// published Electron vulnerabilities, so these checks raise the severity of a sink when its value comes from the server.
import { memberName, calleeObjectName, isFunction } from './helpers.js';
import { resolveLocal, dependsOnParams } from './analysis.js';

// Objects whose methods reach the network, and the request/response members that carry the server's answer
const SERVER_OBJECTS = /^(axios|ky|superagent|got|\$http|\$resource|\$q|http|https|socket|ws|websocket)$/i;
const RESPONSE_MEMBERS = /^(responseText|responseXML)$/;
// names that hold a server response; message event data is covered by inServerContext, which checks the handler
// actually receives it, rather than by guessing from names like event.data or req.body
const RESPONSE_HOLDERS = /^(res|resp|response|reply|xhr)$/i;
const PROMISE_CALLBACKS = /^(then|catch|finally|subscribe|success|error|done|fail|always)$/;
const MESSAGE_EVENTS = new Set(['message', 'websocket-message']);

const isCallNode = (node) => !!node && (node.type === 'CallExpression' || node.type === 'OptionalCallExpression');
const isMemberNode = (node) => !!node && (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression');

/**
 * Whether an expression's value is (or is built from) data returned by the server: fetch()/$http/axios and the
 * bodies they resolve to (`response.json()`, `xhr.responseText`, `res.data`), followed through locals, template
 * strings, concatenation and conditionals. Conservative: unknown provenance returns false (so the finding stays at
 * its base severity rather than being raised).
 */
export function isServerFed(node, scope, depth = 0) {
  if (!node || depth > 6) return false;
  switch (node.type) {
    case 'AwaitExpression':
    case 'TSAsExpression':
    case 'TSNonNullExpression':
      return isServerFed(node.argument || node.expression, scope, depth + 1);
    case 'CallExpression':
    case 'OptionalCallExpression': {
      const callee = node.callee;
      if (callee.type === 'Identifier' && (callee.name === 'fetch' || callee.name === '$http')) return true;
      const object = calleeObjectName(callee);
      if (object && SERVER_OBJECTS.test(object)) return true;
      // the body of a response: response.json(), response.text(), res.blob()
      if (RESPONSE_MEMBERS.test(memberName(callee) || '')) return true;
      if (['json', 'text', 'blob', 'arrayBuffer', 'formData'].includes(memberName(callee) || '') && isMemberNode(callee) &&
        callee.object.type === 'Identifier' && RESPONSE_HOLDERS.test(callee.object.name)) return true;
      return false;
    }
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const property = memberName(node);
      if (RESPONSE_MEMBERS.test(property || '')) return true;
      // res.data, response.body, msg.data, socket.data
      if (/^(data|body)$/.test(property || '') && node.object.type === 'Identifier' && RESPONSE_HOLDERS.test(node.object.name)) return true;
      return false;
    }
    case 'Identifier': {
      const resolved = resolveLocal(node, scope);
      return resolved !== node ? isServerFed(resolved, scope, depth + 1) : false;
    }
    case 'TemplateLiteral':
      return node.expressions.some(expression => isServerFed(expression, scope, depth + 1));
    case 'BinaryExpression':
      return node.operator === '+' && (isServerFed(node.left, scope, depth + 1) || isServerFed(node.right, scope, depth + 1));
    case 'ConditionalExpression':
      return isServerFed(node.consequent, scope, depth + 1) || isServerFed(node.alternate, scope, depth + 1);
    case 'LogicalExpression':
      return isServerFed(node.left, scope, depth + 1) || isServerFed(node.right, scope, depth + 1);
    default:
      return false;
  }
}

/**
 * Whether `value` is derived from the data a server callback receives: the parameter of a `.then()`/`.subscribe()`/
 * AngularJS `.success()` callback on a server call, or of a `message`/WebSocket `onmessage` handler. A sink that merely
 * sits inside such a callback, with a value from elsewhere, doesn't count.
 */
export function inServerContext(ancestors = [], value) {
  if (!value) return false;
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const node = ancestors[i];
    if (!isFunction(node)) continue;
    const parent = ancestors[i - 1];
    const grandparent = ancestors[i - 2];
    const receivesServerData =
      // fetch(url).then(body => ...), $http.get(url).then(...), observable.subscribe(...)
      (isCallNode(parent) && PROMISE_CALLBACKS.test(memberName(parent.callee) || '') && chainReachesServer(parent.callee)) ||
      // socket.onmessage = (event) => ..., addEventListener('message', handler)
      (parent && parent.type === 'AssignmentExpression' && isMemberNode(parent.left) && /^onmessage$/i.test(memberName(parent.left) || '')) ||
      (isCallNode(grandparent) && memberName(grandparent.callee) === 'addEventListener' && grandparent.arguments[0] && MESSAGE_EVENTS.has(String(grandparent.arguments[0].value))) ||
      (isCallNode(parent) && memberName(parent.callee) === 'addEventListener' && parent.arguments[0] && MESSAGE_EVENTS.has(String(parent.arguments[0].value)));
    if (receivesServerData && dependsOnParams(value, node)) return true;
  }
  return false;
}

// Walks the receiver chain of a `.then`/`.subscribe` call looking for a server call: axios.get(u).then, fetch(u).then
function chainReachesServer(callee) {
  let node = callee && callee.object;
  let depth = 0;
  while (node && depth++ < 8) {
    if (isServerFed(node, null)) return true;
    if (isCallNode(node)) node = node.callee && node.callee.object;
    else if (isMemberNode(node)) node = node.object;
    else break;
  }
  return false;
}

// Strings assembled from pieces whose literal parts contain markup: `<li>${x}</li>`, '<b>' + x, so `$(str)` parses HTML
export function looksLikeHtml(node) {
  if (!node) return false;
  if (['Literal', 'StringLiteral'].includes(node.type)) return typeof node.value === 'string' && /<[a-z!/]/i.test(node.value);
  if (node.type === 'TemplateLiteral') return node.quasis.some(q => /</.test((q.value && (q.value.cooked || q.value.raw)) || ''));
  if (node.type === 'BinaryExpression' && node.operator === '+') return looksLikeHtml(node.left) || looksLikeHtml(node.right);
  return false;
}
