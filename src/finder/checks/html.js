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
  if (node.type === 'ConditionalExpression') return looksLikeHtml(node.consequent) || looksLikeHtml(node.alternate);
  return false;
}

// Where untrusted HTML can come from besides the server. Each raises a sink to HIGH, like server data: content pasted
// or dropped from another document, the clipboard, and documents or files the user imports (a .docx converted to
// HTML, a file read with FileReader), any of which another person may have written.
export const ORIGINS = {
  SERVER: 'server-controlled data',
  PASTE: 'pasted or dropped content',
  CLIPBOARD: 'clipboard content',
  DOCUMENT: 'an imported document or file',
};

// converters that turn a document into HTML without sanitizing it: mammoth.convertToHtml(), XLSX.utils.sheet_to_html()
const DOCUMENT_CONVERTERS = /^(convertToHtml|sheet_to_html)$/;
const CLIPBOARD_READS = /^(readHTML|readText|readRTF|readBookmark|read)$/;

/**
 * Where a value handed to an HTML sink comes from, when that is somewhere untrusted: one of ORIGINS, or undefined for
 * a value of unknown provenance.
 */
export function htmlOrigin(value, scope, ancestors = []) {
  if (!value) return undefined;
  if (isServerFed(value, scope) || inServerContext(ancestors, value)) return ORIGINS.SERVER;
  return externalOrigin(value, scope) || callbackOrigin(ancestors, value, scope);
}

function externalOrigin(node, scope, depth = 0) {
  if (!node || depth > 6) return undefined;
  switch (node.type) {
    case 'AwaitExpression':
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'ParenthesizedExpression':
      return externalOrigin(node.argument || node.expression, scope, depth + 1);
    case 'CallExpression':
    case 'OptionalCallExpression': {
      const callee = node.callee;
      const method = memberName(callee) || '';
      if (!isMemberNode(callee)) return undefined;
      const receiver = callee.object;
      const receiverName = receiver.type === 'Identifier' ? receiver.name : memberName(receiver);
      // event.clipboardData.getData('text/html'), (e.originalEvent || e).dataTransfer.getData('text')
      if (method === 'getData' && /^(clipboardData|dataTransfer)$/.test(receiverName || '')) return ORIGINS.PASTE;
      // Electron clipboard.readHTML(), navigator.clipboard.readText()
      if (CLIPBOARD_READS.test(method) && receiverName === 'clipboard') return ORIGINS.CLIPBOARD;
      if (DOCUMENT_CONVERTERS.test(method)) return ORIGINS.DOCUMENT;
      // .then() of a converter is handled by callbackOrigin; other methods of an untrusted value keep its origin
      if (/^(trim|replace|replaceAll|toString|concat|slice|substring|join)$/.test(method)) return externalOrigin(receiver, scope, depth + 1);
      return undefined;
    }
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      // (await mammoth.convertToHtml(input)).value, reader.result of a FileReader
      if (memberName(node) === 'result' && isFileReader(node.object, scope)) return ORIGINS.DOCUMENT;
      return externalOrigin(node.object, scope, depth + 1);
    }
    case 'Identifier': {
      const resolved = resolveLocal(node, scope);
      return resolved !== node ? externalOrigin(resolved, scope, depth + 1) : undefined;
    }
    case 'TemplateLiteral':
      return node.expressions.map(expression => externalOrigin(expression, scope, depth + 1)).find(Boolean);
    case 'BinaryExpression':
      return node.operator === '+' ? externalOrigin(node.left, scope, depth + 1) || externalOrigin(node.right, scope, depth + 1) : undefined;
    case 'ConditionalExpression':
      return externalOrigin(node.consequent, scope, depth + 1) || externalOrigin(node.alternate, scope, depth + 1);
    case 'LogicalExpression':
      return externalOrigin(node.left, scope, depth + 1) || externalOrigin(node.right, scope, depth + 1);
    default:
      return undefined;
  }
}

function isFileReader(node, scope) {
  if (!node) return false;
  const resolved = node.type === 'Identifier' ? resolveLocal(node, scope) : node;
  return !!resolved && resolved.type === 'NewExpression' && resolved.callee.type === 'Identifier' && resolved.callee.name === 'FileReader';
}

// The parameter of a callback that receives untrusted content: mammoth.convertToHtml(x).then(result => ...),
// navigator.clipboard.readText().then(text => ...), reader.onload = (e) => ... of a FileReader
function callbackOrigin(ancestors, value, scope) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const fn = ancestors[i];
    if (!isFunction(fn)) continue;
    const parent = ancestors[i - 1];
    let origin;
    if (isCallNode(parent) && PROMISE_CALLBACKS.test(memberName(parent.callee) || '') && isMemberNode(parent.callee)) {
      origin = externalOrigin(parent.callee.object, scope);
    } else if (parent && parent.type === 'AssignmentExpression' && isMemberNode(parent.left) && /^(onload|onloadend)$/.test(memberName(parent.left) || '') &&
        isFileReader(parent.left.object, scope)) {
      origin = ORIGINS.DOCUMENT;
    } else if (isCallNode(parent) && memberName(parent.callee) === 'addEventListener' && isMemberNode(parent.callee) &&
        ['load', 'loadend'].includes(String(parent.arguments[0] && parent.arguments[0].value)) && isFileReader(parent.callee.object, scope)) {
      origin = ORIGINS.DOCUMENT;
    }
    if (origin && dependsOnParams(value, fn)) return origin;
  }
  return undefined;
}
