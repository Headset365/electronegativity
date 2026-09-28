'use strict';
// Watch mode's traffic observer, loaded into the app's main process by hook.cjs. It feeds the app's network traffic to
// the passive traffic checks (../traffic/detectors.cjs) inside the app and writes only their findings to the session log,
// with redacted evidence: request and response content never leaves the process.
//
// Sources:
//  - each window's own DevTools protocol connection (webContents.debugger, Network domain): requests with the headers
//    actually sent (cookies included), response headers and text bodies, WebSocket connections and frames. Read-only.
//    When the app attaches its own debugger to a window, ours steps aside for that window.
//  - the session's webRequest events, for requests no window's debugger sees (electron.net, service workers) and for
//    windows the debugger could not be attached to: headers and request bodies, no response bodies.
//  - Node's http/https in the main process: request and response headers.
const path = require('path');

const TEXT_TYPES = /json|javascript|ecmascript|text\/|xml|html|x-www-form-urlencoded|graphql/i;
const MAX_RESPONSE_BODY = 512 * 1024;
const MAX_PENDING = 2000;

const headerPairs = (headers) => {
  const out = [];
  if (!headers || typeof headers !== 'object') return out;
  for (const key of Object.keys(headers)) {
    const value = headers[key];
    if (Array.isArray(value)) for (const v of value) out.push([key, String(v)]);
    // raw CDP headers join repeated headers (Set-Cookie) with newlines
    else if (value !== undefined && value !== null) for (const v of String(value).split('\n')) out.push([key, v]);
  }
  return out;
};

const bodyText = (uploadData) => {
  if (!Array.isArray(uploadData)) return undefined;
  let text = '';
  for (const part of uploadData) {
    if (part && part.bytes && text.length < 1024 * 1024) text += Buffer.from(part.bytes).subarray(0, 1024 * 1024 - text.length).toString('utf8');
  }
  return text || undefined;
};

/**
 * @param {{ write: Function, scope?: string[] }} options write(kind, data) appends to the session log
 * @returns the observer, or undefined when the traffic checks can't be loaded
 */
function createTrafficObserver({ write, scope = [] }) {
  let TrafficAnalyzer;
  try {
    ({ TrafficAnalyzer } = require(path.join(__dirname, '..', 'traffic', 'detectors.cjs')));
  } catch (error) {
    write('hook-error', { message: `traffic checks unavailable: ${error && error.message}` });
    return undefined;
  }
  const analyzer = new TrafficAnalyzer({ scope });
  const safely = (fn) => {
    try {
      fn();
    } catch (error) {
      write('hook-error', { message: `traffic: ${error && error.message}` });
    }
  };
  let version = 0;
  let flushed = 0;
  const sources = { debugger: 0, webRequest: 0, node: 0, websocket: 0 };
  const feed = (exchange, source) => {
    sources[source]++;
    analyzer.exchange(exchange);
    version++;
  };
  // the findings so far, rewritten whenever they changed: the analysis reads the last one
  const flush = () => {
    if (version === flushed) return;
    flushed = version;
    write('traffic', { findings: analyzer.results(), summary: { ...analyzer.summary(), sources } });
  };
  const timer = setInterval(flush, 2000);
  if (timer.unref) timer.unref();

  // webContents with our debugger attached: their requests come from the debugger, not webRequest
  const debugged = new Set();
  const pendingWebRequest = new Map();

  // --- session webRequest (hook.cjs chains these into the app's own listeners) ---
  const onBeforeRequest = (details) => {
    if (details.resourceType === 'mainFrame') analyzer.learn({ url: details.url, document: true });
    if (details.webContentsId !== undefined && debugged.has(details.webContentsId)) return;
    if (!/^https?:/i.test(details.url)) return;
    const entry = { method: details.method, url: details.url, requestBody: bodyText(details.uploadData), requestHeadersUnknown: true };
    pendingWebRequest.set(details.id, entry);
    if (pendingWebRequest.size > MAX_PENDING) pendingWebRequest.delete(pendingWebRequest.keys().next().value);
  };
  const onSendHeaders = (details) => {
    const entry = pendingWebRequest.get(details.id);
    if (!entry) return;
    entry.requestHeaders = headerPairs(details.requestHeaders);
    entry.requestHeadersUnknown = false;
    analyzer.trackRequest(entry);
  };
  const onHeadersReceived = (details) => {
    const entry = pendingWebRequest.get(details.id);
    if (!entry) return;
    pendingWebRequest.delete(details.id);
    feed({ ...entry, status: details.statusCode, responseHeaders: headerPairs(details.responseHeaders), source: 'webRequest' }, 'webRequest');
  };
  const onErrorOccurred = (details) => {
    const entry = pendingWebRequest.get(details.id);
    if (!entry) return;
    pendingWebRequest.delete(details.id);
    feed({ ...entry, source: 'webRequest' }, 'webRequest');
  };

  // --- each window's DevTools protocol connection ---
  function attach(contents) {
    const dbg = contents && contents.debugger;
    if (!dbg || typeof dbg.attach !== 'function') return;
    const id = contents.id;
    try {
      if (dbg.isAttached()) return; // the app's own debugger (or DevTools automation) is there first
      dbg.attach('1.3');
    } catch (error) {
      write('traffic-note', { message: `debugger not attached to window ${id}: ${error && error.message}` });
      return;
    }
    let ours = true;
    debugged.add(id);
    // the app attaching its own debugger to this window: step aside, so its attach succeeds
    const originalAttach = dbg.attach;
    dbg.attach = function (...args) {
      if (ours) stop('the app attached its own debugger');
      dbg.attach = originalAttach;
      return originalAttach.apply(this, args);
    };
    const requests = new Map();
    // the ExtraInfo events (the headers actually sent and received, cookies included) can arrive before
    // requestWillBeSent: kept here until their request shows up
    const early = new Map();
    const earlyFor = (requestId) => {
      if (!early.has(requestId)) {
        early.set(requestId, {});
        if (early.size > MAX_PENDING) early.delete(early.keys().next().value);
      }
      return early.get(requestId);
    };
    const sockets = new Map();
    const send = (method, params) => Promise.resolve().then(() => dbg.sendCommand(method, params));
    const finish = (request, response, body) => {
      requests.delete(request.requestId);
      feed({ method: request.method, url: request.url, requestHeaders: headerPairs(request.extraHeaders || request.headers), requestBody: request.postData,
        status: response && response.status, responseHeaders: headerPairs((response && (response.extraHeaders || response.headers)) || {}), responseBody: body,
        document: request.type === 'Document', source: 'debugger' }, 'debugger');
    };
    const onMessage = (event, method, params) => {
      if (!ours) return;
      safely(() => {
        if (method === 'Network.requestWillBeSent') {
          const previous = requests.get(params.requestId);
          // a redirect: the previous hop is complete, with the redirect response
          if (previous && params.redirectResponse) finish(previous, { status: params.redirectResponse.status, headers: params.redirectResponse.headers, extraHeaders: previous.responseExtra });
          if (!/^https?:/i.test(params.request.url)) return;
          const extra = early.get(params.requestId) || {};
          early.delete(params.requestId);
          requests.set(params.requestId, { requestId: params.requestId, method: params.request.method, url: params.request.url, headers: params.request.headers,
            postData: params.request.postData, type: params.type, extraHeaders: extra.request, responseExtra: extra.response });
          analyzer.trackRequest({ method: params.request.method, url: params.request.url, requestHeaders: headerPairs(params.request.headers), requestBody: params.request.postData });
          if (requests.size > MAX_PENDING) requests.delete(requests.keys().next().value);
          // a body too large to come with the event is fetched separately
          if (params.request.hasPostData && params.request.postData === undefined) {
            send('Network.getRequestPostData', { requestId: params.requestId })
              .then(result => { const request = requests.get(params.requestId); if (request && result) request.postData = String(result.postData).slice(0, 1024 * 1024); })
              .catch(() => {});
          }
        } else if (method === 'Network.requestWillBeSentExtraInfo') {
          const request = requests.get(params.requestId);
          // after a redirect the next hop's headers can arrive while the previous hop is still recorded
          if (request && !request.extraHeaders) request.extraHeaders = params.headers;
          else earlyFor(params.requestId).request = params.headers;
        } else if (method === 'Network.responseReceivedExtraInfo') {
          const request = requests.get(params.requestId);
          if (request) request.responseExtra = params.headers;
          else earlyFor(params.requestId).response = params.headers;
        } else if (method === 'Network.responseReceived') {
          const request = requests.get(params.requestId);
          if (request) request.response = { status: params.response.status, headers: params.response.headers, mimeType: params.response.mimeType };
        } else if (method === 'Network.loadingFinished') {
          const request = requests.get(params.requestId);
          if (!request || !request.url) return;
          const response = { ...(request.response || {}), extraHeaders: request.responseExtra };
          if (!TEXT_TYPES.test((request.response && request.response.mimeType) || '') || params.encodedDataLength > MAX_RESPONSE_BODY * 4) return finish(request, response);
          send('Network.getResponseBody', { requestId: params.requestId })
            .then(result => finish(request, response, result && !result.base64Encoded ? String(result.body).slice(0, MAX_RESPONSE_BODY) : undefined))
            .catch(() => finish(request, response));
        } else if (method === 'Network.loadingFailed') {
          const request = requests.get(params.requestId);
          if (request && request.url) finish(request, request.response && { ...request.response, extraHeaders: request.responseExtra });
        } else if (method === 'Network.webSocketCreated') {
          sockets.set(params.requestId, params.url);
          sources.websocket++;
          analyzer.wsOpen(params.url);
          version++;
        } else if (method === 'Network.webSocketFrameReceived' || method === 'Network.webSocketFrameSent') {
          const url = sockets.get(params.requestId);
          if (!url || !params.response || params.response.opcode !== 1) return; // text frames only
          analyzer.wsMessage(url, method === 'Network.webSocketFrameReceived' ? 'receive' : 'send', params.response.payloadData);
          version++;
        }
      });
    };
    function stop(reason) {
      if (!ours) return;
      ours = false;
      debugged.delete(id);
      try {
        dbg.removeListener('message', onMessage);
        if (dbg.isAttached()) dbg.detach();
      } catch {
        // already gone
      }
      if (reason) write('traffic-note', { message: `traffic capture stopped for window ${id}: ${reason}` });
    }
    dbg.on('message', onMessage);
    dbg.once('detach', () => { if (ours) stop(); });
    contents.once('destroyed', () => stop());
    send('Network.enable', { maxPostDataSize: 1024 * 1024 }).catch(error => stop(`Network.enable failed: ${error && error.message}`));
  }

  // --- Node's http/https in the main process: headers only (reading a response body would take it from the app) ---
  function instrumentNodeHttp() {
    for (const name of ['http', 'https']) {
      let mod;
      try {
        mod = require(name);
      } catch {
        continue;
      }
      for (const method of ['request', 'get']) {
        const original = mod[method];
        if (typeof original !== 'function') continue;
        const wrapped = function (...args) {
          const req = original.apply(this, args);
          safely(() => {
            const url = requestUrl(name, args, req);
            if (!url) return;
            const headers = typeof req.getHeaders === 'function' ? req.getHeaders() : {};
            const methodName = req.method || 'GET';
            req.once('response', (res) => safely(() => feed({ method: methodName, url, requestHeaders: headerPairs(headers), status: res.statusCode,
              responseHeaders: headerPairs(res.headers), source: 'node' }, 'node')));
          });
          return req;
        };
        Object.defineProperties(wrapped, Object.getOwnPropertyDescriptors(original));
        mod[method] = wrapped;
      }
    }
  }
  function requestUrl(scheme, args, req) {
    const first = args[0];
    if (typeof first === 'string') return first;
    if (first instanceof URL) return first.href;
    const options = first && typeof first === 'object' ? first : {};
    const host = options.hostname || options.host || (req && typeof req.getHeader === 'function' && req.getHeader('host'));
    if (!host) return undefined;
    const port = options.port && String(options.port) !== (scheme === 'https' ? '443' : '80') ? `:${options.port}` : '';
    return `${scheme}://${String(host).replace(/:\d+$/, '')}${port}${options.path || '/'}`;
  }

  return { onBeforeRequest, onSendHeaders, onHeadersReceived, onErrorOccurred, attach, instrumentNodeHttp, flush, analyzer };
}

module.exports = { createTrafficObserver, headerPairs };
