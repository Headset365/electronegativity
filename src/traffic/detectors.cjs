'use strict';
// Passive checks on the app's network traffic: HTTP exchanges and WebSocket connections and messages, from a saved
// capture (HAR, Burp) or observed live in watch mode (hook.cjs loads this into the app's main process). They never send
// anything. Findings carry redacted evidence only: secrets are reduced to a short prefix, and user input is referred to
// by field name.
//
// An exchange is { method, url, requestHeaders: [[name, value]], requestBody, status, responseHeaders, responseBody,
// source }, bodies as strings (or undefined when not captured). CommonJS and dependency-free for the watch hook.
const net = require('net');
const { findSecrets, redact, redactText, isSensitiveParam, looksRandomSecret, looksSecretValue, isAuthHeader } = require('./secrets.cjs');

// A few multi-label public suffixes, so the registrable domain is right for common cases without shipping the Public
// Suffix List
const MULTI_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp',
  'com.br', 'com.cn', 'net.cn', 'com.tw', 'co.kr', 'co.in', 'com.mx', 'co.za', 'com.sg', 'com.hk', 'com.tr', 'github.io', 'herokuapp.com',
  'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'appspot.com', 'firebaseapp.com', 'web.app', 'vercel.app', 'netlify.app',
  'pages.dev', 'workers.dev']);

function registrableDomain(host) {
  const h = String(host || '').toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!h) return '';
  if (net.isIP(h.replace(/^\[|\]$/g, ''))) return h;
  const labels = h.split('.');
  for (const n of [3, 2]) if (labels.length > n && MULTI_SUFFIXES.has(labels.slice(-n).join('.'))) return labels.slice(-(n + 1)).join('.');
  return labels.slice(-2).join('.');
}

function isLoopback(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (net.isIPv4(h)) return h.startsWith('127.');
  if (net.isIPv6(h)) return h === '::1' || /^::ffff:127\./.test(h);
  return false;
}

const parseUrl = (url) => {
  try {
    return new URL(url);
  } catch {
    return undefined;
  }
};
const schemeOf = (u) => u ? u.protocol.replace(/:$/, '').toLowerCase() : '';
const hostOf = (u) => u ? u.hostname.toLowerCase().replace(/^\[|\]$/g, '') : '';
const pathOf = (u) => u ? (u.pathname || '/') : '/';
const header = (headers, name) => {
  const n = name.toLowerCase();
  for (const [key, value] of headers || []) if (String(key).toLowerCase() === n) return String(value);
  return undefined;
};
const headerAll = (headers, name) => (headers || []).filter(([key]) => String(key).toLowerCase() === name.toLowerCase()).map(([, v]) => String(v));
const queryPairs = (u) => u ? [...u.searchParams.entries()] : [];
const formPairs = (text) => {
  try {
    return [...new URLSearchParams(String(text || '')).entries()];
  } catch {
    return [];
  }
};
function flattenJson(value, prefix = '', out = [], depth = 0) {
  if (depth > 8 || out.length > 500) return out;
  if (Array.isArray(value)) value.slice(0, 50).forEach((item, i) => flattenJson(item, `${prefix}[${i}]`, out, depth + 1));
  else if (value && typeof value === 'object') for (const key of Object.keys(value)) flattenJson(value[key], prefix ? `${prefix}.${key}` : key, out, depth + 1);
  else if (typeof value === 'string' || typeof value === 'number') out.push([prefix, String(value)]);
  return out;
}

const TRIVIAL = /^(?:true|false|null|undefined|none|yes|no|on|off|\d{1,5}|[a-z]{1,3})$/i;
const STATE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const ID_IN_PATH = /\/(\d{2,})(?=\/|$)/g;
const OBJECT_KEYS = new Set(['user', 'account', 'customer', 'order', 'invoice', 'doc', 'document', 'note', 'file', 'project', 'org', 'team',
  'profile', 'record', 'ticket', 'message', 'item', 'report', 'uid']);
const HTML = /<\s*(script|img|svg|iframe|a|div|span|body|table|video|audio|object|embed|input|form|style)[\s/>]|<\s*\/\s*[a-z][\w-]*\s*>|<[^>]*\bon[a-z]+\s*=|javascript:/i;
const MAX_TRACKED = 5000;
const MAX_EVIDENCE = 5;
const MAX_BODY = 200000;

// id -> [severity, confidence, title, reference]
const RULES = {
  TRAFFIC_CLEARTEXT_HTTP: ['MEDIUM', 'CERTAIN', 'Cleartext HTTP request', 'https://cwe.mitre.org/data/definitions/319.html'],
  TRAFFIC_SECRET_IN_URL: ['HIGH', 'FIRM', 'Secret in a request URL', 'https://cwe.mitre.org/data/definitions/598.html'],
  TRAFFIC_AUTH_TO_THIRD_PARTY: ['HIGH', 'FIRM', 'Authentication material sent to a third-party host', 'https://cwe.mitre.org/data/definitions/200.html'],
  TRAFFIC_USER_INPUT_TO_THIRD_PARTY: ['MEDIUM', 'FIRM', 'User-submitted value forwarded to a third party', 'https://cwe.mitre.org/data/definitions/359.html'],
  TRAFFIC_STATE_CHANGE_NO_AUTH: ['LOW', 'TENTATIVE', 'State-changing request with no visible authentication', 'https://cwe.mitre.org/data/definitions/306.html'],
  TRAFFIC_IDOR_CANDIDATE: ['LOW', 'TENTATIVE', 'Numeric object id in an authenticated request (IDOR candidate)', 'https://cwe.mitre.org/data/definitions/639.html'],
  TRAFFIC_REFLECTED_INPUT: ['LOW', 'TENTATIVE', 'Request input reflected in the response', 'https://cwe.mitre.org/data/definitions/79.html'],
  TRAFFIC_BASIC_AUTH: ['LOW', 'CERTAIN', 'HTTP Basic authentication in use', 'https://cwe.mitre.org/data/definitions/522.html'],
  TRAFFIC_SECRET_IN_RESPONSE: ['MEDIUM', 'FIRM', 'Secret returned in a response body', 'https://cwe.mitre.org/data/definitions/200.html'],
  TRAFFIC_INSECURE_COOKIE: ['LOW', 'CERTAIN', 'Cookie set without Secure or HttpOnly', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
  TRAFFIC_WS_CLEARTEXT: ['MEDIUM', 'CERTAIN', 'Cleartext WebSocket (ws://)', 'https://cwe.mitre.org/data/definitions/319.html'],
  TRAFFIC_WS_SECRET_IN_URL: ['HIGH', 'FIRM', 'Secret in a WebSocket URL', 'https://cwe.mitre.org/data/definitions/598.html'],
  TRAFFIC_WS_HTML_MESSAGE: ['MEDIUM', 'TENTATIVE', 'HTML in an inbound WebSocket message', 'https://cwe.mitre.org/data/definitions/79.html'],
  TRAFFIC_WS_SECRET_IN_MESSAGE: ['MEDIUM', 'FIRM', 'Secret in a WebSocket message', 'https://cwe.mitre.org/data/definitions/200.html'],
};

/**
 * Collects findings from a stream of exchanges and WebSocket events. Repeats of one finding (same id and key) are merged
 * into one with a count and up to five evidence lines.
 * @param {{ scope?: string[] }} options scope: the app's own domains; learned from the traffic when not given
 */
class TrafficAnalyzer {
  constructor({ scope = [] } = {}) {
    this.firstParty = new Set(scope.map(registrableDomain).filter(Boolean));
    this.explicitScope = this.firstParty.size > 0;
    this.inputs = new Map();
    this.findings = new Map();
    this.stats = { http: 0, ws: 0, hosts: new Set() };
  }

  isThirdParty(host) {
    if (!host || isLoopback(host) || this.firstParty.size === 0) return false;
    return !this.firstParty.has(registrableDomain(host));
  }

  noteFirstParty(host) {
    if (host && !isLoopback(host) && !this.explicitScope) this.firstParty.add(registrableDomain(host));
  }

  report(id, key, { description, evidence, location, severity, properties }) {
    const [ruleSeverity, confidence, title, reference] = RULES[id];
    const fullKey = `${id}|${key}`;
    const existing = this.findings.get(fullKey);
    if (existing) {
      existing.count++;
      if (evidence && existing.evidence.length < MAX_EVIDENCE && !existing.evidence.includes(evidence)) existing.evidence.push(evidence);
      return;
    }
    this.findings.set(fullKey, { id, key, severity: severity || ruleSeverity, confidence, title, reference, description, location,
      evidence: evidence ? [evidence] : [], count: 1, properties: properties || {} });
  }

  /**
   * Learns the first-party scope from an exchange without checking it: a host that sets a cookie, or the page an app
   * window loads (`document: true`). Used for a first pass over a saved capture, so requests made before the app's own
   * site shows up are judged against the right scope.
   */
  learn(ex) {
    const u = parseUrl(ex.url);
    if (!u || this.explicitScope) return;
    if (header(ex.responseHeaders, 'set-cookie') || ex.document) this.noteFirstParty(hostOf(u));
  }

  /** The findings so far, in the order they were first seen. */
  results() {
    return [...this.findings.values()];
  }

  summary() {
    return { http: this.stats.http, ws: this.stats.ws, hosts: this.stats.hosts.size, firstParty: [...this.firstParty].sort() };
  }

  /**
   * Records the values a request submits, as soon as it is sent: a later request to a third party carrying one of them
   * is caught even when this request's response is still on its way.
   */
  trackRequest(ex) {
    const u = parseUrl(ex.url);
    if (!u || !/^https?:$/i.test(u.protocol)) return;
    this.trackInputs({ method: String(ex.method || 'GET').toUpperCase(), u, host: hostOf(u), path: pathOf(u), requestHeaders: ex.requestHeaders || [],
      requestBody: ex.requestBody ? String(ex.requestBody).slice(0, MAX_BODY) : '' });
  }

  exchange(ex) {
    const u = parseUrl(ex.url);
    if (!u || !/^https?:$/i.test(u.protocol)) return;
    this.stats.http++;
    const host = hostOf(u);
    this.stats.hosts.add(host);
    const e = { ...ex, method: String(ex.method || 'GET').toUpperCase(), u, host, scheme: schemeOf(u), path: pathOf(u),
      requestHeaders: ex.requestHeaders || [], responseHeaders: ex.responseHeaders || [],
      requestBody: ex.requestBody ? String(ex.requestBody).slice(0, MAX_BODY) : '', responseBody: ex.responseBody ? String(ex.responseBody).slice(0, MAX_BODY) : '' };
    this.trackScope(e);
    for (const check of [this.cleartext, this.secretInUrl, this.authToThirdParty, this.inputToThirdParty, this.stateChangeNoAuth, this.idorCandidate,
      this.reflectedInput, this.basicAuth, this.secretInResponse, this.insecureCookie]) {
      try {
        check.call(this, e);
      } catch {
        // one check failing on an odd exchange never stops the others
      }
    }
  }

  // Not a finding: learns the first-party scope and the values users submitted (to spot them leaving for third parties)
  trackScope(e) {
    // a host that sets a cookie establishes the app's own session; one that only receives cookies may be a tracker
    if (!this.explicitScope && !isLoopback(e.host) && header(e.responseHeaders, 'set-cookie')) this.noteFirstParty(e.host);
    this.trackInputs(e);
  }

  trackInputs(e) {
    const origin = `${e.method} ${e.host}${e.path}`;
    const contentType = (header(e.requestHeaders, 'content-type') || '').toLowerCase();
    let pairs = queryPairs(e.u);
    if (e.requestBody && contentType.includes('application/x-www-form-urlencoded')) pairs = pairs.concat(formPairs(e.requestBody));
    else if (e.requestBody && contentType.includes('application/json')) {
      try {
        pairs = pairs.concat(flattenJson(JSON.parse(e.requestBody)));
      } catch {
        // not JSON after all
      }
    }
    for (const [name, value] of pairs) {
      if (/passw|secret|otp|pin|cvv|card/i.test(name)) continue;
      const v = String(value || '').trim();
      if (v.length < 4 || v.length > 512 || TRIVIAL.test(v) || this.inputs.has(v) || this.inputs.size >= MAX_TRACKED) continue;
      this.inputs.set(v, { origin, host: e.host, name });
    }
  }

  cleartext(e) {
    if (e.scheme !== 'http' || isLoopback(e.host)) return;
    this.report('TRAFFIC_CLEARTEXT_HTTP', e.host, { description: `Requests to ${e.host} are sent over unencrypted http, e.g. ${e.method} http://${e.host}${e.path}`,
      evidence: `${e.method} http://${e.host}${e.path}`, location: `http://${e.host}`, properties: { host: e.host } });
  }

  secretInUrl(e) {
    const hits = queryPairs(e.u).filter(([name, value]) => value && ((isSensitiveParam(name) && value.length >= 6 && !/^(true|false|null)$/i.test(value)) ||
      looksRandomSecret(value) || findSecrets(value).some(s => !s.kind.startsWith('Hard-coded'))));
    if (hits.length === 0) return;
    const names = [...new Set(hits.map(([name]) => name))].sort();
    const cleartext = e.scheme === 'http';
    this.report('TRAFFIC_SECRET_IN_URL', `${e.host}:${names.join(',')}`, {
      description: `The URL of requests to ${e.host}${e.path} carries secret-like parameters (${names.join(', ')})${cleartext ? ', over unencrypted http' : ''}: URLs end up in logs, history and Referer headers`,
      evidence: `${e.method} ${e.scheme}://${e.host}${e.path}?${hits.map(([n, v]) => `${n}=${redact(v)}`).join('&')}`,
      location: `${e.scheme}://${e.host}${e.path}`, severity: 'HIGH', properties: { host: e.host, params: names, cleartext } });
  }

  authToThirdParty(e) {
    if (!this.isThirdParty(e.host)) return;
    for (const [name, value] of e.requestHeaders) {
      if (!isAuthHeader(name) || !String(value).trim() || (String(name).toLowerCase() === 'cookie' && String(value).length <= 4)) continue;
      this.report('TRAFFIC_AUTH_TO_THIRD_PARTY', `${e.host}:${String(name).toLowerCase()}`, {
        description: `The ${name} header is sent to ${e.host}, outside the app's own domains (${[...this.firstParty].sort().join(', ')})`,
        evidence: `${e.method} ${e.host}${e.path} — ${name}: ${redact(value)}`, location: `${e.scheme}://${e.host}`,
        properties: { host: e.host, header: String(name).toLowerCase(), firstParty: [...this.firstParty].sort() } });
      return;
    }
  }

  inputToThirdParty(e) {
    if (!this.isThirdParty(e.host)) return;
    const haystack = `${e.url}\n${e.requestBody.slice(0, 100000)}`;
    for (const [value, tracked] of this.inputs) {
      if (!tracked.host || this.isThirdParty(tracked.host) || !haystack.includes(value)) continue;
      this.report('TRAFFIC_USER_INPUT_TO_THIRD_PARTY', `${e.host}:${tracked.name}`, {
        description: `A value first sent to ${tracked.host} (field ${tracked.name || '?'}) is also sent to the third party ${e.host}`,
        evidence: `${tracked.origin} [${tracked.name}] → ${e.method} ${e.host}${e.path}`, location: `${e.scheme}://${e.host}`,
        properties: { host: e.host, field: tracked.name, from: tracked.host } });
      return;
    }
  }

  stateChangeNoAuth(e) {
    if (!STATE_METHODS.has(e.method) || isLoopback(e.host) || e.status === 401 || e.status === 403) return;
    if (e.requestHeaders.some(([name]) => isAuthHeader(name))) return;
    // live requests observed without their headers (watch mode without header capture) can't be judged
    if (e.requestHeadersUnknown) return;
    this.report('TRAFFIC_STATE_CHANGE_NO_AUTH', `${e.method}:${e.host}:${e.path.replace(/\d+/g, '{id}')}`, {
      description: `${e.method} ${e.host}${e.path} carries no Authorization, Cookie or API key header: check that the server authenticates the caller`,
      evidence: `${e.method} ${e.scheme}://${e.host}${e.path} -> ${e.status || '?'}`, location: `${e.scheme}://${e.host}${e.path}`, properties: { host: e.host, method: e.method } });
  }

  idorCandidate(e) {
    if (isLoopback(e.host) || !e.requestHeaders.some(([name]) => isAuthHeader(name))) return;
    const ids = [...e.path.matchAll(ID_IN_PATH)].map(m => m[1]);
    const queryIds = queryPairs(e.u).filter(([k, v]) => /^\d{2,}$/.test(v) && (/id$|^id|_id/i.test(k) || OBJECT_KEYS.has(k.toLowerCase())));
    if (ids.length === 0 && queryIds.length === 0) return;
    const where = ids.length > 0 ? 'path' : 'query';
    const route = e.path.replace(/\d+/g, '{id}');
    this.report('TRAFFIC_IDOR_CANDIDATE', `${e.method}:${e.host}:${route}`, {
      description: `Authenticated ${e.method} ${e.host}${route} addresses an object by a numeric id in the ${where}: check on the server that another user's id is refused (the tool never requests other ids)`,
      evidence: `${e.method} ${e.scheme}://${e.host}${e.path}`, location: `${e.scheme}://${e.host}${route}`, properties: { host: e.host, location: where, route } });
  }

  reflectedInput(e) {
    if (!e.responseBody || !(e.status >= 200 && e.status < 300)) return;
    const contentType = (header(e.responseHeaders, 'content-type') || '').toLowerCase();
    if (!/html|xml|javascript|json/.test(contentType)) return;
    let params = queryPairs(e.u);
    if (e.requestBody && /urlencoded/.test((header(e.requestHeaders, 'content-type') || '').toLowerCase())) params = params.concat(formPairs(e.requestBody));
    for (const [name, value] of params) {
      if (value.length < 6 || isSensitiveParam(name) || !e.responseBody.includes(value)) continue;
      // in an HTML response right after a tag or quote, or markup sent in the parameter coming back unencoded
      const htmlContext = contentType.includes('html') && ([`>${value}`, `"${value}`, `=${value}`].some(s => e.responseBody.includes(s)) || /<[a-z!/]/i.test(value));
      this.report('TRAFFIC_REFLECTED_INPUT', `${e.host}:${e.path}:${name}`, {
        description: `The request parameter '${name}' comes back in the ${contentType.split(';')[0]} response of ${e.host}${e.path}: check that it is encoded for where it lands`,
        evidence: `${e.method} ${e.host}${e.path} — ${name}=${looksSecretValue(value) ? redact(value) : value.slice(0, 40)}`,
        location: `${e.scheme}://${e.host}${e.path}`, severity: htmlContext ? 'MEDIUM' : 'LOW', properties: { host: e.host, param: name, contentType: contentType.split(';')[0] } });
      return;
    }
  }

  basicAuth(e) {
    const auth = header(e.requestHeaders, 'authorization');
    if (!auth || !/^basic /i.test(auth)) return;
    const cleartext = e.scheme === 'http';
    this.report('TRAFFIC_BASIC_AUTH', e.host, { description: `HTTP Basic authentication is sent to ${e.host}${cleartext ? ' over unencrypted http' : ''}: reusable credentials travel with every request`,
      evidence: `${e.method} ${e.host}${e.path} — Authorization: Basic ${redact(auth.slice(6))}`, location: `${e.scheme}://${e.host}`,
      severity: cleartext ? 'HIGH' : 'LOW', properties: { host: e.host, cleartext } });
  }

  secretInResponse(e) {
    if (!e.responseBody) return;
    const contentType = (header(e.responseHeaders, 'content-type') || '').toLowerCase();
    if (/image|font|video|audio|octet-stream/.test(contentType)) return;
    const real = findSecrets(e.responseBody).filter(s => !s.kind.startsWith('Hard-coded'));
    if (real.length === 0) return;
    const kinds = [...new Set(real.map(s => s.kind))].sort();
    this.report('TRAFFIC_SECRET_IN_RESPONSE', `${e.host}:${e.path}:${kinds.join(',')}`, {
      description: `The response of ${e.host}${e.path} contains ${kinds.join(', ')}`,
      evidence: `${e.method} ${e.host}${e.path}: ${real.slice(0, 3).map(s => `${s.kind}=${redact(s.value)}`).join(', ')}`,
      location: `${e.scheme}://${e.host}${e.path}`, properties: { host: e.host, kinds } });
  }

  insecureCookie(e) {
    if (isLoopback(e.host)) return;
    for (const setCookie of headerAll(e.responseHeaders, 'set-cookie').flatMap(v => v.split('\n'))) {
      const low = setCookie.toLowerCase();
      const name = setCookie.split('=')[0].trim();
      if (!name) continue;
      const missing = e.scheme === 'https'
        ? [['Secure', /;\s*secure\b/], ['HttpOnly', /;\s*httponly\b/]].filter(([, p]) => !p.test(low)).map(([flag]) => flag)
        : /;\s*httponly\b/.test(low) ? [] : ['HttpOnly']; // over http Secure can't apply; HttpOnly still keeps it from page script
      if (missing.length === 0) continue;
      this.report('TRAFFIC_INSECURE_COOKIE', `${e.host}:${name}`, {
        description: `The cookie '${name}' set by ${e.host} lacks ${missing.join(' and ')}${e.scheme === 'http' ? ' (set over unencrypted http)' : ''}`,
        evidence: `Set-Cookie: ${name}=…; ${setCookie.split(';').slice(1, 5).map(s => s.trim()).join('; ')}`, location: `${e.scheme}://${e.host}`,
        properties: { host: e.host, cookie: name, missing } });
    }
  }

  wsOpen(url) {
    const u = parseUrl(url);
    if (!u) return;
    const host = hostOf(u);
    this.stats.hosts.add(host);
    if (schemeOf(u) === 'ws' && !isLoopback(host))
      this.report('TRAFFIC_WS_CLEARTEXT', host, { description: `A WebSocket to ${host} is not encrypted (ws://)`, evidence: `ws://${host}${pathOf(u)}`, location: `ws://${host}`, properties: { host } });
    const hits = queryPairs(u).filter(([name, value]) => (isSensitiveParam(name) && value.length >= 6) || looksRandomSecret(value));
    if (hits.length > 0)
      this.report('TRAFFIC_WS_SECRET_IN_URL', host, { description: `The WebSocket URL ${schemeOf(u)}://${host}${pathOf(u)} carries secret-like parameters (${hits.map(([n]) => n).join(', ')})`,
        evidence: `${schemeOf(u)}://${host}${pathOf(u)}?${hits.map(([n, v]) => `${n}=${redact(v)}`).join('&')}`, location: `${schemeOf(u)}://${host}`, properties: { host } });
  }

  /** direction: 'receive' (server to app) or 'send' */
  wsMessage(url, direction, payload) {
    this.stats.ws++;
    if (direction !== 'receive') return;
    const text = String(payload || '').slice(0, MAX_BODY);
    const u = parseUrl(url);
    const host = hostOf(u) || String(url || '');
    const where = u ? `${schemeOf(u)}://${host}${pathOf(u)}` : host;
    if (HTML.test(text))
      this.report('TRAFFIC_WS_HTML_MESSAGE', host, { description: `Messages from the WebSocket ${where} carry HTML: if the app renders them as HTML without sanitizing, content from another user runs as script (XSS)`,
        evidence: `${where}: message with markup (${text.length} characters)`, location: where, properties: { host } });
    const secret = findSecrets(text).find(s => !s.kind.startsWith('Hard-coded'));
    if (secret)
      this.report('TRAFFIC_WS_SECRET_IN_MESSAGE', `${host}:${secret.kind}`, { description: `A message from the WebSocket ${where} contains ${secret.kind}`,
        evidence: `${where}: ${secret.kind}=${redact(secret.value)}`, location: where, properties: { host, kind: secret.kind } });
  }
}

module.exports = { TrafficAnalyzer, RULES, registrableDomain, isLoopback, redactText };
