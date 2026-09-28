// Saved captures of the app's traffic (a HAR export from DevTools or a proxy, or Burp Suite's "Save items" XML), turned
// into exchanges for the traffic checks, and the checks' findings turned into issues like the other findings.
import fs from 'node:fs';
import zlib from 'node:zlib';
import * as cheerio from 'cheerio';
import { severity, confidence } from '../finder/attributes.js';
import detectors from './detectors.cjs';

const { TrafficAnalyzer } = detectors;
const MAX_BODY = 4 * 1024 * 1024;

export class IngestError extends Error {}

function decompress(body, encoding) {
  const enc = String(encoding || '').toLowerCase().trim();
  if (!enc || !body || body.length === 0) return body;
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(body);
    if (enc === 'deflate') {
      try {
        return zlib.inflateSync(body);
      } catch {
        return zlib.inflateRawSync(body);
      }
    }
    if (enc === 'br') return zlib.brotliDecompressSync(body);
  } catch {
    // leave it as it is
  }
  return body;
}

function dechunk(body) {
  const out = [];
  let i = 0;
  while (i < body.length) {
    const end = body.indexOf('\r\n', i);
    if (end < 0) break;
    const size = Number.parseInt(body.subarray(i, end).toString('latin1').split(';')[0].trim(), 16);
    if (Number.isNaN(size)) return out.length > 0 ? Buffer.concat(out) : body;
    if (size === 0) break;
    out.push(body.subarray(end + 2, end + 2 + size));
    i = end + 2 + size + 2;
  }
  return Buffer.concat(out);
}

/** Splits a raw HTTP message into { startLine, headers: [[name, value]], body: Buffer }. */
export function splitMessage(raw) {
  let at = raw.indexOf('\r\n\r\n');
  let gap = 4;
  if (at < 0) {
    at = raw.indexOf('\n\n');
    gap = 2;
  }
  const head = at < 0 ? raw : raw.subarray(0, at);
  const body = at < 0 ? Buffer.alloc(0) : raw.subarray(at + gap);
  const lines = head.toString('latin1').replace(/\r\n/g, '\n').split('\n');
  const headers = [];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon > 0) headers.push([line.slice(0, colon).trim(), line.slice(colon + 1).trim()]);
  }
  return { startLine: lines[0] || '', headers, body };
}

const headerValue = (headers, name) => (headers.find(([k]) => k.toLowerCase() === name) || [])[1];
const text = (buffer) => buffer && buffer.length > 0 ? buffer.subarray(0, MAX_BODY).toString('utf8') : undefined;

/** Burp Suite "Save items" XML: <items><item><url/><method/><request base64="true"/>...</item></items> */
export function parseBurp(data) {
  const $ = cheerio.load(data, { xml: true });
  if ($.root().children('items').length === 0) throw new IngestError('not a Burp "Save items" export (root <items> expected)');
  const exchanges = [];
  $('items > item').each((_, element) => {
    try {
      const item = $(element);
      const field = (tag) => item.children(tag).first();
      const raw = (tag) => {
        const el = field(tag);
        if (el.length === 0) return Buffer.alloc(0);
        const value = el.text();
        return el.attr('base64') === 'true' ? Buffer.from(value, 'base64') : Buffer.from(value, 'utf8');
      };
      let url = field('url').text().trim();
      let method = field('method').text().trim() || 'GET';
      const request = raw('request');
      const response = raw('response');
      const req = request.length > 0 ? splitMessage(request) : { startLine: '', headers: [], body: Buffer.alloc(0) };
      const res = response.length > 0 ? splitMessage(response) : { startLine: '', headers: [], body: Buffer.alloc(0) };
      if (!url) {
        const host = field('host').text().trim();
        const port = field('port').text().trim();
        const protocol = field('protocol').text().trim() || 'http';
        if (host) url = `${protocol}://${!port || port === '80' || port === '443' ? host : `${host}:${port}`}${field('path').text().trim() || '/'}`;
      }
      const start = req.startLine.match(/^(\S+)\s+(\S+)\s+HTTP/);
      if (start) method = start[1];
      if (!url && start) {
        const host = headerValue(req.headers, 'host');
        if (host) url = /^https?:/i.test(start[2]) ? start[2] : `http://${host}${start[2]}`;
      }
      if (!url) return;
      let status = Number.parseInt(field('status').text().trim(), 10) || undefined;
      const statusLine = res.startLine.match(/^HTTP\/[\d.]+\s+(\d{3})/);
      if (statusLine) status = Number(statusLine[1]);
      let body = res.body;
      if (/chunked/i.test(headerValue(res.headers, 'transfer-encoding') || '')) body = dechunk(body);
      body = decompress(body, headerValue(res.headers, 'content-encoding'));
      exchanges.push({ method, url, requestHeaders: req.headers, requestBody: text(req.body), status, responseHeaders: res.headers, responseBody: text(body), source: 'burp' });
    } catch {
      // a malformed item is skipped
    }
  });
  return { exchanges, websockets: [], kind: 'burp' };
}

const harHeaders = (obj) => (obj && Array.isArray(obj.headers) ? obj.headers : []).filter(h => h && h.name).map(h => [String(h.name), String(h.value ?? '')]);
function harBody(obj) {
  const post = obj && (obj.postData || obj.content);
  if (!post) return { body: Buffer.alloc(0), base64: false };
  if (typeof post.text !== 'string') {
    if (Array.isArray(post.params) && post.params.length > 0)
      return { body: Buffer.from(new URLSearchParams(post.params.map(p => [p.name || '', p.value || ''])).toString()), base64: false };
    return { body: Buffer.alloc(0), base64: false };
  }
  if (String(post.encoding || '').toLowerCase() === 'base64') return { body: Buffer.from(post.text, 'base64'), base64: true };
  return { body: Buffer.from(post.text, 'utf8'), base64: false };
}

/** HAR 1.2, with the WebSocket messages Chrome and Electron DevTools export (_webSocketMessages). */
export function parseHar(data) {
  let har;
  try {
    har = JSON.parse(String(data).replace(/^\uFEFF/, ''));
  } catch (error) {
    throw new IngestError(`invalid HAR JSON: ${error.message}`);
  }
  const entries = har && har.log && har.log.entries;
  if (!Array.isArray(entries)) throw new IngestError('not a HAR file (log.entries missing)');
  const exchanges = [];
  const websockets = [];
  for (const entry of entries) {
    try {
      const request = entry.request || {};
      const response = entry.response || {};
      const url = request.url;
      if (!url) continue;
      const messages = (entry._webSocketMessages || entry.webSocketMessages || []).map(m => ({ direction: m.type === 'receive' ? 'receive' : 'send', data: typeof m.data === 'string' ? m.data : '' }));
      if (/^wss?:/i.test(url) || messages.length > 0) {
        websockets.push({ url: url.replace(/^http/i, 'ws'), messages });
        if (/^wss?:/i.test(url)) continue;
      }
      const { body: requestBody } = harBody(request);
      let { body: responseBody, base64 } = harBody(response);
      const responseHeaders = harHeaders(response);
      // HAR content.text is already decompressed by most tools, unless it was stored as base64
      if (base64) responseBody = decompress(responseBody, headerValue(responseHeaders, 'content-encoding'));
      exchanges.push({ method: request.method || 'GET', url, requestHeaders: harHeaders(request), requestBody: text(requestBody), status: response.status || undefined,
        responseHeaders, responseBody: text(responseBody), source: 'har', document: entry._resourceType === 'document' });
    } catch {
      // a malformed entry is skipped
    }
  }
  return { exchanges, websockets, kind: 'har' };
}

/** Reads a HAR or Burp XML file, by its content. */
export function parseCapture(file) {
  const data = fs.readFileSync(file);
  const head = data.subarray(0, 512).toString('utf8').replace(/^\uFEFF/, '').trimStart();
  if (head.startsWith('{') || /\.har$/i.test(file)) return parseHar(data);
  if (head.startsWith('<') || /\.xml$/i.test(file)) return parseBurp(data);
  try {
    return parseHar(data);
  } catch {
    return parseBurp(data);
  }
}

const SEVERITY = { HIGH: severity.HIGH, MEDIUM: severity.MEDIUM, LOW: severity.LOW, INFORMATIONAL: severity.INFORMATIONAL };
const CONFIDENCE = { CERTAIN: confidence.CERTAIN, FIRM: confidence.FIRM, TENTATIVE: confidence.TENTATIVE };

/** The traffic checks' findings as issues. `source` says where the traffic came from (a capture file, or the watch session). */
export function trafficIssues(findings, source) {
  return findings.map(f => {
    const sev = SEVERITY[f.severity] || severity.LOW;
    const conf = CONFIDENCE[f.confidence] || confidence.TENTATIVE;
    return {
      file: f.location || 'traffic', sample: (f.evidence && f.evidence[0]) || '', location: { line: 0, column: 0 }, id: f.id,
      description: `${f.description}${f.count > 1 ? ` (seen ${f.count} times)` : ''}`,
      properties: { ...f.properties, evidence: f.evidence, count: f.count, source },
      severity: sev, confidence: conf, manualReview: conf !== confidence.CERTAIN, shortenedURL: f.reference,
      visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime',
    };
  });
}

/**
 * Runs the traffic checks on saved captures. Returns { issues, summary: { files, http, ws, hosts, firstParty, errors } }.
 * @param {string[]} files HAR or Burp XML files
 * @param {{ scope?: string[] }} options scope: the app's own domains (learned from the traffic when not given)
 */
export function analyzeCaptures(files, { scope = [] } = {}) {
  const analyzer = new TrafficAnalyzer({ scope });
  const errors = [];
  const captures = [];
  let loaded = 0;
  for (const file of files) {
    let capture;
    try {
      capture = parseCapture(file);
    } catch (error) {
      errors.push(`${file}: ${error.message}`);
      continue;
    }
    loaded++;
    captures.push(capture);
  }
  // first the scope (hosts setting cookies, the pages windows loaded), then the checks
  for (const capture of captures) for (const ex of capture.exchanges) analyzer.learn(ex);
  // https exchanges a proxy decrypted: proof the app accepted the proxy's certificate (a HAR from DevTools is not)
  let interceptedHttps = 0;
  for (const capture of captures) {
    if (capture.kind === 'burp') interceptedHttps += capture.exchanges.filter(ex => /^https:/i.test(ex.url) && ex.status).length;
    for (const ex of capture.exchanges) analyzer.exchange(ex);
    for (const ws of capture.websockets) {
      analyzer.wsOpen(ws.url);
      for (const message of ws.messages) analyzer.wsMessage(ws.url, message.direction, message.data);
    }
  }
  return { issues: trafficIssues(analyzer.results(), 'capture'), summary: { files: loaded, ...analyzer.summary(), interceptedHttps, errors } };
}
