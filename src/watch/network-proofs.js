import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { parse } from 'yaml';
import { isOffline } from '../util/network.js';

// Metadata-only probes: no cookies/auth headers, artifact download or update install.
export function fetchMetadata(url, { origin, websocket = false, metadataOnly = false, maxBytes = 1048576, timeout = 5000, method = 'GET' } = {}) {
  return new Promise(resolve => {
    const u = new URL(url);
    const headers = origin ? { Origin: origin } : {};
    if (method === 'OPTIONS' && origin) Object.assign(headers, { 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' });
    if (websocket) Object.assign(headers, { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64') });
    const req = (u.protocol === 'https:' ? https : http).request(u, { method: method === 'OPTIONS' ? 'OPTIONS' : 'GET', headers }, res => {
      const cors = { allowOrigin: res.headers['access-control-allow-origin'], allowCredentials: res.headers['access-control-allow-credentials'] };
      if (metadataOnly) { done({ outcome: 'response', status: res.statusCode, location: res.headers.location, cors, contentType: res.headers['content-type'] }); res.destroy(); return; }
      let size = 0; const chunks = [];
      res.on('data', b => { size += b.length; if (size > maxBytes) { done({ outcome: 'limit' }); req.destroy(); } else chunks.push(b); });
      res.on('end', () => done({ outcome: 'response', status: res.statusCode, location: res.headers.location, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', () => done({ outcome: 'error' }));
    });
    let finished = false;
    const done = result => { if (finished) return; finished = true; clearTimeout(timer); resolve(result); };
    const timer = setTimeout(() => { done({ outcome: 'timeout' }); req.destroy(); }, timeout);
    req.on('upgrade', (res, socket) => {
      const expected = crypto.createHash('sha1').update(headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      const valid = String(res.headers.upgrade).toLowerCase() === 'websocket' && res.headers['sec-websocket-accept'] === expected;
      socket.destroy(); done({ outcome: valid ? 'upgrade' : 'invalid-upgrade', status: res.statusCode });
    });
    req.on('error', () => done({ outcome: 'error' })); req.end();
  });
}
export function feedFacts(body, url) {
  if (/\/RELEASES$/i.test(new URL(url).pathname)) {
    const lines = body.trim().split(/\r?\n/).filter(Boolean);
    const valid = lines.length > 0 && lines.every(l => /^[a-f\d]{40}\s+\S+\.nupkg\s+\d+\s*$/i.test(l));
    return { format: 'RELEASES', artifacts: lines.length, hashesPresent: valid, hashAlgorithm: valid ? 'sha1' : undefined,
      publisherPresent: false, publisherVerification: 'not verified' };
  }
  const yaml = parse(body, { maxAliasCount: 20 });
  const files = Array.isArray(yaml?.files) ? yaml.files : yaml?.path ? [{ url: yaml.path, sha512: yaml.sha512 }] : [];
  const hash = value => typeof value === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(value) && Buffer.from(value, 'base64').length === 64;
  return { format: 'yaml', artifacts: files.length, hashesPresent: files.length > 0 && files.every(f => hash(f.sha512)),
    hashAlgorithm: files.length > 0 && files.every(f => hash(f.sha512)) ? 'sha512' : undefined,
    publisherPresent: typeof yaml?.publisherName === 'string' || Array.isArray(yaml?.publisherName) && yaml.publisherName.some(n => typeof n === 'string'),
    publisherVerification: 'not verified', artifactTransports: [...new Set(files.map(f => { try { return new URL(f.url, url).protocol; } catch { return 'invalid'; } }))] };
}
export async function inspectFeed(url, { request = fetchMetadata, offline = isOffline() } = {}) {
  if (offline) return { test: 'update-feed', outcome: 'skipped', reason: 'offline mode' };
  const transports = []; let current = url;
  try {
    for (let i = 0; i < 6; i++) {
      const u = new URL(current);
      if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) return { test: 'update-feed', outcome: 'blocked', transports, reason: 'unsafe redirect' };
      transports.push(u.protocol);
      const r = await request(current);
      if (r.outcome !== 'response') return { test: 'update-feed', outcome: r.outcome, transports };
      if ([301, 302, 303, 307, 308].includes(r.status) && r.location) { current = new URL(r.location, current).href; continue; }
      if (r.status !== 200) return { test: 'update-feed', outcome: 'inconclusive', status: r.status, transports };
      return { test: 'update-feed', outcome: 'observed', transports, ...feedFacts(r.body, current), scope: 'feed-metadata',
        secureTransport: transports.every(t => t === 'https:'), installation: false };
    }
    return { test: 'update-feed', outcome: 'limit', transports };
  } catch { return { test: 'update-feed', outcome: 'inconclusive', transports }; }
}
export async function inspectServices(services, listeners, { request = fetchMetadata } = {}) {
  const results = [];
  for (const s of services) {
    if (!listeners.some(l => l.port === s.port && l.transport === 'tcp' && !l.toolInspector && ['127.0.0.1', '0.0.0.0', '::', '::1'].includes(l.address))) {
      results.push({ test: 'local-service', outcome: 'skipped', port: s.port, reason: 'no matching app-owned listener' }); continue;
    }
    const ipv4 = listeners.some(l => l.port === s.port && ['127.0.0.1', '0.0.0.0'].includes(l.address));
    for (const origin of [undefined, 'https://eng-proof.invalid']) {
      const r = await request(`http://${ipv4 ? '127.0.0.1' : '[::1]'}:${s.port}${s.path}`, { origin, websocket: s.transport === 'websocket', metadataOnly: true });
      results.push({ test: 'local-service', outcome: r.outcome, status: r.status, port: s.port, foreignOrigin: !!origin,
        requiresAuth: s.requiresAuth, authenticated: false, transport: s.transport, scope: 'configured-read-only-route' });
    }
  }
  return results;
}

// This establishes the HTTP response without credentials, not the resource's
// authorization contract. In particular, a public endpoint or SPA can return 200.
export async function probeAuthRoutes(listener, findings, { request = fetchMetadata } = {}) {
  if (listener.toolInspector || listener.transport !== 'tcp' || !['127.0.0.1', '0.0.0.0', '::', '::1'].includes(listener.address) ||
      !Number.isInteger(listener.port) || listener.port < 1 || listener.port > 65535) return [];
  const results = [], seen = new Set();
  for (const finding of findings.filter(f => f.id === 'AUTH_MODE_BYPASS_JS_CHECK')) for (const route of finding.properties?.readOnlyRoutes || []) {
    if (seen.size >= 12) return results;
    if (typeof route !== 'string' || !/^\/(?:[\w-]+\/)*(?:handshake|status|health|version|info|ping)\/?$/i.test(route) || seen.has(route)) continue;
    seen.add(route);
    const url = `http://${['127.0.0.1', '0.0.0.0'].includes(listener.address) ? '127.0.0.1' : '[::1]'}:${listener.port}${route}`;
    let response; try { response = await request(url, { metadataOnly: true, method: 'GET' }); } catch { response = { outcome: 'error' }; }
    results.push({ test: 'auth-route', outcome: response.outcome === 'response' ? 'observed' : response.outcome,
      status: response.status, contentType: response.contentType, port: listener.port, route, method: 'GET', authenticated: false,
      scope: 'unauthenticated-http-response', authBypassConfirmed: false, redirectsFollowed: false,
      staticFile: finding.file, staticLine: finding.location?.line });
  }
  return results;
}

export function navigationTestsFromFindings(findings) {
  const hosts = new Set();
  for (const finding of findings.filter(f => /^(?:LIMIT_NAVIGATION|WINDOW_OPEN_HANDLER)_JS_CHECK$/.test(f.id)))
    for (const value of finding.properties?.hosts || []) {
      if (typeof value !== 'string' || value.length > 220) continue;
      let host = value.toLowerCase();
      try { if (/^https?:\/\//.test(host)) host = new URL(host).hostname; } catch { continue; }
      if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/.test(host)) continue;
      hosts.add(host); if (hosts.size >= 8) break;
    }
  return [...hosts].slice(0, 8).flatMap(host => [
    { url: `http://${host}/`, variant: 'allowed-host-http', allowedHost: host },
    { url: `https://eng-proof.${host}/`, variant: 'allowed-host-subdomain', allowedHost: host },
  ]);
}

// Origins a web page or a browser extension would send: a local service that echoes them back in
// Access-Control-Allow-Origin lets that page read its answers (SiYuan's kernel API, CVE-2026-34449 and CVE-2026-54069)
const FOREIGN_ORIGINS = ['https://eng-proof.invalid', 'chrome-extension://engprooftestextensionid'];

/**
 * Every TCP port an app process listens on, without a reviewed route: GET / and a CORS preflight with foreign origins,
 * no cookies or credentials, nothing written. Reports the status, whether the origin is echoed back (and credentials
 * allowed), and whether the port is bound to every interface rather than loopback only.
 */
export async function probeLocalService(listener, { request = fetchMetadata } = {}) {
  const exposed = ['0.0.0.0', '::'].includes(listener.address);
  const host = listener.address === '::1' ? '[::1]' : '127.0.0.1';
  const base = `http://${host}:${listener.port}/`;
  const result = { test: 'local-service-cors', port: listener.port, address: listener.address, exposed, scope: 'unauthenticated-read-only-probe', origins: [] };
  const plain = await request(base, { metadataOnly: true });
  if (plain.outcome !== 'response') return { ...result, outcome: plain.outcome === 'timeout' ? 'timeout' : 'not-http' };
  result.status = plain.status;
  result.contentType = plain.contentType;
  for (const origin of FOREIGN_ORIGINS) {
    for (const method of ['GET', 'OPTIONS']) {
      const r = await request(base, { origin, method, metadataOnly: true });
      const allow = r.cors && r.cors.allowOrigin;
      if (allow && (allow === '*' || allow === origin))
        result.origins.push({ origin, method, allowOrigin: allow, credentials: String(r.cors.allowCredentials).toLowerCase() === 'true' });
    }
  }
  result.outcome = result.origins.length ? 'foreign-origin-allowed' : 'no-cors-for-foreign-origin';
  return result;
}
