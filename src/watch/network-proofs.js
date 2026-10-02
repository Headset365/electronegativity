import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { parse } from 'yaml';
import { isOffline } from '../util/network.js';

// Metadata-only probes: no cookies/auth headers, artifact download or update install.
export function fetchMetadata(url, { origin, websocket = false, metadataOnly = false, maxBytes = 1048576, timeout = 5000 } = {}) {
  return new Promise(resolve => {
    const u = new URL(url);
    const headers = origin ? { Origin: origin } : {};
    if (websocket) Object.assign(headers, { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64') });
    const req = (u.protocol === 'https:' ? https : http).request(u, { method: 'GET', headers }, res => {
      if (metadataOnly) { done({ outcome: 'response', status: res.statusCode, location: res.headers.location }); res.destroy(); return; }
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
