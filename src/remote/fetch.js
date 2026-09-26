// Downloads a remote front end (the page, its scripts, their source maps and the templates they name) into a capture
// folder, in the manifest format watch mode also writes, so both can be scanned the same way (see sources.js).
import fs from 'node:fs';
import path from 'node:path';
import { MANIFEST, sourceMapUrl, inlineSourceMap, referencedUrls, originalSources } from './sources.js';
import { isOffline, OfflineError } from '../util/network.js';

const MAX_BYTES = 30 * 1024 * 1024;

function readManifest(captureDir) {
  const file = path.join(captureDir, MANIFEST);
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => {
    try {
      return JSON.parse(line);
    } catch {
      return undefined;
    }
  }).filter(Boolean);
}

const kindOf = (url, contentType) => {
  if (/javascript|ecmascript/i.test(contentType || '') || /\.m?js$/i.test(new URL(url).pathname)) return 'script';
  if (/json/i.test(contentType || '') || /\.map$/i.test(new URL(url).pathname)) return 'map';
  return /\.html?$/i.test(new URL(url).pathname) ? 'template' : 'page';
};

/**
 * Fetches `seeds` (URLs) and what they refer to on the same origin, and completes a capture made by watch mode:
 * source maps of captured scripts and templates or chunks they name that were never loaded during the session.
 * `headers` (e.g. a Cookie or Authorization header for a test account) are only sent to the seeds' origin.
 * Returns { fetched, failed, skipped, notFound } (notFound: guessed references the server doesn't have).
 */
export async function crawl(captureDir, seeds = [], { headers = {}, maxFiles = 300, log = () => {} } = {}) {
  if (isOffline()) throw new OfflineError();
  fs.mkdirSync(path.join(captureDir, 'files'), { recursive: true });
  const entries = readManifest(captureDir);
  const known = new Set(entries.map(e => e.url));
  const origins = new Set();
  // the page of each origin, which paths named in code resolve against
  const pages = new Map();
  const addPage = (url) => {
    try {
      const { origin } = new URL(url);
      origins.add(origin);
      if (!pages.has(origin)) pages.set(origin, url);
    } catch {
      // not a URL
    }
  };
  for (const seed of seeds) addPage(seed);
  for (const entry of entries) if (entry.kind === 'page') addPage(entry.url);
  const stats = { fetched: 0, failed: [], skipped: 0, notFound: 0 };
  let counter = entries.length;
  const append = (entry) => fs.appendFileSync(path.join(captureDir, MANIFEST), JSON.stringify(entry) + '\n');
  const queue = [];
  const enqueue = (url, from) => {
    if (known.has(url)) return;
    known.add(url);
    queue.push({ url, from });
  };
  const followReferences = (text, url, kind) => {
    let origin;
    try {
      origin = new URL(url).origin;
    } catch {
      return;
    }
    if (!origins.has(origin)) return; // third-party scripts are scanned but not crawled
    const page = kind === 'page' ? url : pages.get(origin) || `${origin}/`;
    for (const reference of referencedUrls(text, url, origin, page)) enqueue(reference, url);
    if (kind === 'script') {
      const map = sourceMapUrl(text, url);
      if (map && /^data:/i.test(map)) {
        const inline = inlineSourceMap(map);
        if (inline) {
          const file = `files/${++counter}.map`;
          fs.writeFileSync(path.join(captureDir, file), inline);
          append({ kind: 'map', url: `${url}.map`, of: url, file });
        }
      } else if (map && !known.has(map)) {
        known.add(map);
        queue.push({ url: map, from: url, mapOf: url });
      }
    }
  };
  for (const seed of seeds) enqueue(seed);
  // what watch mode captured: follow the references and source maps it didn't get to
  const mapped = new Set(entries.filter(e => e.kind === 'map').map(e => e.of));
  for (const entry of entries) {
    if (!entry.file) {
      if (entry.url && /^https?:/i.test(entry.url)) { known.delete(entry.url); enqueue(entry.url); }
      continue;
    }
    if (entry.kind === 'map') {
      try {
        for (const source of originalSources(fs.readFileSync(path.join(captureDir, entry.file), 'utf8'))) followReferences(source.content.replace(/\bimport\b[^;]*?from\s*['"][^'"]*['"]/g, ''), entry.of, 'source');
      } catch {
        // unreadable capture
      }
      continue;
    }
    try {
      const text = fs.readFileSync(path.join(captureDir, entry.file), 'utf8');
      followReferences(mapped.has(entry.url) ? text.replace(/[#@]\s*sourceMappingURL=\S+/g, '') : text, entry.url, entry.kind);
    } catch {
      // unreadable capture
    }
  }

  const fetchOne = async ({ url, from, mapOf }) => {
    if (stats.fetched >= maxFiles) { stats.skipped++; return; }
    let response;
    try {
      const sameOrigin = origins.has(new URL(url).origin);
      response = await fetch(url, { headers: sameOrigin ? headers : {}, redirect: 'follow', signal: AbortSignal.timeout(20000) });
    } catch (error) {
      stats.failed.push({ url, message: String(error && (error.cause && error.cause.code || error.message)) });
      return;
    }
    if (!response.ok) {
      // a guessed reference that doesn't exist is expected; a seed or source map that fails is worth reporting
      if (!from || mapOf) stats.failed.push({ url, message: `HTTP ${response.status}` });
      else stats.notFound++;
      return;
    }
    const length = Number(response.headers.get('content-length') || 0);
    if (length > MAX_BYTES) { stats.skipped++; return; }
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length > MAX_BYTES) { stats.skipped++; return; }
    const contentType = response.headers.get('content-type') || '';
    const kind = mapOf ? 'map' : kindOf(url, contentType);
    // a guessed .js/.html reference answered with the app's HTML shell (single-page app fallback) is not the file
    if (kind === 'script' && /text\/html/i.test(contentType)) return;
    const file = `files/${++counter}${kind === 'script' ? '.js' : kind === 'map' ? '.map' : '.html'}`;
    fs.writeFileSync(path.join(captureDir, file), body);
    append({ kind, url, file, ...(mapOf ? { of: mapOf } : {}) });
    stats.fetched++;
    log(url);
    if (kind === 'map') {
      // the original code names templates and chunks the minified bundle may only build at runtime
      for (const source of originalSources(body.toString('utf8'))) followReferences(source.content.replace(/\bimport\b[^;]*?from\s*['"][^'"]*['"]/g, ''), mapOf, 'source');
      return;
    }
    const header = response.headers.get('sourcemap') || response.headers.get('x-sourcemap');
    followReferences(body.toString('utf8'), url, kind);
    if (header && kind === 'script') {
      const map = sourceMapUrl('', url, header);
      if (map && !known.has(map)) { known.add(map); queue.push({ url: map, mapOf: url }); }
    }
  };
  // a few requests at a time
  while (queue.length > 0) {
    const batch = queue.splice(0, 4);
    await Promise.all(batch.map(fetchOne));
  }
  return stats;
}
