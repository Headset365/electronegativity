// Front-end code served over the network (a remote web app loaded into Electron) is invisible to a scan of the app
// package. These helpers turn captured pages, scripts, templates and source maps into a folder the scanner can read,
// preferring the original sources a source map carries over the minified bundle, and remember which URL each file
// came from so findings point at it.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const MANIFEST = 'manifest.jsonl';

/** The source map a script refers to: `//# sourceMappingURL=app.js.map`, resolved against the script's URL. */
export function sourceMapUrl(code, scriptUrl, header) {
  const reference = header || (() => {
    const tail = String(code).slice(-4096);
    const matches = [...tail.matchAll(/[#@]\s*sourceMappingURL=([^\s'"*]+)/g)];
    return matches.length ? matches[matches.length - 1][1] : undefined;
  })();
  if (!reference || /^data:/i.test(reference)) return reference && /^data:/i.test(reference) ? reference : undefined;
  try {
    return new URL(reference, scriptUrl).href;
  } catch {
    return undefined;
  }
}

/** Reads an inline (data:) source map. */
export function inlineSourceMap(reference) {
  const match = /^data:[^,]*?(;base64)?,(.*)$/is.exec(reference || '');
  if (!match) return undefined;
  try {
    return match[1] ? Buffer.from(match[2], 'base64').toString('utf8') : decodeURIComponent(match[2]);
  } catch {
    return undefined;
  }
}

/**
 * Further files a page or script refers to, to fetch as well: scripts and module imports, and HTML templates
 * (AngularJS templateUrl, ng-include). Module imports resolve against `baseUrl` (the script); other paths named in code
 * resolve against the page (`pageUrl`), as the browser does when the code loads them. Only `origin` is followed.
 */
export function referencedUrls(text, baseUrl, origin, pageUrl = baseUrl) {
  const found = new Set();
  const add = (reference, base) => {
    if (!reference || /^(data|blob|javascript|about|mailto):/i.test(reference) || reference.includes('${')) return;
    try {
      const url = new URL(reference, base);
      if (!/^https?:$/.test(url.protocol) || (origin && url.origin !== origin)) return;
      url.hash = '';
      found.add(url.href);
    } catch {
      // not a URL
    }
  };
  const source = String(text);
  // <script src>, <link rel=modulepreload|preload href> in HTML
  for (const match of source.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) add(match[1], baseUrl);
  for (const match of source.matchAll(/<link\b[^>]*\brel\s*=\s*["']?(?:modulepreload|preload)[^>]*>/gi)) {
    const href = /\bhref\s*=\s*["']?([^"'\s>]+)/i.exec(match[0]);
    if (href && (/\bas\s*=\s*["']?script/i.test(match[0]) || /modulepreload/i.test(match[0]))) add(href[1], baseUrl);
  }
  // ES module imports resolve against the importing script: import x from './y.js', import('./chunk.js')
  for (const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'`](\.{1,2}\/[^"'`\s]+)["'`]/g)) add(match[1], baseUrl);
  // templates and scripts named in code or markup: templateUrl: 'views/editor.html', ng-include="'x.html'"
  for (const match of source.matchAll(/["'`]((?:\.{0,2}\/)?(?:[\w@~-]+\/)*[\w.@~-]+\.(?:html|js|mjs))(?:\?[^"'`\s]*)?["'`]/g)) {
    if (/^(?:\.{0,2}\/)?[\w.@~-]+\.(?:js|mjs)$/.test(match[1]) && !match[1].includes('/')) continue; // bare 'x.js' names are usually not URLs
    add(match[1], /^\.{1,2}\//.test(match[1]) ? baseUrl : pageUrl);
  }
  return [...found];
}

// a safe relative path for a URL or source-map source: no traversal, no absolute paths, a stable suffix for queries
function safeRelative(value, fallbackExtension) {
  const [pathname, query] = String(value).split('?');
  const parts = pathname.replace(/^[a-z]+:\/\/+/i, '').split(/[\\/]+/).filter(part => part && part !== '.' && part !== '..')
    .map(part => part.replace(/[^\w.@~+-]/g, '_').slice(0, 80));
  if (parts.length === 0) parts.push('index');
  let file = parts.join('/');
  if (query) file += `_${crypto.createHash('sha256').update(query).digest('hex').slice(0, 8)}`;
  if (fallbackExtension && !/\.(m?[jt]sx?|html?|vue|json)$/i.test(file)) file += fallbackExtension;
  return file;
}

const SOURCE_EXTENSIONS = /\.(m?[jt]sx?|html?|vue|coffee)$/i;

/**
 * Builds `<captureDir>/scan` from the captured files listed in the manifest. Returns { dir, labels } where labels maps
 * each written file to the URL (and original source) it came from, or undefined when nothing was captured.
 */
export function prepareScanFolder(captureDir) {
  const manifest = path.join(captureDir, MANIFEST);
  if (!fs.existsSync(manifest)) return undefined;
  const entries = fs.readFileSync(manifest, 'utf8').split('\n').filter(Boolean).map(line => {
    try {
      return JSON.parse(line);
    } catch {
      return undefined;
    }
  }).filter(Boolean);
  const scanDir = path.join(captureDir, 'scan');
  fs.rmSync(scanDir, { recursive: true, force: true });
  const labels = new Map();
  const counts = { pages: 0, scripts: 0, templates: 0, recoveredSources: 0, bundlesReplaced: 0 };
  const maps = new Map(entries.filter(e => e.kind === 'map' && e.of).map(e => [e.of, e]));
  const written = new Set();
  const write = (relative, content, label) => {
    const target = path.join(scanDir, relative);
    if (written.has(target)) return;
    written.add(target);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
    labels.set(target, label);
  };
  for (const entry of entries) {
    if (entry.kind === 'map' || !entry.file) continue;
    const file = path.join(captureDir, entry.file);
    if (!fs.existsSync(file)) continue;
    let url;
    try {
      url = new URL(entry.url);
    } catch {
      continue;
    }
    const host = url.host.replace(/[^\w.-]/g, '_');
    const extension = entry.kind === 'script' ? '.js' : '.html';
    if (entry.kind === 'script') {
      const map = maps.get(entry.url);
      const sources = map && map.file && fs.existsSync(path.join(captureDir, map.file)) ? originalSources(fs.readFileSync(path.join(captureDir, map.file), 'utf8')) : [];
      if (sources.length > 0) {
        // scan the original code, which the checks follow far better than a minified bundle
        for (const source of sources) write(path.join(host, '~sources', safeRelative(source.name)), source.content, `${entry.url} (source: ${source.name})`);
        counts.recoveredSources += sources.length;
        counts.bundlesReplaced++;
        continue;
      }
      counts.scripts++;
    } else if (entry.kind === 'page') counts.pages++;
    else counts.templates++;
    write(path.join(host, safeRelative(url.pathname + url.search, extension)), fs.readFileSync(file), entry.url);
  }
  return labels.size > 0 ? { dir: scanDir, labels, counts } : undefined;
}

/** The original sources embedded in a source map (sourcesContent), with bundler prefixes removed. */
export function originalSources(mapText) {
  let map;
  try {
    map = JSON.parse(mapText);
  } catch {
    return [];
  }
  // index maps: { sections: [{ map }] }
  const maps = Array.isArray(map.sections) ? map.sections.map(section => section.map).filter(Boolean) : [map];
  const sources = [];
  for (const m of maps) {
    const names = Array.isArray(m.sources) ? m.sources : [];
    const contents = Array.isArray(m.sourcesContent) ? m.sourcesContent : [];
    names.forEach((name, i) => {
      const content = contents[i];
      if (typeof content !== 'string' || content.length === 0) return;
      const clean = String(name).replace(/^(webpack|vite|rollup|ng):\/\/[^/]*\//i, '').replace(/^file:\/+/i, '').replace(/^(\.\.?\/)+/, '').replace(/\?.*$/, '');
      if (!SOURCE_EXTENSIONS.test(clean)) return; // CSS and assets
      sources.push({ name: clean, content });
    });
  }
  return sources;
}
