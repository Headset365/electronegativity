// Front-end code served over the network (a remote web app loaded into Electron) is invisible to a scan of the app
// package. These helpers turn captured pages, scripts, templates and source maps into a folder the scanner can read,
// preferring the original sources a source map carries over the minified bundle, and remember which URL each file
// came from so findings point at it.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { SourceMap } from 'node:module';
import { Parser } from '../parser/parser.js';
import { recoverableSources, cleanSourceName, MAX_MAP, MAX_MAPS } from '../production/source_map_sources.js';
export { originalSources } from '../production/source_map_sources.js';

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
  if (fallbackExtension && !/\.(m?[jt]sx?|html?|vue|json)$/i.test(file)) file += fallbackExtension;
  // the query (usually a cache buster, angular.min.js?v=3) goes before the extension, so the file keeps its name
  if (query) file = file.replace(/(\.[\w]+)?$/, (ext) => `_${crypto.createHash('sha256').update(query).digest('hex').slice(0, 8)}${ext}`);
  return file;
}

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
  const parser = new Parser(false, true);
  const errors = [];
  let recoveredBytes = 0;
  let mapCount = 0;
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
      let sources = [];
      if (map?.file && fs.existsSync(path.join(captureDir, map.file))) {
        const mapFile = path.join(captureDir, map.file);
        const recovered = ++mapCount > MAX_MAPS || fs.statSync(mapFile).size > MAX_MAP
          ? { error: 'map count or size limit' }
          : recoverableSources(fs.readFileSync(mapFile, 'utf8'), parser, recoveredBytes);
        if (recovered.error) errors.push({ file: entry.url, message: `Source map recovery: ${recovered.error}; bundle retained`, tolerable: true });
        else {
          sources = recovered.sources;
          recoveredBytes += recovered.bytes;
        }
      }
      if (sources.length > 0) {
        // Each bundle owns its originals, even when chunks repeat names such as src/index.js.
        const namespace = crypto.createHash('sha256').update(entry.url).digest('hex').slice(0, 16);
        const paths = sources.map(source => path.join(host, '~sources', namespace, safeRelative(source.name)));
        if (new Set(paths).size !== paths.length || paths.some(file => written.has(path.join(scanDir, file)))) {
          errors.push({ file: entry.url, message: 'Source map recovery: output paths collide; bundle retained', tolerable: true });
        } else {
          sources.forEach((source, i) => write(paths[i], source.content, `${entry.url} (source: ${source.name})`));
          counts.recoveredSources += sources.length;
          counts.bundlesReplaced++;
          continue;
        }
      }
      counts.scripts++;
    } else if (entry.kind === 'page') counts.pages++;
    else counts.templates++;
    write(path.join(host, safeRelative(url.pathname + url.search, extension)), fs.readFileSync(file), entry.url);
  }
  return labels.size > 0 ? { dir: scanDir, labels, counts, errors } : undefined;
}

/**
 * Script locations from stack traces (watch mode), in terms of what was scanned: a frame in a captured bundle whose
 * source map was captured too gets `original` = { file, line, column }, file being the label of the original source
 * the scan reported findings under ("<script URL> (source: src/viewer.js)"). Mutates and returns `frames`.
 */
export function mapFrames(captureDir, frames) {
  const manifest = path.join(captureDir, MANIFEST);
  if (!fs.existsSync(manifest) || !Array.isArray(frames) || frames.length === 0) return frames;
  const entries = fs.readFileSync(manifest, 'utf8').split('\n').filter(Boolean).map(line => {
    try {
      return JSON.parse(line);
    } catch {
      return undefined;
    }
  }).filter(Boolean);
  const withoutQuery = (url) => String(url || '').split(/[?#]/)[0];
  const maps = new Map(entries.filter(e => e.kind === 'map' && e.of && e.file).map(e => [withoutQuery(e.of), e]));
  const loaded = new Map();
  for (const frame of frames) {
    const entry = maps.get(withoutQuery(frame.url));
    if (!entry || !frame.line) continue;
    if (!loaded.has(entry.file)) {
      let sourceMap;
      try {
        sourceMap = new SourceMap(JSON.parse(fs.readFileSync(path.join(captureDir, entry.file), 'utf8')));
      } catch {
        sourceMap = undefined;
      }
      loaded.set(entry.file, sourceMap);
    }
    const sourceMap = loaded.get(entry.file);
    const found = sourceMap && sourceMap.findEntry(frame.line - 1, Math.max(0, (frame.column || 1) - 1));
    if (!found || found.originalSource === undefined || found.originalLine === undefined) continue;
    frame.original = { file: `${entry.of} (source: ${cleanSourceName(found.originalSource)})`, line: found.originalLine + 1, column: found.originalColumn + 1 };
  }
  return frames;
}
