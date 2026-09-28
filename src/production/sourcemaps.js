// Source maps shipped with a packaged app: .map files next to the bundles, or maps inlined into them as data: URLs.
// With `sourcesContent` they carry the original code, comments included. Only reported for what ships (a packaged app,
// app.asar or an unpacked installer): in a source checkout, maps are expected.
import fs from 'node:fs';
import path from 'node:path';
import * as asar from '@electron/asar';
import { severity, confidence } from '../finder/attributes.js';
import { walk } from '../secrets/scan.js';

const inNodeModules = (rel) => rel.split(/[\\/]/).includes('node_modules');
const INLINE = /[#@]\s*sourceMappingURL=data:application\/json[^,]*;base64,([A-Za-z0-9+/=]+)/;
const LINKED = /[#@]\s*sourceMappingURL=([^\s'"]+\.map)\b/;

function listFiles(input) {
  const resolved = path.resolve(input);
  try {
    if (fs.statSync(resolved).isDirectory()) return walk(resolved, { skip: rel => inNodeModules(rel) }).map(file => ({ rel: path.relative(resolved, file), read: () => fs.readFileSync(file) }));
  } catch {
    return [];
  }
  if (!/\.asar$/i.test(resolved)) return [];
  try {
    return asar.listPackage(resolved, { isPack: false }).map(f => f.replace(/^[\\/]/, '')).filter(rel => !inNodeModules(rel))
      .map(rel => ({ rel, read: () => asar.extractFile(resolved, rel) }));
  } catch {
    return [];
  }
}

const withSources = (text) => {
  try {
    const map = JSON.parse(String(text));
    return Array.isArray(map.sourcesContent) && map.sourcesContent.some(s => typeof s === 'string' && s.length > 0) ? (map.sources || []).length : 0;
  } catch {
    return 0;
  }
};

/** At most one finding: how many maps ship, and whether they hold the original sources. */
export function sourceMapIssues(input, { packaged = false } = {}) {
  if (!packaged) return [];
  const files = listFiles(input);
  const maps = files.filter(f => /\.map$/i.test(f.rel));
  let original = 0;
  let inline = 0;
  let linked = 0;
  for (const map of maps.slice(0, 50)) if (withSources(map.read()) > 0) original++;
  const names = new Set(maps.map(m => m.rel.replace(/\\/g, '/')));
  for (const file of files.filter(f => /\.[cm]?js$/i.test(f.rel)).slice(0, 2000)) {
    let text;
    try {
      text = file.read().subarray(-200000).toString('utf8');
    } catch {
      continue;
    }
    const inlined = text.match(INLINE);
    if (inlined) {
      inline++;
      if (withSources(Buffer.from(inlined[1], 'base64').toString('utf8')) > 0) original++;
      continue;
    }
    const link = text.match(LINKED);
    if (link && names.has(path.posix.join(path.posix.dirname(file.rel.replace(/\\/g, '/')), link[1]))) linked++;
  }
  if (maps.length === 0 && inline === 0) return [];
  const first = maps[0] ? maps[0].rel : '(inline)';
  return [{ file: maps[0] ? path.join(path.resolve(input), maps[0].rel) : path.resolve(input), sample: '', location: { line: 0, column: 0 }, id: 'SOURCE_MAP_SHIPPED',
    description: `${__('SOURCE_MAP_SHIPPED')}: ${maps.length} .map file(s)${inline ? ` and ${inline} bundle(s) with an inline map` : ''}${linked ? `, ${linked} bundle(s) linking to theirs` : ''}${original ? `; ${original} include the original sources (sourcesContent)` : ''} (e.g. ${first})`,
    shortenedURL: 'https://developer.mozilla.org/en-US/docs/Glossary/Source_map', severity: original ? severity.LOW : severity.INFORMATIONAL, confidence: confidence.CERTAIN,
    manualReview: false, properties: { maps: maps.length, inline, withSources: original },
    visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime' }];
}
