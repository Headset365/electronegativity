// Read local packaged maps into an in-memory loader. Map names never cause filesystem writes or network fetches.
import path from 'node:path';
import crypto from 'node:crypto';
import { listFiles } from './sourcemaps.js';
import { originalSources } from '../remote/sources.js';
const MAX_MAP = 8 * 1024 * 1024;
const MAX_TOTAL = 32 * 1024 * 1024;

export function recoverPackagedSources(primary, parser, root) {
  const buffers = new Map();
  const origins = new Map();
  const replaced = new Set();
  const errors = [];
  let total = 0;
  let maps = 0;
  const loaded = new Set(primary.list_files);
  const available = new Map(listFiles(root).map(file => [primary.archive ? file.rel : path.join(root, file.rel), file]));
  const read = file => {
    try { return primary.load_buffer(file); } catch { return undefined; }
  };
  for (const bundle of [...loaded].filter(file => /\.[cm]?js$/i.test(file)).slice(0, 2000)) {
    const raw = read(bundle);
    if (!raw) continue;
    const buffer = Buffer.from(raw);
    const refs = [...buffer.subarray(-MAX_MAP).toString('utf8').matchAll(/[#@]\s*sourceMappingURL=([^\s'"*]+)/g)];
    const reference = refs.at(-1)?.[1];
    if (!reference) continue;
    let map, mapFile;
    if (/^data:application\/json[^,]*;base64,/i.test(reference)) {
      map = Buffer.from(reference.slice(reference.indexOf(',') + 1), 'base64'); mapFile = `${bundle} (inline)`;
    } else {
      if (/^[a-z][a-z\d+.-]*:|^[\\/]/i.test(reference)) continue;
      const file = primary.archive ? path.normalize(path.join(path.dirname(bundle), reference)) : path.resolve(path.dirname(bundle), reference);
      if (!available.has(file)) continue;
      try { map = available.get(file).read(); } catch { continue; }
      mapFile = file;
    }
    if (!map) continue;
    const fail = message => errors.push({ file: bundle, message: `Source map recovery: ${message}; bundle retained`, tolerable: true });
    if (++maps > 100 || map.length > MAX_MAP) { fail('map count or size limit'); continue; }
    let json;
    try { json = JSON.parse(map); } catch { fail('invalid JSON'); continue; }
    if (json.version !== 3) { fail('unsupported map version'); continue; }
    const parts = Array.isArray(json.sections) ? json.sections.map(section => section.map).filter(Boolean) : [json];
    if (!parts.length || parts.some(part => !Array.isArray(part.sources) || !Array.isArray(part.sourcesContent) ||
      part.sources.some((name, i) => /\.[cm]?[jt]sx?$/i.test(String(name).split('?')[0]) && typeof part.sourcesContent[i] !== 'string'))) {
      fail('original JavaScript/TypeScript sources are incomplete'); continue;
    }
    const sources = originalSources(map.toString());
    if (!sources.length) continue;
    const namespace = crypto.createHash('sha256').update(path.relative(root, bundle)).digest('hex').slice(0, 12);
    const staged = new Map();
    let valid = true;
    let stagedBytes = 0;
    for (const source of sources) {
      const parts = source.name.replaceAll('\\', '/').split('/');
      if (parts.some(part => part === '..' || part === '') || /^[a-z]:/i.test(source.name) || source.name.includes('\0')) { valid = false; break; }
      const file = path.join(root, '~sources', namespace, ...parts);
      const data = Buffer.from(source.content);
      if (sources.length > 2000 || data.length > 1024 * 1024 || total + stagedBytes + data.length > MAX_TOTAL || staged.has(file)) { valid = false; break; }
      try { if (!parser.parse(file, data)[1]) { valid = false; break; } } catch { valid = false; break; }
      staged.set(file, data); stagedBytes += data.length;
    }
    if (!valid) { fail('unsafe names, duplicate sources, parse failure or source budget exceeded'); continue; }
    for (const [file, data] of staged) {
      total += data.length;
      buffers.set(file, data); loaded.add(file);
      origins.set(file, { bundle, map: mapFile, source: path.relative(path.join(root, '~sources', namespace), file), basis: 'embedded-original-source' });
    }
    replaced.add(bundle); loaded.delete(bundle);
  }
  const loader = Object.create(primary);
  loader._loaded = loaded;
  loader.load_buffer = file => buffers.has(file) ? buffers.get(file) : primary.load_buffer(file);
  return { loader, origins, errors, replaced: [...replaced] };
}
