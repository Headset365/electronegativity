// Read local packaged maps into an in-memory loader. Map names never cause filesystem writes or network fetches.
import path from 'node:path';
import crypto from 'node:crypto';
import { listFiles } from './sourcemaps.js';
import { recoverableSources, MAX_MAP, MAX_MAPS } from './source_map_sources.js';

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
    if (++maps > MAX_MAPS || map.length > MAX_MAP) { fail('map count or size limit'); continue; }
    const recovered = recoverableSources(map.toString(), parser, total);
    if (recovered.error) { fail(recovered.error); continue; }
    const sources = recovered.sources;
    if (!sources.length) continue;
    const namespace = crypto.createHash('sha256').update(path.relative(root, bundle)).digest('hex').slice(0, 12);
    const staged = new Map();
    for (const source of sources) {
      const file = path.join(root, '~sources', namespace, ...source.name.split('/'));
      const data = Buffer.from(source.content);
      staged.set(file, data);
    }
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
