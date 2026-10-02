// Shared recovery contract: incomplete or unparseable originals never replace shipped code.
export const MAX_MAP = 8 * 1024 * 1024;
export const MAX_TOTAL = 32 * 1024 * 1024;
export const MAX_MAPS = 100;
const SOURCE_EXTENSIONS = /\.([cm]?[jt]sx?|html?|vue|coffee)$/i;
export const cleanSourceName = name => String(name).replace(/^(webpack|vite|rollup|ng):\/\/[^/]*\//i, '').replace(/^file:\/+/i, '').replace(/^(\.\.?\/)+/, '').replace(/\?.*$/, '');

function mapParts(map, depth = 0) {
  if (!map || typeof map !== 'object' || depth > 8) throw new Error('invalid or deeply nested map');
  if (!Array.isArray(map.sections)) return [map];
  if (!map.sections.length) throw new Error('empty index map');
  return map.sections.flatMap(section => mapParts(section?.map, depth + 1));
}

/** Embedded originals for reference discovery; replacement requires recoverableSources(). */
export function originalSources(mapText) {
  try {
    return mapParts(JSON.parse(mapText)).flatMap(part => {
      const names = Array.isArray(part.sources) ? part.sources : [];
      const contents = Array.isArray(part.sourcesContent) ? part.sourcesContent : [];
      return names.flatMap((name, i) => {
        const clean = cleanSourceName(name);
        return typeof contents[i] === 'string' && contents[i].length > 0 && SOURCE_EXTENSIONS.test(clean)
          ? [{ name: clean, content: contents[i] }] : [];
      });
    });
  } catch { return []; }
}

/** Validate the entire source set before either local or remote recovery replaces a bundle. */
export function recoverableSources(mapText, parser, totalBytes = 0) {
  const fail = error => ({ sources: [], bytes: 0, error });
  if (Buffer.byteLength(mapText) > MAX_MAP) return fail('map size limit');
  let json, parts;
  try { json = JSON.parse(mapText); parts = mapParts(json); } catch { return fail('invalid JSON or index map'); }
  if (json.version !== 3 || parts.some(part => part.version !== 3)) return fail('unsupported map version');
  if (parts.some(part => !Array.isArray(part.sources) || !Array.isArray(part.sourcesContent) ||
    part.sources.some((name, i) => SOURCE_EXTENSIONS.test(cleanSourceName(name)) && typeof part.sourcesContent[i] !== 'string')))
    return fail('original sources are incomplete');
  const sources = originalSources(mapText);
  if (sources.length > 2000) return fail('source count limit');
  const names = new Set();
  let bytes = 0;
  for (const source of sources) {
    source.name = source.name.replaceAll('\\', '/');
    const segments = source.name.split('/');
    const key = process.platform === 'win32' ? source.name.toLowerCase() : source.name;
    if (segments.some(part => ['..', '.', ''].includes(part)) || /^[a-z]:/i.test(source.name) || source.name.includes('\0') || names.has(key))
      return fail('unsafe or duplicate source names');
    names.add(key);
    const size = Buffer.byteLength(source.content);
    bytes += size;
    if (size > 1024 * 1024 || totalBytes + bytes > MAX_TOTAL) return fail('source size limit');
    try { if (!parser.parse(source.name, Buffer.from(source.content))[1]) return fail('unsupported source or parse failure'); }
    catch { return fail('source parse failure'); }
  }
  return { sources, bytes };
}
