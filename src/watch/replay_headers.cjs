// Chromium supplies Fetch Metadata and hop-by-hop headers for the new request.
// Reusing a renderer's Sec-Fetch-Mode/Dest on a main-process session.fetch can
// make Chromium reject the request before it reaches the app's server.
const MANAGED = new Set(['host', 'content-length', 'connection', 'accept-encoding',
  'cookie', 'cookie2', 'content-type', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
function replayHeaders(headers) {
  const out = {};
  for (const key of Object.keys(headers || {})) {
    const name = key.toLowerCase();
    if (MANAGED.has(name) || name.startsWith('sec-') || name.startsWith('proxy-')) continue;
    const value = headers[key];
    out[key] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return out;
}
module.exports = { replayHeaders };
