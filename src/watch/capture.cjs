'use strict';
const { discoverFields } = require('./campaign.cjs');
const MARKUP = /<\s*[a-z][\w-]*[\s>/]|&lt;\s*[a-z][\w-]*|\\u003c\s*[a-z]/i;

// Field metadata only: raw values and authentication stay in the replay cache.
function inspectBody(text, marker = '') {
  const fields = [], candidates = new Set(discoverFields(text));
  const add = (name, value) => {
    if (fields.length < 60 && typeof value === 'string') fields.push({ name, html: MARKUP.test(value),
      marker: !!marker && value.includes(marker), candidate: candidates.has(name) });
  };
  const walk = (value, name, depth) => {
    if (depth > 6 || fields.length >= 60) return;
    if (Array.isArray(value)) value.slice(0, 20).forEach(item => walk(item, `${name}[]`, depth + 1));
    else if (value && typeof value === 'object') for (const key of Object.keys(value)) walk(value[key], name ? `${name}.${key}` : key, depth + 1);
    else add(name || '(body)', value);
  };
  let format;
  const trimmed = String(text).trim();
  if (/^[[{]/.test(trimmed)) {
    try { walk(JSON.parse(trimmed), '', 0); format = 'json'; } catch { /* not replayable JSON */ }
  } else if (/^[\w.%[\]-]+=/.test(trimmed) && !/\s/.test(trimmed.slice(0, 200))) {
    for (const [name, value] of new URLSearchParams(trimmed)) add(name, value);
    format = 'form';
  } else {
    for (const [, name, value] of trimmed.matchAll(/name="([^"]{1,100})"(?:; filename="[^"]*")?\r?\n(?:[^\r\n]+\r?\n)*\r?\n([\s\S]*?)\r?\n--/g)) add(name, value);
  }
  return { fields, format, html: MARKUP.test(text) };
}

function replayHeaders(headers) {
  const out = {}, skip = new Set(['host', 'content-length', 'connection', 'accept-encoding', 'cookie', 'content-type', 'origin', 'referer']);
  for (const [key, value] of Object.entries(headers || {})) if (!skip.has(key.toLowerCase()))
    out[key] = Array.isArray(value) ? value.join(', ') : String(value);
  return out;
}
module.exports = { inspectBody, replayHeaders };
