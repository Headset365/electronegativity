'use strict';
function values(object, field) {
  if (field === '(body)') return [object];
  const parts = field.replaceAll('[]', '.*').split('.');
  const walk = (node, index) => {
    if (index === parts.length) return [node];
    if (parts[index] === '*') return Array.isArray(node) ? node.flatMap(item => walk(item, index + 1)) : [];
    return node && Object.hasOwn(node, parts[index]) ? walk(node[parts[index]], index + 1) : [];
  };
  return walk(object, 0);
}
function parse(body) {
  try { return JSON.parse(body); } catch { return Object.fromEntries(new URLSearchParams(body)); }
}
async function verifySaved({ verify, expected, fields, fetch, headers }) {
  if (!verify) return { verification: 'not-configured' };
  try {
    const timeout = promise => Promise.race([promise, new Promise((_, reject) => { const timer = setTimeout(() => reject(Error('Read-back timed out')), 5000); timer.unref?.(); promise.finally(() => clearTimeout(timer)).catch(() => {}); })]);
    const response = await timeout(Promise.resolve(fetch(verify.url, { method: 'GET', headers, cache: 'no-store' })));
    if (!response.ok) return { verification: 'inconclusive', status: response.status };
    const text = await timeout(Promise.resolve(response.text()));
    if (typeof text !== 'string' || text.length > 100000) return { verification: 'inconclusive' };
    let actual = parse(text);
    for (const key of verify.bodyPath || []) actual = actual?.[key];
    const original = parse(expected);
    const matching = fields.every(field => {
      const before = values(original, field), after = values(actual, field);
      return before.length && before.length === after.length && JSON.stringify(before) === JSON.stringify(after);
    });
    return { verification: matching ? 'matched' : 'mismatch', status: response.status };
  } catch { return { verification: 'inconclusive' }; }
}
module.exports = { verifySaved };
