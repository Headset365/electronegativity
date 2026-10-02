// Links the traffic findings (a saved capture, or watch mode) to the static findings describing the same problem in code,
// so the report shows each static finding confirmed or seen at runtime instead of two unrelated rows.

import { recordValidation } from '../finder/validation.js';

const hostsIn = (text) => [...String(text || '').matchAll(/\bhttps?:\/\/([a-z0-9.-]+)/gi)].map(m => m[1].toLowerCase());

const mark = (issue, status, scope, text, sources = []) => {
  recordValidation(issue, { status, scope, text,
    evidence: sources.flatMap(s => [`${s.id} at ${s.file}: ${s.description}`, ...(s.properties?.evidence || [])]) });
  for (const source of sources) source.properties = { ...source.properties,
    staticFindings: [...new Set([...(source.properties?.staticFindings || []), `${issue.id} at ${issue.file}${issue.location?.line ? `:${issue.location.line}` : ''}`])] };
};

/**
 * Mutates `issues`: static findings the traffic confirms get a `validation` ({ status, text }), and the traffic findings
 * name the static finding they back.
 * @param {Array} issues all findings
 * @param {{ interceptedHttps?: number }} context interceptedHttps: HTTPS exchanges with responses in a supplied Burp capture
 */
export function reconcileTraffic(issues, { interceptedHttps = 0 } = {}) {
  const of = (id) => issues.filter(i => i.id === id);
  const cleartextHosts = new Set(of('TRAFFIC_CLEARTEXT_HTTP').map(i => i.properties && i.properties.host).filter(Boolean));
  of('RUNTIME_INSECURE_LOAD').forEach(i => hostsIn(i.file).forEach(h => cleartextHosts.add(h)));

  // http:// in the code, and requests to that host really went out unencrypted
  for (const issue of issues.filter(i => /^HTTP_RESOURCES_(JS|HTML)_CHECK$/.test(i.id) || /^UPDATE_SECURITY_/.test(i.id))) {
    const host = hostsIn(`${issue.sample} ${issue.description}`).find(h => cleartextHosts.has(h));
    if (host) {
      const sources = issues.filter(i => i.id === 'TRAFFIC_CLEARTEXT_HTTP' && i.properties?.host === host ||
        i.id === 'RUNTIME_INSECURE_LOAD' && hostsIn(i.file).includes(host));
      const update = /^UPDATE_SECURITY_/.test(issue.id);
      mark(issue, update ? 'observed' : 'confirmed', 'transport',
        `Requests to ${host} were observed over unencrypted HTTP. This confirms host-level transport only; the exact static call site${update ? ' and updater workflow' : ''} is not established.`, sources);
    }
  }

  // Capture presence alone does not establish the originating app or which certificate it accepted.
  if (interceptedHttps > 0)
    for (const issue of of('CERTIFICATE_PINNING_GLOBAL_CHECK'))
      mark(issue, 'observed', 'capture', `${interceptedHttps} HTTPS exchange(s) with responses were present in the supplied proxy capture. Verify the originating app, hosts and proxy certificate before concluding that pinning is absent. This does not demonstrate a certificate-validation bypass.`);

  // the server pushes HTML over a WebSocket: the static HTML sinks fed by messages are where it would be rendered
  const wsHtml = of('TRAFFIC_WS_HTML_MESSAGE');
  if (wsHtml.length > 0)
    for (const issue of of('XSS_SINK_JS_CHECK').filter(i => /message|websocket|socket/i.test(`${i.description} ${i.properties && i.properties.origin}`)))
      mark(issue, 'observed', 'traffic', `HTML was observed over a WebSocket (${wsHtml.map(w => w.properties.host).join(', ')}). Delivery to this particular sink and script execution remain unverified.`, wsHtml);

  // secrets the code holds, seen leaving in a URL
  const urlSecrets = of('TRAFFIC_SECRET_IN_URL');
  if (urlSecrets.length > 0)
    for (const issue of of('PLAINTEXT_SECRETS_JS_CHECK').filter(i => hostsIn(i.sample).some(h => urlSecrets.some(u => u.properties.host === h))))
      mark(issue, 'observed', 'traffic', 'A secret-like value was observed in a request URL to the same host. Identity with the static value and its privileges remain unverified.', urlSecrets.filter(u => hostsIn(issue.sample).includes(u.properties?.host)));
  return issues;
}
