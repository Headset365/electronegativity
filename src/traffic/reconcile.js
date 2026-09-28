// Links the traffic findings (a saved capture, or watch mode) to the static findings describing the same problem in code,
// so the report shows each static finding confirmed or seen at runtime instead of two unrelated rows.

const hostsIn = (text) => [...String(text || '').matchAll(/\bhttps?:\/\/([a-z0-9.-]+)/gi)].map(m => m[1].toLowerCase());
const mark = (issue, status, text) => {
  if (!issue.validation || issue.validation.status !== 'confirmed') issue.validation = { status, text };
};

/**
 * Mutates `issues`: static findings the traffic confirms get a `validation` ({ status, text }), and the traffic findings
 * name the static finding they back.
 * @param {Array} issues all findings
 * @param {{ interceptedHttps?: number }} context interceptedHttps: https exchanges read by an intercepting proxy (a Burp capture)
 */
export function reconcileTraffic(issues, { interceptedHttps = 0 } = {}) {
  const of = (id) => issues.filter(i => i.id === id);
  const cleartextHosts = new Set(of('TRAFFIC_CLEARTEXT_HTTP').map(i => i.properties && i.properties.host).filter(Boolean));
  of('RUNTIME_INSECURE_LOAD').forEach(i => hostsIn(i.file).forEach(h => cleartextHosts.add(h)));

  // http:// in the code, and requests to that host really went out unencrypted
  for (const issue of issues.filter(i => /^HTTP_RESOURCES_(JS|HTML)_CHECK$/.test(i.id) || /^UPDATE_SECURITY_/.test(i.id))) {
    const host = hostsIn(`${issue.sample} ${issue.description}`).find(h => cleartextHosts.has(h));
    if (host) mark(issue, 'confirmed', `Confirmed at runtime: requests to ${host} went out over unencrypted http.`);
  }

  // an intercepting proxy read the app's https traffic: the app accepted the proxy's certificate
  if (interceptedHttps > 0)
    for (const issue of of('CERTIFICATE_PINNING_GLOBAL_CHECK'))
      mark(issue, 'confirmed', 'Confirmed at runtime: an intercepting proxy read the app\'s https traffic, so the app trusted a certificate it was not pinned to.');

  // the server pushes HTML over a WebSocket: the static HTML sinks fed by messages are where it would be rendered
  const wsHtml = of('TRAFFIC_WS_HTML_MESSAGE');
  if (wsHtml.length > 0)
    for (const issue of of('XSS_SINK_JS_CHECK').filter(i => /message|websocket|socket/i.test(`${i.description} ${i.properties && i.properties.origin}`)))
      mark(issue, 'observed', `Seen at runtime: the server sends HTML over a WebSocket (${wsHtml.map(w => w.properties.host).join(', ')}); if it reaches this sink unsanitized, it is XSS.`);

  // secrets the code holds, seen leaving in a URL
  const urlSecrets = of('TRAFFIC_SECRET_IN_URL');
  if (urlSecrets.length > 0)
    for (const issue of of('PLAINTEXT_SECRETS_JS_CHECK').filter(i => hostsIn(i.sample).some(h => urlSecrets.some(u => u.properties.host === h))))
      mark(issue, 'observed', 'Seen at runtime: a secret is sent in the URL of requests to this host.');
  return issues;
}
