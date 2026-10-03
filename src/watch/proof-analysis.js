import { severity, confidence } from '../finder/attributes.js';

const issue = (id, description, properties, sev = severity.INFORMATIONAL, confirmed = false, scope = 'observation') => ({
  id, file: 'runtime', sample: '', location: { line: 0, column: 0 }, description, properties, severity: sev, confidence: confidence.CERTAIN,
  manualReview: false, constructorName: 'Runtime', shortenedURL: 'https://www.electronjs.org/docs/latest/tutorial/security',
  visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false },
  validation: { status: confirmed ? 'confirmed' : 'observed', scope, text: description },
});
export function analyzeProofs(records) {
  const issues = [];
  const proofs = records.filter(r => r.kind === 'proof');
  for (const p of proofs) {
    const properties = { ...p }; delete properties.t; delete properties.kind;
    let text = `${p.test}: ${p.outcome}.`, sev = severity.INFORMATIONAL, confirmed = false;
    if (p.test === 'certificate' && p.outcome === 'accepted') {
      text = `The app session '${p.session}' received the tool's unique response over HTTPS with a self-signed certificate. Invalid certificate acceptance is proved for this loopback endpoint; other hosts and the responsible bypass mechanism are not established.`;
      sev = severity.HIGH; confirmed = true;
    } else if (p.test === 'run-as-node' && p.outcome === 'enabled') {
      text = 'The packaged executable exited with code 42 when launched with ELECTRON_RUN_AS_NODE=1 and the tool’s process.exit(42) expression. RunAsNode execution is proved.';
      sev = severity.HIGH; confirmed = true;
    } else if (p.test === 'node-inspector' && p.outcome === 'connected') {
      text = 'The tool connected to the packaged app’s Node inspector after launching it with a CLI inspect argument. CLI inspector support is proved; this port was opened by the tool and is not evidence that ordinary app launches expose it.';
      sev = severity.LOW; confirmed = true;
    } else if (p.test === 'ipc') {
      text = `Reviewed IPC '${p.channel || '(none)'}': ${p.outcome}. ${p.outcome === 'canary-read' ? 'The handler returned the tool-owned file canary through a real foreign-origin renderer.' : 'Resolution alone does not prove authorization bypass or a file read.'} The renderer has a tool-supplied IPC bridge; exposure through the app’s own renderer is untested. A ../ path to a tool file does not establish escape from the app’s allowed directory.`;
      if (p.outcome === 'canary-read') { sev = severity.MEDIUM; confirmed = true; }
    } else if (p.test === 'shell-handoff') {
      text = `The configured ${p.scope} test reached shell.${p.method} with scheme '${p.scheme || 'path'}'. The operating-system call was blocked by the tool. This proves route-to-shell flow for this test input.`;
      sev = severity.MEDIUM; confirmed = true;
    } else if (['navigation', 'window-open', 'permission-request', 'permission-check'].includes(p.test)) {
      // "blocked" means the app opened no window of its own: a handler that passes the URL to the operating system instead
      // (shell.openExternal) is no protection against a link with another scheme
      const handedOff = ['navigation', 'window-open'].includes(p.test) && proofs.some(h => h.test === 'shell-handoff' && h.scope === p.test);
      if (handedOff) {
        properties.handedToOs = true;
        text = `${p.test}: the app opened no window of its own, but its handler passed the URL to the operating system (shell.openExternal, blocked by the tool).`;
      }
      text += ' This is a synthetic handler-decision test with OS/process/file mutation guards, not a renderer reachability test.';
      if (p.actualSender) text += ' The permission handler received the existing renderer and a foreign requesting URL; handlers that inspect the actual renderer origin may give a different answer for a real foreign renderer.';
      confirmed = ['allowed', 'blocked', 'not-configured'].includes(p.outcome);
    } else if (p.test === 'update-feed') {
      if (p.source) text += ` Feed address source: ${p.source}.`;
      text += ' Only feed metadata was fetched; artifact hashes and publisher signature enforcement were not verified.';
      if (p.outcome === 'observed' && !p.secureTransport) { text += ' At least one feed hop used HTTP.'; sev = severity.MEDIUM; }
      if (p.outcome === 'observed' && !p.hashesPresent) text += ' Valid hashes were not present for every artifact.';
    } else if (p.test === 'local-service-cors') {
      const echoed = (p.origins || []).filter(o => o.allowOrigin === o.origin);
      const credentials = (p.origins || []).some(o => o.credentials && o.allowOrigin !== '*');
      const where = `port ${p.port} (${p.address})`;
      if (!['foreign-origin-allowed', 'no-cors-for-foreign-origin'].includes(p.outcome)) text = `Local service on ${where}: ${p.outcome}; not an HTTP service the probe could read.`;
      else {
        const allowed = [...new Set((p.origins || []).map(o => o.origin.replace(/:\/\/.*$/, '://…')))];
        text = `An app process serves HTTP on ${where}, answering an unauthenticated GET / with HTTP ${p.status}${p.contentType ? ` (${String(p.contentType).split(';')[0]})` : ''}.`;
        if (p.origins && p.origins.length) {
          text += ` It allows cross-origin reads from ${allowed.join(' and ')} origins (Access-Control-Allow-Origin: ${echoed.length ? 'the requesting origin' : '*'}${credentials ? ', with credentials' : ''}), so a web page${allowed.some(o => o.startsWith('chrome-extension')) ? ' or a browser extension' : ''} the user opens can call this service and read its answers.`;
          sev = credentials || echoed.length ? severity.HIGH : severity.MEDIUM;
          confirmed = true;
        }
        if (p.exposed) {
          text += ' The port is bound to every network interface, so other machines on the network can reach it.';
          if (sev === severity.INFORMATIONAL) sev = severity.MEDIUM;
          confirmed = true;
        }
        text += ' Only the root path was requested, without credentials; which routes need authentication is not established.';
      }
    } else if (p.test === 'local-service') {
      text += ' The configured route was requested without credentials; response status or a WebSocket handshake alone does not prove that protected data/actions are accessible.';
    } else if (p.test === 'auth-route') {
      text = `Unauthenticated GET ${p.route} on app-owned port ${p.port}: ${p.outcome}${p.status ? `, HTTP ${p.status}` : ''}. No credentials were sent and redirects were not followed. A response, including HTTP 200, does not establish access to a protected resource; public routes and SPA responses must be excluded before confirming an authentication bypass.`;
    }
    const id = sev === severity.INFORMATIONAL ? 'RUNTIME_PROOF' : p.test === 'certificate' ? 'RUNTIME_CERTIFICATE_PROOF' :
      ['run-as-node', 'node-inspector'].includes(p.test) ? 'RUNTIME_FUSE_PROOF' : p.test === 'ipc' ? 'RUNTIME_IPC_PROOF' :
        p.test === 'shell-handoff' ? 'RUNTIME_SHELL_PROOF' : p.test === 'update-feed' ? 'RUNTIME_UPDATE_PROOF' :
          p.test === 'local-service-cors' ? 'RUNTIME_LOCAL_SERVICE' : 'RUNTIME_PROOF';
    issues.push(issue(id, text, properties, sev, confirmed, p.scope || 'bounded-probe'));
  }
  for (const r of records.filter(r => r.kind === 'windows-acl')) {
    if (r.status !== 'observed') { issues.push(issue('WINDOWS_INSTALL_PERMISSIONS', `Install ACL inventory: ${r.status}; effective write access remains untested.`, { status: r.status })); continue; }
    for (const p of r.paths || []) {
      const broad = p.broadWrite || [];
      const current = p.currentTokenWriteGrants?.length || 0;
      issues.push(issue('WINDOWS_INSTALL_PERMISSIONS', `${p.path}: ${p.status}. ${broad.length ? 'The ACL contains write grants to broad user groups. Deny entries, inheritance and the attacker’s token need review before claiming effective code replacement or elevation.' : 'No broad-group write grant was identified by this bounded ACL review.'} ${current ? `Write grants match the current ${r.elevated ? 'elevated' : 'non-elevated'} token; same-account replacement needs review.` : 'No current-token write grant was identified.'} A per-user install can legitimately be writable by its owner; effective rights and privilege escalation are not established.`,
        { ...p, elevated: r.elevated }, broad.length || current && r.elevated === false ? severity.LOW : severity.INFORMATIONAL, p.status === 'observed', 'acl-configuration'));
    }
  }
  for (const r of records.filter(r => r.kind === 'windows-protocol')) {
    issues.push(issue('WINDOWS_PROTOCOL_REGISTRATION', `Protocol registry inventory: ${r.status}${r.errors ? `; ${r.errors} inaccessible keys/views` : ''}. Only registrations whose executable matches the app were selected.`, { status: r.status, errors: r.errors, count: r.protocols?.length || 0 }));
    for (const p of r.protocols || []) issues.push(issue('WINDOWS_PROTOCOL_REGISTRATION', `${p.scheme} (${p.hive}, ${p.view}): %1/%L ${p.hasArgument ? p.argumentQuoted ? 'is quoted' : 'is unquoted' : 'was not found'}, executable ${p.executableQuoted ? 'is quoted' : 'is unquoted'}. Switch injection and second-instance argument validation are not proved by the registry command alone.`,
      p, p.hasArgument && !p.argumentQuoted || !p.executableQuoted ? severity.LOW : severity.INFORMATIONAL, true, 'registry-configuration'));
  }
  const toolListeners = new Set(records.filter(r => r.kind === 'proof-listener').map(r => `${r.pid}:${r.port}`));
  const appSockets = records.filter(r => r.kind === 'windows-listener' && !r.toolInspector && !toolListeners.has(`${r.pid}:${r.port}`));
  // UDP endpoints are Chromium's own networking (QUIC, mDNS, WebRTC), not services that accept connections: one summary
  const listeners = appSockets.filter(r => r.transport !== 'udp');
  const udp = appSockets.filter(r => r.transport === 'udp');
  for (const p of listeners) issues.push(issue('WINDOWS_LOCAL_LISTENER', `App process ${p.pid} listens on ${p.address}:${p.port} (${p.transport}). Authentication and origin enforcement are untested unless a reviewed service route was supplied.`, p));
  if (udp.length) issues.push(issue('WINDOWS_LOCAL_LISTENER', `${udp.length} UDP endpoint(s) were open in the app's processes (${[...new Set(udp.map(p => `${p.address}:${p.port}`))].slice(0, 6).join(', ')}${udp.length > 6 ? ', …' : ''}). These are usually Chromium's own networking (QUIC, mDNS, WebRTC) rather than services; review only if the app implements its own UDP protocol.`,
    { transport: 'udp', count: udp.length, endpoints: udp.map(({ pid, address, port }) => ({ pid, address, port })) }));
  for (const p of records.filter(r => r.kind === 'windows-ports')) issues.push(issue('WINDOWS_LOCAL_LISTENER', `Listening-service inventory: ${p.status}.`, { status: p.status }));
  for (const p of records.filter(r => r.kind === 'motw')) issues.push(issue('WINDOWS_MARK_OF_THE_WEB', `Observed ${p.operation} file: Zone.Identifier ${p.status}${p.zone === undefined ? '' : ` (ZoneId ${p.zone})`}. This does not establish Word Protected View behavior, and a locally created file may legitimately have no zone stream.`, p, severity.INFORMATIONAL, ['present', 'absent'].includes(p.status), 'file-metadata'));
  const before = records.filter(r => r.kind === 'logout-snapshot' && r.phase === 'before').pop();
  const after = records.filter(r => r.kind === 'logout-snapshot' && r.phase === 'after').pop();
  if (before || after) {
    const prior = new Map((before?.entries || []).map(e => [`${e.store}:${e.key}`, e]));
    const retained = (after?.entries || []).filter(e => prior.get(`${e.store}:${e.key}`)?.value === e.value);
    const complete = !!before && !!after && before.t < after.t;
    issues.push(issue('RUNTIME_LOGOUT_RETENTION', complete ? `${retained.length} cookie/web-storage values remained unchanged after the tester marked logout; ${retained.filter(e => e.candidate).length} have credential-like names. Retention does not prove that a credential still authenticates. IndexedDB, OS credential stores and unvisited origins are outside the live-value comparison.` : 'Logout comparison is incomplete or out of order; both before/after markers are required.',
      { complete, before: prior.size, after: after?.entries?.length || 0, retained: complete ? retained : [], errors: [...(before?.errors || []), ...(after?.errors || [])] }, severity.INFORMATIONAL, complete, 'logout-retention'));
  }
  for (const r of records.filter(r => r.kind === 'logout-files')) issues.push(issue('RUNTIME_LOGOUT_FILES', `${r.retained?.length || 0} test-marker locations remained in app files after logout. Log/dump coverage is bounded; matches can be historical remnants and do not prove a credential works.`, r, severity.INFORMATIONAL, r.complete, 'logout-retention'));
  return { issues, summary: { attempts: proofs.length, outcomes: Object.fromEntries([...new Set(proofs.map(p => p.outcome))].map(o => [o, proofs.filter(p => p.outcome === o).length])),
    listeners: listeners.length, logout: !!before && !!after } };
}
