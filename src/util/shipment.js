// Keep declaration, package presence and runtime loading separate. A missing
// package manifest cannot establish that code was not bundled into JavaScript.
export function annotateShipment(rows, { packaged = false } = {}) {
  for (const row of rows) {
    const kinds = row.kinds || [];
    const present = kinds.some(k => ['node_modules', 'bundled library', 'Electron runtime'].includes(k));
    // loaded at run time from the app's server, never installed: the fix belongs to the server-hosted front end
    if (!present && kinds.includes('served by the app server')) {
      row.shipment = { status: 'loaded-from-server', evidence: kinds.filter(k => k !== 'lockfile'), scope: 'server-hosted-front-end',
        note: 'Found only in code the app loads from its server, not in the installed package; the fix is a server-side deployment.' };
      row.dev = false;
      continue;
    }
    row.shipment = {
      status: present ? packaged ? 'present-in-package' : 'present-in-scanned-code' : row.dev ? 'development-metadata-only' : 'unverified',
      evidence: kinds.filter(k => k !== 'lockfile'),
      scope: packaged ? 'shipped-package-inventory' : 'source-inventory',
      note: present ? 'Presence is established; vulnerability reachability remains untested.' :
        row.dev ? 'Development declaration only. Review build/supply-chain risk; bundled runtime presence is not established.' : 'Lockfile declaration only; shipped presence is not established.',
    };
    // A package shipped despite being declared dev is still a runtime component.
    if (present) row.dev = false;
  }
  return rows;
}
