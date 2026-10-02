// Keep declaration, package presence and runtime loading separate. A missing
// package manifest cannot establish that code was not bundled into JavaScript.
export function annotateShipment(rows, { packaged = false } = {}) {
  for (const row of rows) {
    const kinds = row.kinds || [];
    const present = kinds.some(k => ['node_modules', 'bundled library', 'Electron runtime'].includes(k));
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
