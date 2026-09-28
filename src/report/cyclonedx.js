// A CycloneDX 1.5 SBOM (JSON) of what the app ships: the Electron runtime, npm packages and bundled library copies, with
// the known vulnerabilities of each (OSV advisories, CISA KEV and EPSS where they were looked up) and the Chromium
// advisories of the bundled build. Written with `-o report.cdx.json`.
import crypto from 'node:crypto';
import pkg from '../../package.json' with { type: 'json' };

const purl = (name, version) => `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${encodeURIComponent(version)}`;
const rating = (level) => ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', MODERATE: 'medium', LOW: 'low' })[String(level || '').toUpperCase()] || 'unknown';

/** @param {Object} meta the report meta: dependencies (the dependency table), app ({ name, version }), electronVersion */
export function cycloneDx(meta) {
  const rows = (meta.dependencies && meta.dependencies.rows) || [];
  const app = meta.app || {};
  const components = [];
  const vulnerabilities = [];
  const refs = new Set();
  for (const row of rows) {
    const ref = purl(row.name, row.version);
    if (refs.has(ref)) continue;
    refs.add(ref);
    const properties = [{ name: 'electronegativity:found-as', value: row.kinds.join(', ') }];
    if (row.support) properties.push({ name: 'electronegativity:support', value: row.support.status });
    if (row.latest) properties.push({ name: 'electronegativity:latest-version', value: row.latest });
    if (row.dev) properties.push({ name: 'electronegativity:development-only', value: 'true' });
    if (row.malicious) properties.push({ name: 'electronegativity:malicious', value: row.malicious.id });
    for (const file of row.files || []) properties.push({ name: 'electronegativity:file', value: file });
    components.push({ type: row.name === 'electron' ? 'framework' : 'library', 'bom-ref': ref, name: row.name, version: row.version, purl: ref, properties });
    for (const advisory of row.advisories || []) {
      const vulnerability = {
        'bom-ref': `${advisory.id}@${ref}`, id: advisory.cves && advisory.cves[0] ? advisory.cves[0] : advisory.id,
        source: { name: 'OSV', url: `https://osv.dev/vulnerability/${advisory.id}` },
        references: [advisory.id, ...(advisory.cves || [])].filter((id, i, all) => all.indexOf(id) === i).map(id => ({ id, source: { name: /^CVE-/.test(id) ? 'NVD' : 'OSV', url: /^CVE-/.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${id}` } })),
        ratings: [{ severity: rating(advisory.severity), source: { name: 'OSV' } }],
        description: advisory.summary, published: advisory.published ? `${advisory.published}T00:00:00Z` : undefined,
        recommendation: advisory.fixed ? `Upgrade ${row.name} to ${advisory.fixed} or later` : undefined,
        affects: [{ ref }], properties: [],
      };
      if (advisory.kev) vulnerability.properties.push({ name: 'cisa:kev', value: 'true' }, { name: 'cisa:kev:date-added', value: advisory.kev.added || '' });
      if (advisory.epss) vulnerability.properties.push({ name: 'first:epss', value: String(advisory.epss.epss) }, { name: 'first:epss:percentile', value: String(advisory.epss.percentile) });
      vulnerabilities.push(vulnerability);
    }
  }
  const chromium = meta.dependencies && meta.dependencies.chromium;
  const electron = rows.find(r => r.name === 'electron');
  if (chromium && chromium.checked && electron) {
    const ref = purl('electron', electron.version);
    for (const cve of chromium.top) {
      vulnerabilities.push({ 'bom-ref': `${cve.id}@chromium`, id: cve.id, source: { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cve.id}` },
        ratings: [{ severity: rating(cve.severity), score: cve.score, source: { name: 'NVD' } }], description: `Chromium ${chromium.chromium}: ${cve.summary || ''}`,
        recommendation: cve.electronFix ? `Upgrade Electron to ${cve.electronFix} or later` : undefined, affects: [{ ref }],
        properties: [...(cve.kev ? [{ name: 'cisa:kev', value: 'true' }] : []), { name: 'electronegativity:chromium-open-advisories', value: String(chromium.total) }] });
    }
  }
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1,
    metadata: {
      timestamp: meta.generatedAt || new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'Electronegativity', version: pkg.version }] },
      component: { type: 'application', 'bom-ref': 'app', name: app.name || 'app', ...(app.version ? { version: app.version } : {}) },
    },
    components,
    dependencies: [{ ref: 'app', dependsOn: components.map(c => c['bom-ref']) }],
    vulnerabilities: vulnerabilities.map(v => JSON.parse(JSON.stringify(v))), // drop undefined fields
  };
}
