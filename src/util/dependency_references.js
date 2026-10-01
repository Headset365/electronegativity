// Sources shared by the HTML dependency report and the components workbook.
export const npmUrl = (name, version) => `https://www.npmjs.com/package/${name.split('/').map(encodeURIComponent).join('/')}${version ? `/v/${encodeURIComponent(version)}` : ''}`;

const LABELS = { ADVISORY: 'advisory', FIX: 'fix', REPORT: 'report', ARTICLE: 'article', WEB: 'reference' };

function uniqueWebReferences(references) {
  const seen = new Set();
  return references.filter(({ url }) => {
    // eslint-disable-next-line no-control-regex
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url) || /[\s\u0000-\u001f\u007f]/u.test(url) || seen.has(url)) return false;
    try { if (!new URL(url).hostname) return false; } catch { return false; }
    seen.add(url);
    return true;
  });
}

export function projectReferences(row) {
  const references = [];
  if (row.latest && row.known !== undefined) references.push({ url: npmUrl(row.name, row.latest), label: 'npm' });
  if (row.releaseNotes) references.push({ url: row.releaseNotes, label: 'release notes' });
  if (row.repository) references.push({ url: row.repository, label: 'repository' });
  if (row.homepage && !String(row.homepage).startsWith(`${row.repository}#`)) references.push({ url: row.homepage, label: 'homepage' });
  if (row.support?.policy) references.push({ url: row.support.policy, label: 'support policy' });
  return uniqueWebReferences(references);
}

export function advisoryReferences(advisory) {
  const references = [];
  if (advisory.id) {
    references.push({ url: `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`, label: 'OSV advisory' });
    if (/^GHSA-/.test(advisory.id)) references.push({ url: `https://github.com/advisories/${encodeURIComponent(advisory.id)}`, label: 'GitHub advisory' });
  }
  for (const ref of advisory.references || []) references.push({ url: ref.url, label: LABELS[ref.type] || 'reference' });
  return uniqueWebReferences(references);
}

/** Every source for one component, once per URL, including the installed and fixed versions. */
export function componentReferences(row) {
  const references = [{ url: npmUrl(row.name), label: 'npm package' }];
  if (row.known) references.push({ url: npmUrl(row.name, row.version), label: 'installed version' });
  if (row.latest) references.push({ url: npmUrl(row.name, row.latest), label: 'latest version' });
  if (row.latestInMajor && row.latestInMajor !== row.version) references.push({ url: npmUrl(row.name, row.latestInMajor), label: 'latest in installed major' });
  references.push(...projectReferences(row));
  for (const advisory of row.advisories || []) {
    const sources = (advisory.cves || []).map(cve => ({ url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`, label: cve }));
    sources.push(...advisoryReferences(advisory));
    if (advisory.fixed) sources.push({ url: npmUrl(row.name, advisory.fixed), label: `fixed version (${advisory.fixed})` });
    references.push(...sources.map(ref => ({ ...ref, advisory: advisory.id })));
  }
  if (row.malicious?.id) references.push(...advisoryReferences(row.malicious).map(ref => ({ ...ref, advisory: row.malicious.id })));
  return uniqueWebReferences(references);
}
