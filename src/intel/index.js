// Vulnerability intelligence on top of the dependency table: which advisories CISA lists as exploited in the wild (KEV),
// FIRST's exploit probability (EPSS), known-malicious package versions, and the Chromium CVEs that affect the Chromium
// build inside the app's Electron, minus the fixes Electron's release notes say were backported into that version.
// Every lookup is cached on disk and degrades to "not checked" when a source is unreachable. A port of
// Electron-Dynamic's static/intel.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { isOffline } from '../util/network.js';
import { cacheDir, writeCacheFile } from '../util/cache.js';

const DAY = 24 * 60 * 60 * 1000;
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = 'https://api.first.org/data/v1/epss?cve=';
export const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:google:chrome:';
export const RELEASES_URL = 'https://releases.electronjs.org/releases.json';
export const RELEASE_PAGE = 'https://releases.electronjs.org/release/v';

// Package versions known to be malicious or sabotaged (OSV's MAL- advisories cover newer cases)
export const KNOWN_MALICIOUS = {
  'event-stream': ['3.3.6'], 'flatmap-stream': null, 'eslint-scope': ['3.7.2'], 'eslint-config-eslint': ['5.0.2'],
  'ua-parser-js': ['0.7.29', '0.8.0', '1.0.0'], coa: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'], rc: ['1.2.9', '1.3.9', '2.3.9'],
  'node-ipc': ['9.2.2', '10.1.1', '10.1.2'], colors: ['1.4.44-liberty-2', '1.4.1'], faker: ['6.6.6'],
};

const cacheFile = (key) => path.join(cacheDir(), `${key.replace(/[^\w.-]/g, '_').slice(0, 150)}.json`);

/**
 * GET (or POST) JSON or text through a disk cache. A fresh cached copy is used as is; a failed request falls back to a
 * stale copy; with no copy it returns undefined. `fetchImpl` is for tests.
 */
export async function cached(url, { key = url, ttl = DAY, text = false, headers = {}, timeout = 30000, fetchImpl = fetch } = {}) {
  const file = cacheFile(key);
  let stale;
  try {
    const stat = fs.statSync(file);
    stale = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (Date.now() - stat.mtimeMs < ttl) return stale;
  } catch {
    // no cached copy
  }
  if (isOffline()) return stale;
  try {
    const response = await fetchImpl(url, { headers: { 'User-Agent': 'electronegativity', ...headers }, signal: AbortSignal.timeout(timeout) });
    if (!response.ok) return stale;
    const value = text ? await response.text() : await response.json();
    try {
      writeCacheFile(file, JSON.stringify(value));
    } catch {
      // the cache is optional
    }
    return value;
  } catch {
    return stale;
  }
}

/** CVE id -> { name, added, due, ransomware } from CISA's Known Exploited Vulnerabilities catalog. */
export async function kevCatalog(options) {
  const data = await cached(KEV_URL, { key: 'cisa-kev', ...options });
  const out = new Map();
  for (const v of (data && data.vulnerabilities) || []) if (v.cveID) out.set(v.cveID, { name: v.vulnerabilityName, added: v.dateAdded, due: v.dueDate, ransomware: v.knownRansomwareCampaignUse === 'Known' });
  return out;
}

/** CVE id -> { epss, percentile } from FIRST, 100 CVEs per request. */
export async function epssScores(cves, options) {
  const out = new Map();
  const list = [...new Set(cves)].sort();
  for (let i = 0; i < list.length; i += 100) {
    const chunk = list.slice(i, i + 100);
    const key = `epss-${crypto.createHash('sha1').update(chunk.join(',')).digest('hex').slice(0, 16)}`;
    const data = await cached(EPSS_URL + chunk.join(','), { key, ...options });
    for (const row of (data && data.data) || []) out.set(row.cve, { epss: Number(row.epss), percentile: Number(row.percentile) });
  }
  return out;
}

const isMalicious = (name, version) => Object.hasOwn(KNOWN_MALICIOUS, name) && (KNOWN_MALICIOUS[name] === null || KNOWN_MALICIOUS[name].includes(version));

/**
 * Adds to the dependency table's advisories whether CISA lists them as exploited (kev) and their EPSS score, and marks
 * malicious package versions (row.malicious: an OSV MAL- advisory, or the known list). Mutates `report`.
 * @returns {{ checked: boolean, kev: number, malicious: number }}
 */
export async function enrichDependencies(report, options = {}) {
  const rows = (report && report.rows) || [];
  for (const row of rows) {
    // Vulnerability summaries often describe malicious input, not a malicious published package. OSV's MAL
    // identifiers and the curated version list establish package provenance; summary keywords do not.
    const mal = row.advisories.find(a => /^MAL-/.test(a.id));
    if (mal) row.malicious = { source: 'OSV', id: mal.id };
    else if (isMalicious(row.name, row.version)) row.malicious = { source: 'known list', id: `MAL-${row.name}` };
  }
  const summary = { checked: false, kev: 0, malicious: rows.filter(r => r.malicious).length };
  if (report.offline || isOffline()) return summary;
  const cves = rows.flatMap(r => r.advisories.flatMap(a => [a.id, ...(a.cves || [])])).filter(id => /^CVE-/.test(id));
  if (cves.length === 0) return { ...summary, checked: true };
  const [kev, epss] = await Promise.all([kevCatalog(options), epssScores(cves, options)]);
  for (const row of rows) {
    for (const advisory of row.advisories) {
      const ids = [advisory.id, ...(advisory.cves || [])];
      const listed = ids.map(id => kev.get(id)).find(Boolean);
      if (listed) advisory.kev = listed;
      const score = ids.map(id => epss.get(id)).filter(Boolean).sort((a, b) => b.epss - a.epss)[0];
      if (score) advisory.epss = score;
    }
    row.kev = row.advisories.some(a => a.kev);
  }
  return { ...summary, checked: kev.size > 0, kev: rows.filter(r => r.kev).length };
}

const vt = (version) => String(version || '').split('-')[0].split('.').map(Number);
const cmp = (a, b) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d) return d;
  }
  return 0;
};
const STABLE = /^\d+\.\d+\.\d+$/;

/** Every Electron release with the Chromium version it ships (releases.electronjs.org). */
export async function electronReleases(options) {
  const data = await cached(RELEASES_URL, { key: 'electron-releases-full', ttl: DAY / 2, ...options });
  return Array.isArray(data) ? data : [];
}

/** The Chromium version inside an Electron release. */
export function chromiumOf(releases, electron) {
  const release = releases.find(r => r.version === String(electron).replace(/^v/, ''));
  return release && release.chrome ? String(release.chrome) : undefined;
}

// "Security: backported fix for CVE-2023-1234, CVE-2023-5678 and CVE-..." in a release page
export function backportedCves(page) {
  const text = String(page || '').replace(/<[^>]+>/g, ' ');
  const out = new Set();
  for (const m of text.matchAll(/backport(?:ed)?\s+(?:the\s+)?fix(?:es)?\s+for\s+((?:CVE-\d{4}-\d{4,}[\s,and]*)+)/gi))
    for (const cve of m[1].match(/CVE-\d{4}-\d{4,}/g) || []) out.add(cve);
  return out;
}

/**
 * The Chromium fixes Electron backported into this version and into later releases of its major line, from the release
 * notes. @returns {{ checked, inBuild: Map<cve, version>, later: Map<cve, version>, note? }}
 */
export async function electronBackports(electron, releases, options = {}) {
  const out = { checked: false, inBuild: new Map(), later: new Map() };
  if (!electron || !STABLE.test(electron)) return { ...out, note: 'Electron version not identified (or a pre-release)' };
  const major = vt(electron)[0];
  const versions = [...new Set(releases.map(r => String(r.version)).filter(v => STABLE.test(v) && vt(v)[0] === major))].sort((a, b) => cmp(vt(a), vt(b)));
  const pages = new Map();
  let next = 0;
  // release notes don't change once published: cached for 30 days
  await Promise.all(Array.from({ length: Math.min(8, versions.length) }, async () => {
    while (next < versions.length) {
      const version = versions[next++];
      pages.set(version, await cached(RELEASE_PAGE + version, { key: `electron-notes-${version}`, ttl: 30 * DAY, text: true, ...options }));
    }
  }));
  const mine = vt(electron);
  for (const version of versions) {
    const target = cmp(vt(version), mine) <= 0 ? out.inBuild : out.later;
    for (const cve of backportedCves(pages.get(version))) if (!target.has(cve)) target.set(cve, version);
  }
  for (const cve of out.later.keys()) if (out.inBuild.has(cve)) out.later.delete(cve);
  const missing = versions.filter(v => !pages.get(v));
  out.checked = missing.length < versions.length;
  if (missing.length) out.note = `release notes unavailable for ${missing.length} of ${versions.length} ${major}.x releases`;
  return out;
}

// whether an NVD CVE's google:chrome configuration covers `version`; [hit, fixed in]
export function chromeMatch(cve, version) {
  for (const config of cve.configurations || []) {
    for (const node of config.nodes || []) {
      for (const match of node.cpeMatch || []) {
        const parts = String(match.criteria || '').split(':');
        if (parts[3] !== 'google' || parts[4] !== 'chrome' || !match.vulnerable) continue;
        if (!['*', '-'].includes(parts[5])) {
          if (cmp(vt(parts[5]), version) === 0) return [true, undefined];
          continue;
        }
        const { versionEndExcluding: endX, versionEndIncluding: endI, versionStartIncluding: startI, versionStartExcluding: startX } = match;
        if (!endX && !endI) continue; // unbounded: not version-specific
        if (startI && cmp(version, vt(startI)) < 0) continue;
        if (startX && cmp(version, vt(startX)) <= 0) continue;
        if (endX && cmp(version, vt(endX)) >= 0) continue;
        if (endI && cmp(version, vt(endI)) > 0) continue;
        return [true, endX];
      }
    }
  }
  return [false, undefined];
}

function cvssOf(cve) {
  const metrics = cve.metrics || {};
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']) {
    for (const m of metrics[key] || []) if (m.cvssData && m.cvssData.baseSeverity) return [m.cvssData.baseSeverity.toLowerCase(), m.cvssData.baseScore];
  }
  for (const m of metrics.cvssMetricV2 || []) return [(m.baseSeverity || '').toLowerCase() || undefined, m.cvssData && m.cvssData.baseScore];
  return [undefined, undefined];
}

/**
 * The Chromium CVEs fixed upstream after the Chromium build in this Electron version, minus Electron's backports, from
 * NVD (CPE google:chrome). Each open CVE names the first Electron release carrying its fix. NVD allows 5 requests in
 * 30 s without an API key (NVD_API_KEY raises it).
 */
export async function chromiumAdvisories({ electron, chromium, releases = [], kev = new Map(), top = 25, options = {}, sleep = (ms) => new Promise(r => setTimeout(r, ms)) }) {
  const out = { chromium, checked: false };
  if (!chromium || vt(chromium).some(Number.isNaN)) return { ...out, note: 'Chromium version not identified' };
  if (isOffline()) return { ...out, note: 'not checked (--offline)' };
  const apiKey = process.env.NVD_API_KEY;
  const items = [];
  let total;
  for (let page = 0; page < 5; page++) {
    const data = await cached(`${NVD_URL}${chromium}&resultsPerPage=2000&startIndex=${items.length}`, { key: `nvd-chrome-${chromium}-${items.length}`, timeout: 120000,
      headers: apiKey ? { apiKey } : {}, ...options });
    if (!data || !Array.isArray(data.vulnerabilities)) {
      out.note = 'NVD unreachable or rate-limited (set NVD_API_KEY to raise the limit)';
      break;
    }
    items.push(...data.vulnerabilities);
    total = data.totalResults ?? items.length;
    if (items.length >= total || data.vulnerabilities.length === 0) break;
    if (!apiKey) await sleep(6500);
  }
  if (items.length === 0) return out;
  const version = vt(chromium);
  const backports = await electronBackports(electron, releases, options);
  const major = electron ? vt(electron)[0] : undefined;
  const stable = releases.filter(r => STABLE.test(String(r.version)) && r.chrome).map(r => ({ version: r.version, v: vt(r.version), chrome: vt(r.chrome) })).sort((a, b) => cmp(a.v, b.v));
  const firstFix = (fixed) => {
    if (!fixed) return undefined;
    const need = vt(fixed);
    const hit = stable.find(r => r.v[0] === major && cmp(r.chrome, need) >= 0) || stable.find(r => cmp(r.chrome, need) >= 0);
    return hit && hit.version;
  };
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const open = [];
  const backported = [];
  for (const { cve } of items) {
    const [hit, fixed] = chromeMatch(cve || {}, version);
    if (!hit) continue;
    const [sev, score] = cvssOf(cve);
    const row = { id: cve.id, severity: sev || 'unknown', score, fixedIn: fixed, published: String(cve.published || '').slice(0, 10), kev: kev.has(cve.id),
      summary: ((cve.descriptions || []).find(d => d.lang === 'en') || {}).value?.slice(0, 220),
      cwes: [...new Set((cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(id => /^CWE-\d+$/.test(id || '')))] };
    if (backports.inBuild.has(cve.id)) {
      backported.push({ ...row, backportedIn: backports.inBuild.get(cve.id) });
      continue;
    }
    counts[counts[row.severity] !== undefined ? row.severity : 'unknown']++;
    row.electronFix = backports.later.get(cve.id) || firstFix(fixed);
    open.push(row);
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  open.sort((a, b) => Number(b.kev) - Number(a.kev) || rank[a.severity] - rank[b.severity] || (b.score || 0) - (a.score || 0));
  return { ...out, checked: true, partial: total !== undefined && items.length < total, total: open.length, counts, kev: open.filter(r => r.kev).length,
    top: open.slice(0, top), backported: backported.length, backportedTop: backported.slice(0, top), backportsChecked: backports.checked, backportsNote: backports.note,
    source: `NVD (CPE google:chrome), CISA KEV${backports.checked ? ', Electron release notes' : ''}` };
}
