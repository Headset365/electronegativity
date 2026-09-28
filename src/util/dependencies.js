import { valid, coerce, compare, gt, gte, lt, major, prerelease } from 'semver';
import { assertOnline } from './network.js';

// The dependency table of the report: for each package or library the app ships or loads, when its version came out,
// what the latest version is, whether its version line is still supported and which advisories affect it.
//
// Sources: the npm registry (versions, release dates, deprecation), endoflife.date (support windows of projects that
// publish one) and OSV (advisories, with their CVE ids and fixed versions).

const REGISTRY = 'https://registry.npmjs.org/';
const EOL_API = 'https://endoflife.date/api/v1/products/';
const OSV_QUERY = 'https://api.osv.dev/v1/query';
const CONCURRENCY = 8;

// npm package -> endoflife.date product (the products that list an npm package, plus packages released with them)
const ANGULARJS_MODULES = /^angular(-(animate|aria|cookies|loader|message-format|messages|mocks|parse-ext|resource|route|sanitize|touch))?$/;
const EOL_PRODUCTS = {
  electron: 'electron', jquery: 'jquery', 'jquery-ui': 'jquery-ui', 'jquery-ui-dist': 'jquery-ui', bootstrap: 'bootstrap',
  react: 'react', 'react-dom': 'react', vue: 'vue', vuetify: 'vuetify', svelte: 'svelte', 'ember-source': 'emberjs',
  next: 'nextjs', nuxt: 'nuxt', express: 'express', eslint: 'eslint', grunt: 'grunt', protractor: 'protractor',
  tailwindcss: 'tailwind-css', quasar: 'quasar', 'react-native': 'react-native', '@ionic/core': 'ionic', '@ionic/angular': 'ionic',
  '@fortawesome/fontawesome-svg-core': 'font-awesome', 'font-awesome': 'font-awesome', ckeditor4: 'ckeditor', ckeditor: 'ckeditor',
  '@strapi/strapi': 'strapi', '@adonisjs/core': 'adonisjs', 'aws-cdk': 'amazon-cdk', yarn: 'yarn', pnpm: 'pnpm',
};
export function eolProduct(name) {
  if (EOL_PRODUCTS[name]) return EOL_PRODUCTS[name];
  if (ANGULARJS_MODULES.test(name)) return 'angularjs';
  if (/^@angular\//.test(name)) return 'angular';
  return undefined;
}

async function getJson(url, { timeout = 30000, body } = {}) {
  const response = await fetch(url, body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeout) }
    : { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(timeout) });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }));
  return results;
}

const day = (timestamp) => timestamp ? String(timestamp).slice(0, 10) : undefined;
const stable = (v) => valid(v) && !prerelease(v);

/** Release facts from an npm registry document, for `version`. */
export function registryFacts(doc, version) {
  const time = doc.time || {};
  const versions = Object.keys(doc.versions || {}).filter(stable).sort(compare);
  const latest = (doc['dist-tags'] && doc['dist-tags'].latest) || versions[versions.length - 1];
  const current = valid(version) || (coerce(version) && coerce(version).version);
  const facts = {
    released: day(time[version] || (current && time[current])),
    latest,
    latestReleased: day(latest && time[latest]),
    deprecated: current && doc.versions && doc.versions[current] && doc.versions[current].deprecated || undefined,
    known: !!(current && doc.versions && doc.versions[current]),
    ...projectLinks(doc),
  };
  if (current && latest && valid(latest)) {
    facts.versionsBehind = versions.filter(v => gt(v, current) && !gt(v, latest)).length;
    facts.majorsBehind = Math.max(0, major(latest) - major(current));
    // the newest release in the same major line, the smallest upgrade to pick up fixes
    facts.latestInMajor = versions.filter(v => major(v) === major(current) && gte(v, current)).pop();
  }
  return facts;
}

// git+https://github.com/owner/repo.git, git://github.com/owner/repo, github:owner/repo -> https://github.com/owner/repo
export function repositoryUrl(repository) {
  let url = typeof repository === 'string' ? repository : repository && repository.url;
  if (!url) return undefined;
  url = String(url).trim();
  const short = url.match(/^(?:github:)?([\w.-]+)\/([\w.-]+)$/);
  if (short) return `https://github.com/${short[1]}/${short[2]}`;
  url = url.replace(/^git\+/, '').replace(/^git:\/\//, 'https://').replace(/^ssh:\/\/git@/, 'https://').replace(/^git@([^:]+):/, 'https://$1/').replace(/#.*$/, '').replace(/\.git$/, '');
  return /^https?:\/\//.test(url) ? url : undefined;
}

// where to read about the project and its newer versions: homepage, repository and its release notes
function projectLinks(doc) {
  const latest = (doc['dist-tags'] && doc['dist-tags'].latest) || undefined;
  const latestManifest = (latest && doc.versions && doc.versions[latest]) || {};
  const repository = repositoryUrl(doc.repository || latestManifest.repository);
  const homepage = doc.homepage || latestManifest.homepage;
  return {
    homepage: /^https?:\/\//.test(homepage || '') ? homepage : undefined,
    repository,
    releaseNotes: repository && /^https:\/\/(github\.com|gitlab\.com)\//.test(repository) ? `${repository}/${repository.includes('gitlab.com') ? '-/releases' : 'releases'}` : undefined,
  };
}

/** Support status from an endoflife.date product, for `version`. */
export function supportFacts(product, version) {
  const current = coerce(version);
  if (!product || !current) return undefined;
  const releases = product.releases || [];
  // the release cycle is named after the version prefix it covers: "1.8" or "3"
  const cycle = releases
    .filter(r => { const parts = String(r.name).split('.'); return parts.every((p, i) => Number(p) === [current.major, current.minor, current.patch][i]); })
    .sort((a, b) => String(b.name).length - String(a.name).length)[0];
  const open = releases.filter(r => !r.isEol).map(r => `${r.name}.x`);
  // every release line past its end of life: the project is discontinued
  const supported = open.length > 0 ? open : ['none (all release lines are end of life)'];
  const policy = (product.links && product.links.releasePolicy) || (product.links && product.links.html);
  if (!cycle) {
    const oldest = releases.map(r => coerce(r.name)).filter(Boolean).sort(compare)[0];
    if (oldest && lt(current, oldest)) return { status: 'unsupported', detail: 'Older than every release line the project tracks', supported, policy, source: 'endoflife.date' };
    return { status: 'unknown', detail: 'Release line not listed by endoflife.date', supported, policy, source: 'endoflife.date' };
  }
  const extended = cycle.isEol && cycle.isMaintained && cycle.custom && cycle.custom.eoesProvider;
  return {
    status: cycle.isEol ? 'unsupported' : 'supported',
    detail: cycle.isEol
      ? `${cycle.name}.x reached end of life${cycle.eolFrom ? ` on ${cycle.eolFrom}` : ''}${extended ? ` (paid extended support: ${cycle.custom.eoesProvider})` : ''}`
      : `${cycle.name}.x is supported${cycle.eolFrom ? ` until ${cycle.eolFrom}` : ''}`,
    eol: cycle.eolFrom || undefined,
    supported,
    policy,
    source: 'endoflife.date',
  };
}

/** The advisories of an OSV query result, reduced to what the report shows. */
export function advisoryFacts(vulns, name, version) {
  const current = coerce(version) && coerce(version).version;
  return (vulns || []).filter(v => !v.withdrawn).map(v => {
    const cves = (v.aliases || []).filter(a => /^CVE-/.test(a));
    let fixed;
    for (const affected of v.affected || []) {
      if (!affected.package || affected.package.ecosystem !== 'npm' || affected.package.name !== name) continue;
      for (const range of affected.ranges || []) {
        if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
        let introduced;
        for (const event of range.events || []) {
          if (event.introduced !== undefined) introduced = event.introduced === '0' ? '0.0.0' : event.introduced;
          if (event.fixed && current && valid(event.fixed) && valid(introduced) && gte(current, introduced) && lt(current, event.fixed)) fixed = event.fixed;
        }
      }
    }
    const level = (v.database_specific && v.database_specific.severity) || undefined;
    // the advisory's own references: the advisory page, the fix, the report (a few, web links only)
    const references = (v.references || []).filter(r => /^https?:\/\//.test(r.url || '') && ['ADVISORY', 'FIX', 'REPORT', 'WEB', 'ARTICLE'].includes(r.type))
      .sort((a, b) => ['ADVISORY', 'FIX', 'REPORT', 'ARTICLE', 'WEB'].indexOf(a.type) - ['ADVISORY', 'FIX', 'REPORT', 'ARTICLE', 'WEB'].indexOf(b.type))
      .filter((r, i, all) => all.findIndex(o => o.url === r.url) === i).slice(0, 5).map(r => ({ type: r.type, url: r.url }));
    return { id: v.id, cves, summary: v.summary || (v.details || '').split('\n')[0].slice(0, 200), severity: level ? String(level).toUpperCase().replace('MODERATE', 'MEDIUM') : undefined, fixed, references,
      published: day(v.published) };
  }).sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', undefined];

// Status when no support policy is published: deprecation, or how far behind the latest major version it is
function inferredSupport(registry) {
  if (!registry) return { status: 'unknown', detail: 'Not found on npm', supported: [] };
  const latestLine = registry.latest && valid(registry.latest) ? [`${major(registry.latest)}.x (latest; no published policy)`] : [];
  if (registry.deprecated) return { status: 'unsupported', detail: `Deprecated on npm: ${registry.deprecated}`, supported: latestLine };
  if (registry.majorsBehind > 0) return { status: 'outdated', detail: `No published support policy; ${registry.majorsBehind} major version${registry.majorsBehind > 1 ? 's' : ''} behind the latest`, supported: latestLine };
  return { status: 'current', detail: 'No published support policy; on the latest major version', supported: latestLine };
}

/**
 * Builds the dependency table.
 * @param {Array<{name, version, kind, direct, dev, files}>} packages
 * @returns {Promise<{rows, errors, offline}>}
 */
export async function dependencyReport(packages, { concurrency = CONCURRENCY } = {}) {
  const rows = packages.map(p => ({ ...p, advisories: [] }));
  try {
    assertOnline();
  } catch {
    for (const row of rows) row.support = { status: 'unknown', detail: 'Not looked up (offline)', supported: [] };
    return { rows, errors: [], offline: true };
  }
  const errors = [];
  const registryDocs = new Map();
  const products = new Map();
  const names = [...new Set(rows.map(r => r.name))];

  await mapLimit(names, concurrency, async (name) => {
    try {
      registryDocs.set(name, await getJson(REGISTRY + name.replace('/', '%2f')));
    } catch (e) {
      errors.push({ source: 'npm registry', name, message: String(e.message) });
    }
  });
  await mapLimit([...new Set(names.map(eolProduct).filter(Boolean))], concurrency, async (product) => {
    try {
      const json = await getJson(EOL_API + product);
      if (json) products.set(product, json.result);
    } catch (e) {
      errors.push({ source: 'endoflife.date', name: product, message: String(e.message) });
    }
  });
  await mapLimit(rows, concurrency, async (row) => {
    try {
      const json = await getJson(OSV_QUERY, { body: { package: { name: row.name, ecosystem: 'npm' }, version: row.version } });
      row.advisories = advisoryFacts(json && json.vulns, row.name, row.version);
    } catch (e) {
      row.advisoryError = true;
      errors.push({ source: 'OSV', name: row.name, message: String(e.message) });
    }
  });

  for (const row of rows) {
    const doc = registryDocs.get(row.name);
    if (doc) Object.assign(row, registryFacts(doc, row.version));
    row.support = supportFacts(products.get(eolProduct(row.name)), row.version) || inferredSupport(doc && row);
    // maintainers deprecate individual versions inside a supported line (jQuery 3.4.1): an upgrade within it is due
    if (row.support.status === 'supported' && row.deprecated) row.support = { ...row.support, status: 'unsupported', detail: `Deprecated on npm: ${row.deprecated}` };
    const fixes = row.advisories.map(a => a.fixed);
    if (fixes.length > 0) row.fixedIn = fixes.includes(undefined) ? null : fixes.sort(compare).pop();
  }
  return { rows, errors, offline: false };
}

const STATUS_ORDER = ['unsupported', 'outdated', 'unknown', 'current', 'supported'];
export function sortRows(rows) {
  return [...rows].sort((a, b) =>
    (b.advisories.length > 0) - (a.advisories.length > 0) ||
    STATUS_ORDER.indexOf(a.support.status) - STATUS_ORDER.indexOf(b.support.status) ||
    (b.direct === true) - (a.direct === true) ||
    a.name.localeCompare(b.name) || compare(coerce(a.version) || '0.0.0', coerce(b.version) || '0.0.0'));
}
