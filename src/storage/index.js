// The data-at-rest review (--user-data, and after a watch session) and the saved-credential trace (--canary), turned
// into findings like the others.
import path from 'node:path';
import fs from 'node:fs';
import { severity, confidence } from '../finder/attributes.js';
import { defaultProfileDirs, reviewProfile } from './at_rest.js';
import { searchRoots, snapshot, changedFiles, credentialTargets, scanForCanaries } from './canary.js';

const finding = (id, file, sev, conf, description, properties, reference, sample = '') => ({
  file, sample, location: { line: 0, column: 0 }, id, description, properties, shortenedURL: reference, severity: sev, confidence: conf,
  manualReview: conf !== confidence.CERTAIN && sev !== severity.INFORMATIONAL,
  visibility: { excludesGlobal: [], inlineDisabled: false, globalDisabled: false, globalCheckDisabled: false }, constructorName: 'Runtime',
});

const SAFE_STORAGE = 'https://www.electronjs.org/docs/latest/api/safe-storage';
const COOKIE_FUSE = 'https://www.electronjs.org/docs/latest/tutorial/fuses#encryptedcookies';

/**
 * Before a watch session: what the app's folders and the Credential Manager hold, to compare with afterwards.
 * @param {{ names: string[], searchDirs?: string[], userData?: string, installDir?: string }} options
 */
export function credentialBaseline({ names, searchDirs = [], userData, installDir }) {
  const roots = searchRoots(names, { extra: [...searchDirs, ...(userData && userData !== 'auto' ? [userData] : [])], installDir });
  return { roots, files: snapshot(roots), targets: credentialTargets() };
}

const isDir = (dir) => {
  try {
    return fs.statSync(dir).isDirectory();
  } catch {
    return false;
  }
};

/**
 * @param {Object} options
 * @param {string[]} options.names the app's names (productName, package name, publisher): its folders are named after them
 * @param {string} [options.userData] the profile folder, or 'auto' to find it by name
 * @param {string} [options.observedUserData] the profile folder the app reported while it ran (watch mode)
 * @param {boolean} [options.review] review the profile (--user-data, or after a watch session)
 * @param {string[]} [options.canaries] test passwords typed into the app
 * @param {string[]} [options.searchDirs] more folders to search for them
 * @param {string} [options.installDir] the app's install folder, searched too
 * @param {Object} [options.baseline] credentialBaseline() taken before the session
 * @param {boolean} [options.cookieEncryption] the EnableCookieEncryption fuse, when known
 * @param {boolean} [options.reveal] keep full values in the report (--show-secrets)
 * @returns {{ issues: Array, summary: Object, notes: string[] }}
 */
export function reviewDataAtRest({ names = [], userData, observedUserData, review = false, canaries = [], searchDirs = [], installDir, baseline, cookieEncryption, reveal = false }) {
  const issues = [];
  const notes = [];
  const summary = {};

  // --- the profile: web storage and cookies ---
  if (review || userData) {
    const profiles = userData && userData !== 'auto' ? [userData] : [observedUserData, ...defaultProfileDirs(names)].filter(Boolean);
    const profile = profiles.find(isDir);
    if (!profile) notes.push(userData && userData !== 'auto' ? `--user-data: ${userData} is not a readable folder` : `no profile folder found for ${names.join(', ') || 'the app'}: give it with --user-data`);
    else {
      const data = reviewProfile(profile, { cookieEncryption, reveal });
      summary.profile = { path: profile, revealed: reveal, webStorage: data.webStorage.length, cookies: data.cookies.total || 0, cookieError: data.cookies.error,
        insecureCookieFlags: data.cookies.insecureFlags || [] };
      for (const w of data.webStorage) {
        const where = w.origin ? `${w.store} (${w.origin})` : w.store;
        const uncertain = w.basis === 'entropy';
        issues.push(finding('STORAGE_SECRET_AT_REST', path.join(profile, w.store === 'Local Storage' ? 'Local Storage/leveldb' : w.store),
          uncertain ? severity.INFORMATIONAL : w.basis === 'name' ? severity.LOW : severity.MEDIUM,
          uncertain ? confidence.TENTATIVE : confidence.FIRM,
          `${w.kind} kept in ${where}${w.key ? ` under the key '${w.key}'` : ''}; ${uncertain ? 'the value may be an identifier, so determine whether it is a credential' : 'review whether this value grants access and who can read the profile'}`,
          { store: w.store, origin: w.origin, key: w.key, kind: w.kind, basis: w.basis }, 'https://cwe.mitre.org/data/definitions/312.html', `${w.kind}: ${w.shown}`));
      }
      const cookies = data.cookies;
      for (const c of cookies.plaintext || [])
        issues.push(finding('STORAGE_COOKIE_AT_REST', cookies.file, severity.MEDIUM, confidence.CERTAIN,
          `The cookie '${c.name}' for ${c.host} is stored unencrypted in the cookie store`, { host: c.host, name: c.name }, COOKIE_FUSE, `${c.name} @ ${c.host}: ${c.value}`));
      if (cookies.weakEncryption)
        issues.push(finding('STORAGE_COOKIE_AT_REST', cookies.file, severity.LOW, confidence.FIRM,
          `${cookies.weakEncryption} cookie(s) use Chromium's fallback encryption with a fixed key (v10 ${process.platform === 'linux' ? 'without an OS keyring' : 'with the EnableCookieEncryption fuse off'}): effectively cleartext on disk`,
          { weakEncryption: cookies.weakEncryption }, COOKIE_FUSE));
      if (cookies.error) notes.push(`cookie store ${cookies.file}: ${cookies.error}`);
      // responses kept on disk: service worker Cache Storage and the HTTP cache
      const caches = data.caches || { stores: {}, secrets: [] };
      summary.profile.caches = Object.fromEntries(Object.entries(caches.stores).map(([store, s]) => [store, { entries: s.entries, hosts: Object.keys(s.hosts).length }]));
      for (const c of caches.secrets)
        issues.push(finding('STORAGE_SECRET_AT_REST', path.join(profile, c.store === 'Cache Storage' ? 'Service Worker/CacheStorage' : 'Cache'), severity.MEDIUM, confidence.FIRM,
          `${c.kind} in a cached response (${c.store}) from ${c.url}: responses stay on disk after the session ends`,
          { store: c.store, url: c.url, kind: c.kind }, 'https://cwe.mitre.org/data/definitions/524.html', `${c.kind}: ${c.shown}`));
      for (const [store, s] of Object.entries(caches.stores)) {
        const hosts = Object.entries(s.hosts).sort((a, b) => b[1] - a[1]);
        issues.push(finding('STORAGE_CACHED_RESPONSES', path.join(profile, store === 'Cache Storage' ? 'Service Worker/CacheStorage' : 'Cache'), severity.INFORMATIONAL, confidence.CERTAIN,
          `${s.entries} response(s) kept in the ${store}${hosts.length ? ` from ${hosts.slice(0, 5).map(([h, n]) => `${h} (${n})`).join(', ')}${hosts.length > 5 ? ', ...' : ''}` : ''}: documents and API responses the app fetched stay on disk; send Cache-Control: no-store for sensitive ones`,
          { store, entries: s.entries, hosts: Object.fromEntries(hosts) }, 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control'));
      }
    }
  }

  // --- the saved-credential trace ---
  const values = canaries.filter(Boolean);
  if (values.length > 0) {
    if (values.some(value => value.length < 8)) notes.push('--canary: use a unique value of at least 8 characters so matches mean something');
    // the folders recorded before the session, and the profile folder the app reported while it ran (it can differ
    // from the one its name suggests, after an app.setPath('userData'))
    const roots = baseline ? searchRoots([], { extra: [...baseline.roots, ...(observedUserData ? [observedUserData] : [])] })
      : searchRoots(names, { extra: [...searchDirs, ...(userData && userData !== 'auto' ? [userData] : []), ...(observedUserData ? [observedUserData] : [])], installDir });
    if (roots.length === 0) notes.push('--canary: no app data folder found; give one with --search-dir');
    else {
      const diff = baseline ? changedFiles(baseline.files, snapshot(baseline.roots)) : undefined;
      const newTargets = baseline ? credentialTargets().filter(t => !baseline.targets.includes(t)) : [];
      const result = scanForCanaries(roots, values, { registryNames: names, changedPaths: diff && new Set(diff.map(d => d.path)) });
      const shown = (value) => reveal ? value : value.length > 4 ? `${value.slice(0, 2)}…${value.slice(-1)}` : '…';
      const byLocation = new Map();
      for (const hit of result.hits) byLocation.set(hit.location, [...(byLocation.get(hit.location) || []), hit]);
      for (const [location, hits] of byLocation) {
        const encodings = [...new Set(hits.map(h => h.encoding))].sort();
        const plain = encodings.some(e => e.startsWith('plaintext'));
        const evidence = hits.slice(0, 4).map(h => `${h.encoding}: …${reveal ? h.context : h.context.replace(h.match, '[canary]')}…`);
        issues.push(finding('STORAGE_CREDENTIAL_AT_REST', location, severity.HIGH, confidence.CERTAIN,
          `The test password '${shown(hits[0].canary)}' typed into the app was found ${plain ? 'in plaintext' : 'encoded but not encrypted'} (${encodings.join(', ')}) in ${location}${plain ? '' : ': base64, hex and URL encoding are reversible by anyone who can read it'}`,
          { store: hits[0].store || 'file', encodings, evidence }, SAFE_STORAGE, evidence[0]));
      }
      summary.credentialTrace = { canaries: values.length, roots, files: result.files, leveldbStores: result.leveldbStores, locations: [...byLocation.keys()],
        credentialManagerNew: newTargets, protectedMarkers: result.markers.slice(0, 50), changed: (diff || []).slice(0, 200), baseline: !!baseline };
      if (byLocation.size === 0) {
        const parts = [`The test password was not found in plaintext or a common encoding in ${result.files} files (${result.leveldbStores} LevelDB stores decoded) under ${roots.join(', ')}.`];
        const evidence = [];
        if (newTargets.length > 0) {
          parts.push(`${newTargets.length} new Windows Credential Manager entr${newTargets.length === 1 ? 'y' : 'ies'} appeared during the session (DPAPI-protected, tied to the Windows account).`);
          evidence.push(...newTargets.map(t => `Credential Manager: ${t}`));
        }
        const real = result.markers.filter(m => !/not the credential/.test(m.markers[0]));
        if (real.length > 0) {
          parts.push(`${real.length} file(s) ${diff ? 'written during the session ' : ''}hold DPAPI or safeStorage-encrypted values.`);
          evidence.push(...real.slice(0, 10).map(m => `${m.markers.join(', ')}: ${m.path}`));
        }
        if (diff) {
          parts.push(`${diff.length} file(s) were created or changed during the session.`);
          evidence.push(...diff.slice(0, 15).map(d => `${d.change} (${d.size} bytes): ${d.path}`));
        } else parts.push('No before/after comparison: run the app in watch mode with --canary so its folders are recorded first.');
        if (newTargets.length === 0 && real.length === 0)
          parts.push('No OS-protected storage was seen either: the app may keep a server-issued token instead of the password (see the data-at-rest findings), store it elsewhere (add --search-dir), or not have saved it.');
        issues.push(finding('STORAGE_CREDENTIAL_TRACE', roots[0], severity.INFORMATIONAL, confidence.FIRM, parts.join(' '), { evidence }, SAFE_STORAGE, evidence[0] || ''));
      }
    }
  }
  return { issues, summary, notes };
}

/** The app's names from its package.json: productName and name (Electron names the profile folder after them) and the author. */
export function appNames(manifest, extra = []) {
  const names = [];
  if (manifest) {
    if (typeof manifest.productName === 'string') names.push(manifest.productName);
    if (typeof manifest.name === 'string') names.push(manifest.name);
    const author = typeof manifest.author === 'string' ? manifest.author.replace(/\s*[<(].*$/, '') : manifest.author && manifest.author.name;
    if (author) names.push(author);
  }
  return [...new Set([...names, ...extra].map(n => String(n || '').trim()).filter(Boolean))];
}
