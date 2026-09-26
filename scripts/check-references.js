// Checks that the reference of every check (and the upgrade checks) still exists: the page loads and, for links to a
// section, the section's anchor is on the page. Needs network access: npm run check:references
import i18n from '../src/locales/i18n.js';
import { CHECKS } from '../src/finder/checks/AtomicChecks/index.js';
import { ELECTRON_ATOMIC_UPGRADE_CHECKS } from '../src/finder/checks/AtomicChecks/ElectronAtomicUpgradeChecks.js';
import { GLOBAL_CHECKS } from '../src/finder/checks/GlobalChecks/index.js';

await i18n();

const checks = [...CHECKS, ...Object.values(ELECTRON_ATOMIC_UPGRADE_CHECKS).flat(), ...GLOBAL_CHECKS].map(C => new C());
const byUrl = new Map();
for (const check of checks) byUrl.set(check.shortenedURL, [...(byUrl.get(check.shortenedURL) || []), check.id]);

const pages = new Map();
async function fetchPage(url) {
  if (!pages.has(url)) pages.set(url, fetch(url, { redirect: 'follow', headers: { 'user-agent': 'electronegativity-reference-check' } })
    .then(async response => ({ status: response.status, text: response.ok ? await response.text() : '' }))
    .catch(error => ({ status: 0, text: '', error })));
  return pages.get(url);
}

// Anchors are element ids (Docusaurus, MDN, OWASP) or GitHub's user-content ids
const hasAnchor = (html, anchor) => {
  const escaped = anchor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`id=["']?(user-content-)?${escaped}["'\\s>]`, 'i').test(html);
};

let failures = 0;
for (const [url, ids] of [...byUrl.entries()].sort()) {
  const [page, anchor] = url.split('#');
  const { status, text, error } = await fetchPage(page);
  let problem;
  if (!/^https:\/\//.test(url)) problem = 'not an https URL';
  else if (status !== 200) problem = `HTTP ${status}${error ? ' ' + error.message : ''}`;
  else if (anchor && !hasAnchor(text, decodeURIComponent(anchor))) problem = `anchor #${anchor} not found`;
  if (problem) failures++;
  console.log(`${problem ? 'FAIL' : 'ok  '} ${url}${problem ? ` (${problem})` : ''}\n       ${ids.join(', ')}`);
}
console.log(`\n${byUrl.size} references, ${failures} broken`);
process.exitCode = failures ? 1 : 0;
