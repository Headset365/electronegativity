import { assertOnline } from './network.js';

// Client for the OSV vulnerability database (https://osv.dev), which mirrors the GitHub Security Advisories for npm packages
const OSV_QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000; // maximum number of queries accepted per request

/**
 * Looks up the advisories affecting each npm package version.
 * @param {Array<{name: string, version: string}>} packages
 * @returns {Promise<string[][]>} advisory ids for each package, in the same order
 */
export async function queryNpmAdvisories(packages, { timeout = 30000 } = {}) {
  assertOnline();
  const results = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const response = await fetch(OSV_QUERY_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries: batch.map(({ name, version }) => ({ package: { name, ecosystem: 'npm' }, version })) }),
      signal: AbortSignal.timeout(timeout)
    });
    if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}`);
    const json = await response.json();
    results.push(...json.results.map(r => (r.vulns || []).map(v => v.id)));
  }
  return results;
}
