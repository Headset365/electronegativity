// Checks the links of the components workbook before they go to a client. Several of the sites answer "OK" for any
// address (deps.dev and Electron's release pages are single-page apps) or refuse automated requests (npm's website), so
// each link is checked against the data behind it: the npm registry facts already looked up for the component, deps.dev's
// API, and Snyk's page, which answers 404 for a version it doesn't know. GitHub's advisory search loads for any query: its
// link holds when the package exists on npm.
import { componentLinks, needsAction } from '../report/xlsx.js';
import { isOffline } from './network.js';

const TIMEOUT = 15000;
const CONCURRENCY = 4;

// one answer per address for the whole run (an --app run checks the same components after every session)
const cache = new Map();

async function answers(url, fetchImpl) {
  if (!cache.has(url)) cache.set(url, (async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await fetchImpl(url, { headers: { Accept: 'text/html,application/json' }, signal: AbortSignal.timeout(TIMEOUT) });
        try { await response.body?.cancel(); } catch { /* the body is not needed */ }
        if (response.ok) return true;
        if (response.status === 404 || response.status === 410) return false;
        // rate limited or a server error: once more, a little later
      } catch {
        // timed out or no connection: once more
      }
      if (attempt === 0) await new Promise(resolve => setTimeout(resolve, 2000));
    }
    return false;
  })());
  return cache.get(url);
}

async function mapLimit(items, limit, fn) {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++]);
  }));
}

/**
 * Checks the five links of every component needing action and records the result on its row as `linkChecks`: one
 * true/false per link, in the order of componentLinks. Offline, nothing can be checked: every link is left for manual
 * validation.
 */
export async function checkComponentLinks(dependencies, { fetchImpl = fetch } = {}) {
  const rows = ((dependencies && dependencies.rows) || []).filter(needsAction);
  if (isOffline() || dependencies?.offline) {
    for (const row of rows) row.linkChecks = [false, false, false, false, false];
    return;
  }
  await mapLimit(rows, CONCURRENCY, async (row) => {
    const links = componentLinks(row);
    // on npm: the registry knew the package (it has a latest version); a version it doesn't know links the package page
    const onNpm = !!row.latest;
    const name = encodeURIComponent(row.name);
    const version = encodeURIComponent(row.version);
    const [depsDev, snyk] = await Promise.all([
      answers(`https://api.deps.dev/v3/systems/npm/packages/${name}/versions/${version}`, fetchImpl),
      answers(links[3].url, fetchImpl),
    ]);
    row.linkChecks = [onNpm, onNpm && !!links[1], depsDev, snyk, onNpm];
  });
}
