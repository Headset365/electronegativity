// The update feed an electron-builder app ships in resources/app-update.yml, as an exact metadata address (latest.yml)
// for --prove's feed check, so the check runs without a --proof-profile when the app never sets the feed itself.
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';

export const APP_UPDATE_FILE = 'app-update.yml';

// a metadata address the feed check may fetch: http(s), no credentials, no query string (tokens travel there)
function exact(url) {
  try {
    const u = new URL(url);
    return ['http:', 'https:'].includes(u.protocol) && !u.username && !u.password && !u.search ? u.href : undefined;
  } catch {
    return undefined;
  }
}
const join = (base, ...parts) => [String(base).replace(/\/+$/, ''), ...parts.map(p => String(p).replace(/^\/+|\/+$/g, '')).filter(Boolean)].join('/');

/**
 * The feed of an app-update.yml's settings: { url, provider } for the latest.yml (or <channel>.yml) the updater reads on
 * Windows, or { skipped, provider } when it can't be known without the tester (a private repository, a token, a provider
 * with no public address, macros in the address).
 */
export function feedFromSettings(settings) {
  const provider = String(settings?.provider || '').toLowerCase();
  const file = `${String(settings?.channel || 'latest').replace(/[^\w.-]/g, '') || 'latest'}.yml`;
  const result = (url) => {
    const checked = url && !/\$\{/.test(url) ? exact(url) : undefined;
    return checked ? { url: checked, provider } : { skipped: 'the feed address is not an exact http(s) address without credentials or a query string: give it in --proof-profile', provider };
  };
  if (provider === 'generic') return result(settings.url && join(settings.url, file));
  if (provider === 'github') {
    if (settings.private || settings.token) return { skipped: 'private GitHub releases need a token: give the exact latest.yml address in --proof-profile', provider };
    if (!settings.owner || !settings.repo) return { skipped: 'app-update.yml names no GitHub owner and repository', provider };
    const host = settings.host && settings.host !== 'github.com' ? settings.host : 'github.com';
    return result(`https://${host}/${encodeURIComponent(settings.owner)}/${encodeURIComponent(settings.repo)}/releases/latest/download/${file}`);
  }
  if (provider === 's3') {
    if (!settings.bucket) return { skipped: 'app-update.yml names no S3 bucket', provider };
    const base = settings.endpoint ? join(settings.endpoint, settings.bucket)
      : `https://${settings.bucket}.s3${settings.region ? `.${settings.region}` : ''}.amazonaws.com`;
    return result(join(base, settings.path || '', file));
  }
  if (provider === 'spaces') {
    if (!settings.name || !settings.region) return { skipped: 'app-update.yml names no Spaces name and region', provider };
    return result(join(`https://${settings.name}.${settings.region}.digitaloceanspaces.com`, settings.path || '', file));
  }
  return { skipped: `the ${provider || 'unnamed'} update provider has no address the tool can work out: give the exact metadata address in --proof-profile`, provider };
}

/** The feed of the app-update.yml in `resourcesDir`, or undefined when there is none (or it can't be read). */
export function feedFromAppUpdate(resourcesDir) {
  if (!resourcesDir) return undefined;
  const file = path.join(resourcesDir, APP_UPDATE_FILE);
  let settings;
  try {
    if (!fs.statSync(file).isFile() || fs.statSync(file).size > 65536) return undefined;
    settings = YAML.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
  return settings && typeof settings === 'object' ? { ...feedFromSettings(settings), file } : undefined;
}

/** The resources folder of a packaged app, from its scanned code (resources/app.asar or resources/app) or its executable. */
export function resourcesFolder({ code, executable } = {}) {
  if (code && /[\\/]resources[\\/]app(\.asar)?$/i.test(path.resolve(code))) return path.dirname(path.resolve(code));
  if (executable) return path.join(path.dirname(path.resolve(executable)), 'resources');
  return undefined;
}

/**
 * The feed an app sets in code (autoUpdater.setFeedURL, found by the static scan) as an exact metadata address:
 * { url } when everything in it is known on this machine (${process.platform} is), { skipped } when it depends on values
 * only the running app has (a release track the user chose), or undefined when the code sets no feed.
 */
export function feedFromCode(staticIssues = [], platform = process.platform) {
  const set = staticIssues.find(issue => issue.id === 'UPDATE_FEED_JS_CHECK' && issue.properties && issue.properties.feed);
  if (!set) return undefined;
  const { feed, provider, channel } = set.properties;
  const resolve = (value) => String(value).replace(/\$\{process\.platform\}/g, platform);
  const address = resolve(feed);
  const file = channel === undefined ? 'latest.yml' : `${resolve(channel)}.yml`;
  if (/\$\{/.test(address) || /\$\{/.test(file))
    return { skipped: `the app sets its update feed in code from values only the running app has (${feed}): give the exact metadata address in --proof-profile`, provider, code: feed };
  const exactAddress = /(?:latest[^/]*\.ya?ml|RELEASES)$/i.test(new URL(address).pathname) ? address : `${address.replace(/\/+$/, '')}/${file}`;
  if (provider && !['generic', 'custom'].includes(String(provider).toLowerCase()) && exactAddress !== address)
    return { skipped: `the app sets a ${provider} update feed in code: give the exact metadata address in --proof-profile`, provider, code: feed };
  return { url: exactAddress, provider, code: feed };
}
