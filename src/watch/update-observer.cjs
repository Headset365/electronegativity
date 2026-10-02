'use strict';
const observed = new WeakSet();
function observeUpdater(updater, write) {
  if (!updater || observed.has(updater)) return;
  observed.add(updater);
  if (typeof updater.setFeedURL !== 'function') return;
  const original = updater.setFeedURL;
  updater.setFeedURL = function (options) {
    const value = typeof options === 'string' ? options : options?.url;
    try {
      const u = new URL(value);
      if (['http:', 'https:'].includes(u.protocol)) {
        const exact = !u.search && !u.username && !u.password;
        u.search = ''; u.hash = ''; u.username = ''; u.password = '';
        write('update-feed', { url: u.href, exact, publisherConfigured: !!this.publisherName, signatureCheckConfigured: this.verifyUpdateCodeSignature !== false });
      }
    } catch { /* provider-specific configuration requires an exact profile URL */ }
    return original.apply(this, arguments);
  };
}
// Update traffic of the main process: electron-updater fetches its feed (latest.yml, RELEASES) and installers through
// Electron's net module, which works even when the updater is bundled into the app (nothing to hook by name). The feed
// address it really uses is recorded for --prove, and a downloaded update is recorded so the session can warn that the
// app may install another version when it quits. Only the host and path are kept.
const FEED = /(?:latest[^/]*\.ya?ml|RELEASES)$/i;
const INSTALLER = /\.(?:exe|msi|nupkg|blockmap|dmg|zip|AppImage|deb|rpm|pkg)$/i;
function observeUpdateTraffic(net, write) {
  if (!net || observed.has(net) || typeof net.request !== 'function') return;
  observed.add(net);
  const original = net.request;
  net.request = function (options) {
    try {
      const value = typeof options === 'string' ? options : options && (options.url ||
        (options.hostname || options.host ? `${options.protocol || 'https:'}//${options.hostname || options.host}${options.port ? `:${options.port}` : ''}${options.path || '/'}` : undefined));
      if (value) {
        const u = new URL(value);
        if (['http:', 'https:'].includes(u.protocol)) {
          // a cache-busting parameter (electron-updater adds noCache) is not part of the address; anything else may be a token
          const exact = !u.username && !u.password && [...u.searchParams.keys()].every(key => /^(nocache|_|t|ts|v|cachebust)$/i.test(key));
          const clean = `${u.protocol}//${u.host}${u.pathname}`;
          if (FEED.test(u.pathname)) write('update-feed', { url: clean, exact, source: 'net.request' });
          else if (INSTALLER.test(u.pathname)) write('update-download', { url: clean });
        }
      }
    } catch { /* not a URL the updater would use */ }
    return original.apply(this, arguments);
  };
}
module.exports = { observeUpdater, observeUpdateTraffic };
