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
module.exports = { observeUpdater };
