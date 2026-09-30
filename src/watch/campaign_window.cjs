'use strict';

// Pin one renderer before the first write. Never switch to another account/window if it closes.
function campaignWindow(webContents, profile, entry) {
  let selected;
  const candidates = () => {
    if (selected) return selected.isDestroyed() ? [] : [selected];
    const live = webContents.getAllWebContents().filter(c => !c.isDestroyed());
    const source = Number.isInteger(entry?.webContents) && entry.webContents > 0;
    if (source && (!profile.windowUrl || profile.view === 'captured')) {
      return live.filter(c => c.id === entry.webContents && ['window', 'browserView', 'webview'].includes(c.getType()) &&
        (!profile.windowUrl || c.getURL().startsWith(profile.windowUrl)));
    }
    if (profile.view === 'captured') return [];
    return live.filter(c => c.getType() === 'window' && (!profile.windowUrl || c.getURL().startsWith(profile.windowUrl)));
  };
  return {
    candidates,
    select() {
      const matches = candidates();
      if (matches.length !== 1) {
        if (matches.length > 1) throw new Error(`Campaign matched ${matches.length} app windows; set windowUrl in the campaign profile to select one`);
        throw new Error(sourceMissing());
      }
      selected = matches[0];
      return selected;
    },
  };
  function sourceMissing() {
    return entry && (!profile.windowUrl || profile.view === 'captured')
      ? 'Campaign originating app view is unavailable; keep the saving view open and capture a new save'
      : 'Campaign matched no app windows; check windowUrl and keep the intended view open';
  }
}

module.exports = { campaignWindow };
