import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { campaignWindow } = createRequire(import.meta.url)('../src/watch/campaign_window.cjs');
const contents = (id, type = 'window', url = `https://app.test/view/${id}`) => ({ id, type, url, destroyed: false,
  isDestroyed() { return this.destroyed; }, getType() { return this.type; }, getURL() { return this.url; } });
const selector = (list, profile = {}, entry) => campaignWindow({ getAllWebContents: () => list }, profile, entry);

describe('Campaign window selection', () => {
  it('keeps the captured source with an explicit viewer URL and multiple app windows', () => {
    const list = [contents(1), contents(2)];
    assert.equal(selector(list, { view: 'https://app.test/saved/42' }, { webContents: 2 }).select(), list[1]);
  });
  for (const type of ['window', 'browserView', 'webview']) {
    it(`can reopen the exact captured ${type}`, () => {
      const list = [contents(1), contents(2, type)];
      assert.equal(selector(list, { view: 'captured' }, { webContents: 2 }).select(), list[1]);
    });
  }
  it('pins a selected window when opening the viewer changes its URL', () => {
    const list = [contents(1), contents(2)];
    const match = selector(list, { windowUrl: 'https://app.test/view/2' });
    match.select(); list[1].url = 'https://app.test/saved/42';
    assert.deepEqual(match.candidates(), [list[1]]);
  });
  it('never switches to a different window when the source closes', () => {
    const list = [contents(1), contents(2)];
    const match = selector(list, { view: 'captured' }, { webContents: 2 });
    match.select(); list[1].destroyed = true;
    assert.deepEqual(match.candidates(), []);
    assert.throws(() => match.select(), /originating app view is unavailable/);
  });
  it('distinguishes an ambiguous selection from no matching windows', () => {
    assert.throws(() => selector([contents(1), contents(2)]).select(), /matched 2 app windows/);
    assert.throws(() => selector([contents(1)], { windowUrl: 'https://missing.test/' }).select(), /matched no app windows/);
  });
  it('honors an explicit window selector for an explicit viewer', () => {
    const list = [contents(1), contents(2)];
    assert.equal(selector(list, { view: 'https://app.test/saved', windowUrl: 'https://app.test/view/1' }, { webContents: 2 }).select(), list[0]);
  });
  it('requires the actual captured source when reopening the captured view', () => {
    const list = [contents(1), contents(2)];
    assert.throws(() => selector(list, { view: 'captured', windowUrl: 'https://app.test/view/1' }, { webContents: 2 }).select(), /originating app view/);
    assert.throws(() => selector(list, { view: 'captured' }, { webContents: -1 }).select(), /originating app view/);
  });
  it('excludes background and DevTools renderers from captured selections', () => {
    for (const type of ['backgroundPage', 'remote']) assert.throws(() => selector([contents(1, type)], { view: 'captured' }, { webContents: 1 }).select());
  });
});
