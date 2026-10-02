import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { feedFromSettings, feedFromAppUpdate, resourcesFolder } from '../src/watch/app-update.js';

describe('Update feed from app-update.yml (--prove)', () => {
  it('works out the latest.yml address of the common providers', () => {
    assert.deepEqual(feedFromSettings({ provider: 'generic', url: 'https://updates.example.com/win/' }), { url: 'https://updates.example.com/win/latest.yml', provider: 'generic' });
    assert.equal(feedFromSettings({ provider: 'generic', url: 'https://updates.example.com', channel: 'beta' }).url, 'https://updates.example.com/beta.yml');
    assert.equal(feedFromSettings({ provider: 'github', owner: 'acme', repo: 'desk' }).url, 'https://github.com/acme/desk/releases/latest/download/latest.yml');
    assert.equal(feedFromSettings({ provider: 's3', bucket: 'acme-updates', region: 'ap-southeast-2', path: '/win' }).url, 'https://acme-updates.s3.ap-southeast-2.amazonaws.com/win/latest.yml');
    assert.equal(feedFromSettings({ provider: 'spaces', name: 'acme', region: 'syd1' }).url, 'https://acme.syd1.digitaloceanspaces.com/latest.yml');
  });

  it('leaves to the tester what it cannot know: tokens, private repositories, macros and other providers', () => {
    assert.match(feedFromSettings({ provider: 'github', owner: 'acme', repo: 'desk', private: true }).skipped, /private GitHub releases/);
    assert.match(feedFromSettings({ provider: 'generic', url: 'https://u.example.com/?token=abc' }).skipped, /query string/);
    assert.match(feedFromSettings({ provider: 'generic', url: 'https://user:pw@u.example.com/' }).skipped, /without credentials/);
    assert.match(feedFromSettings({ provider: 'generic', url: 'https://u.example.com/${os}' }).skipped, /exact/);
    assert.match(feedFromSettings({ provider: 'keygen', account: 'x' }).skipped, /keygen update provider/);
  });

  it('reads the file next to a packaged app, and finds the resources folder from the app or its code', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-app-update-'));
    try {
      const resources = path.join(dir, 'resources');
      fs.mkdirSync(resources);
      assert.equal(feedFromAppUpdate(resources), undefined);
      fs.writeFileSync(path.join(resources, 'app-update.yml'), 'provider: generic\nurl: https://updates.example.com/win\nupdaterCacheDirName: myapp-updater\n');
      assert.equal(feedFromAppUpdate(resources).url, 'https://updates.example.com/win/latest.yml');
      // unreadable YAML is no feed; a file naming no provider says why it was skipped
      fs.writeFileSync(path.join(resources, 'app-update.yml'), 'key: [unclosed');
      assert.equal(feedFromAppUpdate(resources), undefined);
      fs.writeFileSync(path.join(resources, 'app-update.yml'), 'updaterCacheDirName: myapp-updater\n');
      assert.match(feedFromAppUpdate(resources).skipped, /unnamed update provider/);
      assert.equal(resourcesFolder({ code: path.join(resources, 'app.asar') }), resources);
      assert.equal(resourcesFolder({ executable: path.join(dir, 'MyApp.exe') }), resources);
      assert.equal(resourcesFolder({}), undefined);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
