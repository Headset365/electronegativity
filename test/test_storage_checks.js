import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as asar from '@electron/asar';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { secretSources, scanSecrets } from '../src/secrets/scan.js';

chaiShould();
await _i18n();

// fake credentials, split so secret scanners don't take the test source for a leak
const GITHUB = ['ghp_', 'Zq8Lm2Vt9Rk4Zp8Wn3Yb6Hs7Tx4Wv1Yp8Nb2Qm'].join('');
const tmp = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
async function scan(files, options = {}) {
  const dir = tmp('eng-storage-checks-');
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  const result = await run({ input: dir, offline: true, ...options });
  return { dir, issues: result.issues, of: (id) => result.issues.filter(i => i.id === id) };
}

describe('Storage and secret checks', () => {
  it('reports secrets written to files, web storage and electron-store', async () => {
    const { of } = await scan({ 'package.json': '{"name":"a","main":"main.js"}', 'main.js': `
const fs = require('fs');
const Store = require('electron-store');
const { safeStorage } = require('electron');
const store = new Store();
const encrypted = new Store({ encryptionKey: 'constant-key' });
function save(password, token, theme) {
  fs.writeFileSync('credentials.json', JSON.stringify({ password }));
  fs.writeFileSync('prefs.json', JSON.stringify({ theme }));
  fs.writeFileSync('vault.bin', safeStorage.encryptString(token));
  localStorage.setItem('prefs', JSON.stringify({ token }));
  localStorage['authToken'] = token;
  sessionStorage.theme = theme;
}` });
    of('SECRET_FILE_WRITE_JS_CHECK').map(i => i.location.line).should.deep.equal([8]);
    of('ELECTRON_STORE_ENCRYPTION_JS_CHECK').map(i => i.properties.issue).should.deep.equal(['no-encryption', 'hardcoded-key']);
    of('PLAINTEXT_SECRETS_JS_CHECK').map(i => i.location.line).should.deep.equal([11, 12]);
  });

  it('reports cookies set in code without their security attributes', async () => {
    const { of } = await scan({ 'main.js': `
session.defaultSession.cookies.set({ url: 'http://app.test', name: 'sessionid', value: v });
session.defaultSession.cookies.set({ url: 'https://app.test', name: 'theme', value: 'dark', secure: true, httpOnly: true });
ses.cookies.set({ url: 'https://app.test', name: 'lang', value: 'en', secure: true });` });
    const found = of('COOKIE_FLAGS_JS_CHECK');
    found.map(i => [i.location.line, i.severity.name]).should.deep.equal([[2, 'MEDIUM'], [4, 'LOW']]);
    found[0].properties.cleartext.should.equal(true);
  });

  it('lists where credentials are read and written, and how they are protected', async () => {
    const { of } = await scan({ 'main.js': `
const Store = require('electron-store');
const keytar = require('keytar');
const settings = new Store();
settings.set('rememberedPassword', pw);
const saved = settings.get('rememberedPassword');
keytar.setPassword('MyApp', user, pw);
const blob = safeStorage.decryptString(fs.readFileSync(file));
localStorage.getItem('authToken');
const old = localStorage.password;
fs.readFileSync('token.json');
settings.set('theme', 'dark');` });
    const rows = of('CREDENTIAL_ACCESS_JS_CHECK').map(i => [i.location.line, i.properties.op, i.properties.api, i.properties.protected]);
    rows.should.deep.equal([
      [5, 'write', 'settings.set', false], [6, 'read', 'settings.get', false], [7, 'write', 'keytar.setPassword', true],
      [8, 'read', 'safeStorage.decryptString', true], [9, 'read', 'localStorage.getItem', false], [10, 'read', 'localStorage.password', false],
      [11, 'read', 'fs.readFileSync', null]]);
    of('CREDENTIAL_ACCESS_JS_CHECK')[0].properties.store.should.include('no encryptionKey');
  });

  it('shows the credential table in the HTML report, not in the findings list', async () => {
    const dir = tmp('eng-cred-html-');
    fs.writeFileSync(path.join(dir, 'main.js'), "keytar.setPassword('MyApp', user, pw);\nlocalStorage.setItem('authToken', t);\n");
    const output = path.join(dir, 'report.html');
    await run({ input: dir, offline: true, output });
    const html = fs.readFileSync(output, 'utf8');
    html.should.include('Saved credentials');
    html.should.include('keytar.setPassword');
    html.should.not.include('data-check="CREDENTIAL_ACCESS_JS_CHECK"');
  });

  it('finds hard-coded secrets in code and configuration files, redacted', async () => {
    const { of } = await scan({
      'main.js': `const token = '${GITHUB}';\nconst apiKey = "Zq8Lm2Vt9Rk4Zp8WXYZ";\nconst label = 'not a secret at all';\n`,
      'config/.env': 'DB_PASSWORD=Vt9Rk4Zp8Wn3Yb6HsQx7\nAPI_URL=https://api.example.com\n',
      'config/app.yml': 'service:\n  signing: "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5oQ7s"\n',
      'test/fixture.env': 'SECRET_TOKEN=Vt9Rk4Zp8Wn3Yb6HsQx8\n',
    });
    const found = of('HARDCODED_SECRET');
    found.map(i => [path.basename(i.file), i.location.line, i.properties.kind, i.severity.name]).should.deep.equal([
      ['main.js', 1, 'GitHub token', 'HIGH'], ['main.js', 2, 'Hard-coded apiKey', 'MEDIUM'],
      ['.env', 1, 'Hard-coded DB_PASSWORD', 'MEDIUM'], ['app.yml', 2, 'High-entropy value (signing)', 'LOW']]);
    JSON.stringify(found).should.not.include(GITHUB);
    found[0].sample.should.include('redacted');
  });

  it('can be left out or run alone', async () => {
    const files = { 'main.js': `const token = '${GITHUB}';\n` };
    (await scan(files, { excludeFromScan: ['hardcodedsecretscheck'] })).of('HARDCODED_SECRET').length.should.equal(0);
    const alone = await scan(files, { customScan: ['hardcodedsecretscheck'] });
    alone.of('HARDCODED_SECRET').length.should.equal(1);
  });

  it('searches native modules and what ships next to a packaged app\'s code', async () => {
    const root = tmp('eng-packaged-secrets-');
    const resources = path.join(root, 'MyApp', 'resources');
    const source = path.join(root, 'src');
    fs.mkdirSync(source, { recursive: true });
    fs.writeFileSync(path.join(source, 'package.json'), '{"name":"my-app","main":"main.js"}');
    fs.writeFileSync(path.join(source, 'main.js'), 'console.log(1);\n');
    fs.mkdirSync(resources, { recursive: true });
    await asar.createPackage(source, path.join(resources, 'app.asar'));
    const native = path.join(resources, 'app.asar.unpacked', 'node_modules', 'addon', 'build', 'Release');
    fs.mkdirSync(native, { recursive: true });
    fs.writeFileSync(path.join(native, 'addon.node'), Buffer.concat([Buffer.alloc(64), Buffer.from(`\0key=${GITHUB}\0`), Buffer.alloc(64)]));
    fs.writeFileSync(path.join(resources, 'app-update.yml'), `provider: generic\ntoken: "${GITHUB}"\n`);
    fs.writeFileSync(path.join(root, 'MyApp', 'helper.dll'), Buffer.concat([Buffer.alloc(32), Buffer.from(`AKIA${'ABCDEFGHIJKLMNOP'}`, 'utf16le')]));
    const sources = secretSources(path.join(resources, 'app.asar'), [], () => Buffer.alloc(0));
    const issues = scanSecrets(sources);
    const where = issues.map(i => [path.basename(i.file), i.properties.source]);
    where.should.deep.include(['addon.node', 'binary']);
    where.should.deep.include(['helper.dll', 'binary']);
    // the same token is reported once, where it was first found
    issues.filter(i => i.properties.kind === 'GitHub token').length.should.equal(1);
    issues.find(i => i.properties.source === 'binary').description.should.match(/offset 0x[0-9a-f]+/);
  });
});
