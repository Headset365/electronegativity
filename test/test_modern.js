import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import { Parser } from '../src/parser/index.js';
import { Finder } from '../src/finder/index.js';
import {
  findOldestElectronVersion,
  findElectronVersionsFromPackageLock,
  findElectronVersionsFromYarnLock,
  findElectronVersionsFromPnpmLock
} from '../src/util/electron_version.js';

const should = chaiShould();
await _i18n();

const parsers = [new Parser(false, true), new Parser(true, true), new Parser(true, false), new Parser(false, false)];

async function findIssues(filename, source, electronVersion, checkId) {
  const results = [];
  for (const parser of parsers) {
    const finder = new Finder(null, null, null);
    const [type, data, content] = parser.parse(filename, source);
    const issues = await finder.find(filename, data, type, content, null, electronVersion);
    results.push(issues.filter(i => i.id === checkId).length);
  }
  // every parser must agree
  new Set(results).size.should.equal(1, `parsers disagree: ${results}`);
  return results[0];
}

const secureByDefaultWindow = `
import { app, BrowserWindow } from 'electron';
import path from 'node:path';

await app.whenReady();
const win = new BrowserWindow({
  webPreferences: { preload: path.join(import.meta.dirname, 'preload.mjs') }
});
`;

const nodeIntegrationWindow = `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: true } });
`;

const remoteWindow = `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({ webPreferences: { enableRemoteModule: true } });
`;

describe('Modern Electron defaults', () => {
  describe('contextIsolation (default since Electron 12)', () => {
    it('is reported when missing on Electron 11', async () => {
      (await findIssues('main.mjs', secureByDefaultWindow, '11.0.0', 'CONTEXT_ISOLATION_JS_CHECK')).should.equal(1);
    });
    it('is not reported when missing on Electron 12+', async () => {
      (await findIssues('main.mjs', secureByDefaultWindow, '12.0.0', 'CONTEXT_ISOLATION_JS_CHECK')).should.equal(0);
      (await findIssues('main.mjs', secureByDefaultWindow, '38.1.0', 'CONTEXT_ISOLATION_JS_CHECK')).should.equal(0);
    });
    it('is reported when missing and the version is unknown', async () => {
      (await findIssues('main.mjs', secureByDefaultWindow, null, 'CONTEXT_ISOLATION_JS_CHECK')).should.equal(1);
    });
  });

  describe('sandbox (default since Electron 20)', () => {
    it('is reported when missing on Electron 19', async () => {
      (await findIssues('main.mjs', secureByDefaultWindow, '19.1.0', 'SANDBOX_JS_CHECK')).should.equal(1);
    });
    it('is not reported when missing on Electron 20+', async () => {
      (await findIssues('main.mjs', secureByDefaultWindow, '20.0.0', 'SANDBOX_JS_CHECK')).should.equal(0);
    });
    it('is reported on Electron 20+ when nodeIntegration disables the sandbox', async () => {
      (await findIssues('main.js', nodeIntegrationWindow, '30.0.0', 'SANDBOX_JS_CHECK')).should.equal(1);
    });
  });

  describe('remote module (removed in Electron 14)', () => {
    it('is reported on Electron 13', async () => {
      (await findIssues('main.js', remoteWindow, '13.0.0', 'REMOTE_MODULE_JS_CHECK')).should.equal(1);
    });
    it('is not reported on Electron 14+', async () => {
      (await findIssues('main.js', remoteWindow, '14.0.0', 'REMOTE_MODULE_JS_CHECK')).should.equal(0);
    });
  });

  it('accepts non-semver version overrides such as "30"', async () => {
    (await findIssues('main.mjs', secureByDefaultWindow, '30', 'CONTEXT_ISOLATION_JS_CHECK')).should.equal(0);
  });
});

describe('Modern syntax and file types', () => {
  const modernSyntax = `
import config from './config.json' with { type: 'json' };
class Window { #secret = 1; static { this.ready = true; } }
const value = config?.a ?? 0;
const { shell } = await import('electron');
shell.openExternal(value);
`;

  for (const filename of ['main.mjs', 'main.js', 'main.mts']) {
    it(`parses ${filename} and runs checks on it`, async () => {
      (await findIssues(filename, modernSyntax, '30.0.0', 'OPEN_EXTERNAL_JS_CHECK')).should.equal(1);
    });
  }

  it('parses CommonJS .cjs files', async () => {
    (await findIssues('main.cjs', nodeIntegrationWindow, '30.0.0', 'NODE_INTEGRATION_JS_CHECK')).should.equal(1);
  });
});

describe('Electron version detection', () => {
  it('reads package-lock.json v3', () => {
    findElectronVersionsFromPackageLock({
      lockfileVersion: 3,
      packages: {
        '': { devDependencies: { electron: '^38.0.0' } },
        'node_modules/electron': { version: '38.1.2' },
        'node_modules/electron-builder': { version: '26.0.0' }
      }
    }).should.deep.equal(['38.1.2']);
  });

  it('reads package-lock.json v1', () => {
    findElectronVersionsFromPackageLock({ lockfileVersion: 1, dependencies: { electron: { version: '9.4.0' } } }).should.deep.equal(['9.4.0']);
  });

  it('reads Yarn classic lockfiles', () => {
    const yarnLock = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


electron@^30.0.0:
  version "30.4.0"
  resolved "https://registry.yarnpkg.com/electron/-/electron-30.4.0.tgz"

electron-builder@^24.0.0:
  version "24.13.3"
`;
    findElectronVersionsFromYarnLock(yarnLock).should.deep.equal(['30.4.0']);
  });

  it('reads Yarn Berry lockfiles', () => {
    const yarnLock = `__metadata:
  version: 8
  cacheKey: 10

"electron@npm:^31.0.0":
  version: 31.7.7
  resolution: "electron@npm:31.7.7"

"electron-updater@npm:^6.0.0":
  version: 6.3.9
  resolution: "electron-updater@npm:6.3.9"
`;
    findElectronVersionsFromYarnLock(yarnLock).should.deep.equal(['31.7.7']);
  });

  it('reads pnpm lockfiles', () => {
    const pnpmLock = `lockfileVersion: '9.0'

importers:
  .:
    devDependencies:
      electron:
        specifier: ^37.0.0
        version: 37.2.0

packages:
  electron@37.2.0:
    resolution: {integrity: sha512-abc}
  electron-store@10.0.0:
    resolution: {integrity: sha512-def}
`;
    findElectronVersionsFromPnpmLock(pnpmLock).should.deep.equal(['37.2.0']);
  });

  it('returns the oldest version across sources', async () => {
    const version = await findOldestElectronVersion({
      pjsonData: { devDependencies: { electron: '^38.0.0' } },
      plockData: { packages: { 'node_modules/electron': { version: '38.1.2' }, 'packages/legacy/node_modules/electron': { version: '28.3.3' } } }
    });
    version.should.equal('28.3.3');
  });

  it('ignores malformed lockfiles', async () => {
    const version = await findOldestElectronVersion({ pjsonData: { dependencies: { electron: '33.0.0' } }, yarnLockData: '{{{ not a lockfile', pnpmLockData: ': : :' });
    should.exist(version);
    version.should.equal('33.0.0');
  });
});
