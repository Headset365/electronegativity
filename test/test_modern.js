import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
import { listLockfilePackages } from '../src/util/lockfiles.js';
import { renderHtmlReport } from '../src/util/report_html.js';
import { writeIssues } from '../src/util/index.js';
import { severity, confidence } from '../src/finder/attributes.js';
import UnsupportedVersionGlobalCheck from '../src/finder/checks/GlobalChecks/UnsupportedVersionGlobalCheck.js';

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

  describe('affinity (removed in Electron 14)', () => {
    const affinityWindow = `const win = new BrowserWindow({ webPreferences: { affinity: 'shared' } });`;
    it('is reported on Electron 13', async () => {
      (await findIssues('main.js', affinityWindow, '13.0.0', 'AFFINITY_JS_CHECK')).should.equal(1);
    });
    it('is not reported on Electron 14+', async () => {
      (await findIssues('main.js', affinityWindow, '14.0.0', 'AFFINITY_JS_CHECK')).should.equal(0);
    });
  });

  describe("'new-window' event (removed in Electron 22)", () => {
    const newWindow = `win.webContents.on('new-window', (e) => e.preventDefault());`;
    it('counts as a navigation limit on Electron 21', async () => {
      const finder = new Finder(null, null, null);
      const [type, data, content] = parsers[0].parse('main.js', newWindow);
      const issues = await finder.find('main.js', data, type, content, null, '21.0.0');
      issues.filter(i => i.id === 'LIMIT_NAVIGATION_JS_CHECK').map(i => i.properties.event).should.deep.equal(['new-window']);
    });
    it('is reported as ineffective on Electron 22+', async () => {
      const finder = new Finder(null, null, null);
      const [type, data, content] = parsers[0].parse('main.js', newWindow);
      const issues = await finder.find('main.js', data, type, content, null, '22.0.0');
      issues.filter(i => i.id === 'LIMIT_NAVIGATION_JS_CHECK').map(i => i.properties.event).should.deep.equal(['new-window-removed']);
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

  it('reads multi-document pnpm lockfiles (pnpm 10)', () => {
    const pnpmLock = `lockfileVersion: '9.0'\nimporters:\n  .:\n    configDependencies: {}\n---\nlockfileVersion: '9.0'\npackages:\n  electron@39.1.0:\n    resolution: {integrity: sha512-x}\n`;
    findElectronVersionsFromPnpmLock(pnpmLock).should.deep.equal(['39.1.0']);
  });

  it("prefers the root project's locked Electron over copies pulled in by tools", async () => {
    const version = await findOldestElectronVersion({
      pjsonData: { devDependencies: { electron: '^38.0.0' } },
      plockData: { packages: { 'node_modules/electron': { version: '38.1.2' }, 'node_modules/some-test-runner/node_modules/electron': { version: '28.3.3' } } }
    });
    version.should.equal('38.1.2');
  });

  it("uses pnpm importers to find the root project's Electron", async () => {
    const pnpmLock = `lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      electron:\n        specifier: 44.2.0\n        version: 44.2.0\npackages:\n  electron@39.8.10:\n    resolution: {integrity: a}\n  electron@44.2.0:\n    resolution: {integrity: b}\n`;
    (await findOldestElectronVersion({ pjsonData: { devDependencies: { electron: '44.2.0' } }, pnpmLockData: pnpmLock })).should.equal('44.2.0');
  });

  it('falls back to every lockfile entry when the root dependency is unknown', async () => {
    (await findOldestElectronVersion({ plockData: { packages: { 'a/node_modules/electron': { version: '30.0.0' }, 'b/node_modules/electron': { version: '29.1.0' } } } })).should.equal('29.1.0');
  });

  it('ignores malformed lockfiles', async () => {
    const version = await findOldestElectronVersion({ pjsonData: { dependencies: { electron: '33.0.0' } }, yarnLockData: '{{{ not a lockfile', pnpmLockData: ': : :' });
    should.exist(version);
    version.should.equal('33.0.0');
  });
});

describe('Lockfile inventory', () => {
  it('lists npm lockfile v3 packages with their dev flag', () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      '': { name: 'app' },
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/@scope/tool': { version: '1.0.0', dev: true },
      'node_modules/a/node_modules/lodash': { version: '4.17.21', dev: true },
      'packages/local': { link: true, resolved: 'packages/local' }
    } }, null, 2);
    listLockfilePackages('package-lock.json', lock).map(({ name, version, dev }) => ({ name, version, dev })).should.deep.equal([
      { name: 'lodash', version: '4.17.21', dev: false },
      { name: '@scope/tool', version: '1.0.0', dev: true },
    ]);
  });

  it('lists Yarn classic, Yarn Berry and pnpm packages', () => {
    const classic = 'electron@^30.0.0:\n  version "30.4.0"\n\n"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":\n  version "1.2.0"\n';
    listLockfilePackages('yarn.lock', classic).map(p => `${p.name}@${p.version}`).should.deep.equal(['electron@30.4.0', '@scope/pkg@1.2.0']);

    const berry = '__metadata:\n  version: 8\n\n"@scope/pkg@npm:^1.0.0":\n  version: 1.2.0\n  resolution: "@scope/pkg@npm:1.2.0"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n';
    listLockfilePackages('yarn.lock', berry).map(p => `${p.name}@${p.version}`).should.deep.equal(['@scope/pkg@1.2.0']);

    const pnpm = "lockfileVersion: '9.0'\npackages:\n  '@scope/pkg@1.2.0':\n    resolution: {integrity: sha512-a}\n  react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-b}\n";
    listLockfilePackages('pnpm-lock.yaml', pnpm).map(p => `${p.name}@${p.version}`).should.deep.equal(['@scope/pkg@1.2.0', 'react-dom@18.2.0']);
  });
});

describe('Unsupported Electron versions', () => {
  const releases = ['40.1.0', '40.0.0', '39.2.3', '39.2.2', '38.5.0', '37.9.9'];
  const run = (versionNumber, versionSpec) => {
    const check = new UnsupportedVersionGlobalCheck();
    check.getReleases = async () => releases;
    return check.perform([{ id: 'ELECTRON_VERSION_JSON_CHECK', file: 'package.json', properties: { versionNumber, versionSpec }, manualReview: true }], 'quiet');
  };

  it('reports majors older than the latest three', async () => {
    const [issue] = await run('37.0.0', '^37.0.0');
    issue.severity.name.should.equal('HIGH');
    issue.properties.supported.should.deep.equal([40, 39, 38]);
  });
  it('does not report supported majors installed through a range', async () => {
    (await run('39.0.0', '^39.0.0')).should.have.length(0);
  });
  it('reports a newer patch release for pinned versions', async () => {
    const [issue] = await run('39.2.2', '39.2.2');
    issue.severity.name.should.equal('LOW');
    issue.properties.latest.should.equal('39.2.3');
  });
});

describe('Report output', () => {
  const issue = (overrides) => ({
    id: 'OPEN_EXTERNAL_JS_CHECK', file: 'src/main.js', location: { line: 3, column: 2 },
    sample: '</script><img src=x onerror=alert(1)>', description: 'Review the use of openExternal',
    severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true,
    shortenedURL: 'javascript:alert(1)', ...overrides
  });

  it('renders a self-contained HTML report that escapes scanned code', () => {
    const html = renderHtmlReport([issue(), issue({ id: 'X_CHECK', severity: severity.HIGH, properties: { advisories: ['GHSA-1234-abcd-efgh'] }, shortenedURL: 'https://example.com' })],
      { version: '2.0.0', input: '/app', electronVersion: '38.0.0', filesScanned: 1, atomicChecks: 1, globalChecks: 1, generatedAt: 'now', errors: [] });
    html.should.not.include('<img src=x');
    html.should.include('&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;');
    html.should.not.include('href="javascript:');
    html.should.include('https://osv.dev/vulnerability/GHSA-1234-abcd-efgh');
    html.should.not.match(/<(link|script) [^>]*src=/);
  });

  it('writes JSON, HTML, SARIF and CSV based on the file extension', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-report-'));
    for (const ext of ['json', 'html', 'sarif', 'csv']) {
      const file = path.join(dir, `out.${ext}`);
      writeIssues('/app', false, file, [issue()], false, { electronVersion: '38.0.0' });
      const content = fs.readFileSync(file, 'utf8');
      if (ext === 'json') {
        const json = JSON.parse(content);
        json.electronVersion.should.equal('38.0.0');
        json.issues[0].severity.should.equal('MEDIUM');
      }
      if (ext === 'html') content.should.match(/^<!doctype html>/);
      if (ext === 'sarif') JSON.parse(content).version.should.equal('2.1.0');
      if (ext === 'csv') content.split('\n')[0].should.match(/^issue, severity/);
    }
    fs.rmSync(dir, { recursive: true });
  });
});
