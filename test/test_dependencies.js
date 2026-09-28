import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { detectLibraries } from '../src/util/libraries.js';
import { vendoredLibrary } from '../src/util/file.js';
import { dependencyReport, registryFacts, supportFacts, advisoryFacts, eolProduct, sortRows, repositoryUrl } from '../src/util/dependencies.js';
import { renderHtmlReport } from '../src/util/report_html.js';

chaiShould();
await _i18n();

// Canned answers of the npm registry, endoflife.date and OSV
const REGISTRY = {
  jquery: {
    'dist-tags': { latest: '3.7.1' },
    homepage: 'https://jquery.com',
    repository: { type: 'git', url: 'git+https://github.com/jquery/jquery.git' },
    versions: { '1.12.4': {}, '3.4.1': { deprecated: 'This version is deprecated.' }, '3.5.0': {}, '3.6.0': {}, '3.7.1': {}, '4.0.0-beta': {} },
    time: { '1.12.4': '2016-05-20T00:00:00Z', '3.4.1': '2019-05-01T21:04:36Z', '3.5.0': '2020-04-10T00:00:00Z', '3.6.0': '2021-03-02T00:00:00Z', '3.7.1': '2023-08-28T13:37:37Z' },
  },
  angular: {
    'dist-tags': { latest: '1.8.3' },
    versions: { '1.5.8': {}, '1.8.2': {}, '1.8.3': {} },
    time: { '1.5.8': '2016-07-22T00:00:00Z', '1.8.2': '2020-10-21T00:00:00Z', '1.8.3': '2022-04-07T00:00:00Z' },
  },
  marked: {
    'dist-tags': { latest: '12.0.0' },
    versions: { '0.3.6': {}, '4.0.10': {}, '11.0.0': {}, '12.0.0': {} },
    time: { '0.3.6': '2016-07-30T00:00:00Z', '12.0.0': '2024-01-01T00:00:00Z' },
  },
};
const EOL = {
  jquery: { links: { releasePolicy: 'https://jquery.com/support/' }, releases: [
    { name: '3', isEol: false, eolFrom: null }, { name: '2', isEol: true, eolFrom: null }, { name: '1', isEol: true, eolFrom: null }] },
  angularjs: { links: { releasePolicy: 'https://docs.angularjs.org/misc/version-support-status' }, releases: [
    { name: '1.8', isEol: true, eolFrom: '2021-12-31', isMaintained: true, custom: { eoesProvider: 'HeroDevs' } }, { name: '1.5', isEol: true, eolFrom: '2021-12-31' }] },
};
const OSV = {
  'jquery@3.4.1': [{ id: 'GHSA-gxr4-xjj5-5px2', aliases: ['CVE-2020-11022'], summary: 'Potential XSS vulnerability in jQuery', database_specific: { severity: 'MODERATE' },
    references: [{ type: 'WEB', url: 'https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/' }, { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022' },
      { type: 'FIX', url: 'https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77' }, { type: 'PACKAGE', url: 'https://www.npmjs.com/package/jquery' }],
    affected: [{ package: { name: 'jquery', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.2.0' }, { fixed: '3.5.0' }] }] }] }],
  'angular@1.5.8': [{ id: 'GHSA-aaaa', aliases: ['CVE-2022-25844'], summary: 'ReDoS', database_specific: { severity: 'MODERATE' },
    affected: [{ package: { name: 'angular', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.2.21' }] }] }] }],
};

function mockFetch() {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push(String(url));
    const json = (status, body) => ({ ok: status < 400, status, json: async () => body });
    if (url.startsWith('https://registry.npmjs.org/')) {
      const doc = REGISTRY[decodeURIComponent(url.slice('https://registry.npmjs.org/'.length))];
      return doc ? json(200, doc) : json(404, {});
    }
    if (url.startsWith('https://endoflife.date/api/v1/products/')) {
      const product = EOL[url.split('/').pop()];
      return product ? json(200, { result: product }) : json(404, {});
    }
    if (url === 'https://api.osv.dev/v1/query') {
      const { package: { name }, version } = JSON.parse(init.body);
      return json(200, OSV[`${name}@${version}`] ? { vulns: OSV[`${name}@${version}`] } : {});
    }
    throw new Error(`unexpected ${url}`);
  };
  return { calls, restore: () => { globalThis.fetch = original; } };
}

describe('Library detection', () => {
  it('finds libraries by their banners, also several concatenated in one bundle', () => {
    const bundle = [
      '/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(){}();',
      '/**\n * @license AngularJS v1.5.8\n * (c) 2010-2016 Google, Inc. http://angularjs.org\n * License: MIT\n */\n(function(){})();',
      '/**\n * Copyright (c) Tiny Technologies, Inc. All rights reserved.\n *\n * Version: 5.10.2 (2021-11-17)\n */\n!function(){}();',
      '/*! @license DOMPurify 2.3.3 | (c) Cure53 and other contributors */',
    ].join('\n');
    detectLibraries(bundle).map(l => `${l.name}@${l.version}`).should.have.members(['jquery@3.4.1', 'angular@1.5.8', 'tinymce@5.10.2', 'dompurify@2.3.3']);
  });

  it('finds libraries whose banner was stripped by their version strings', () => {
    detectLibraries('var e={full:"1.8.2",major:1,minor:8,dot:2,codeName:"meteoric-mining"};').should.deep.equal([{ name: 'angular', version: '1.8.2' }]);
    detectLibraries('var n,t="4.17.21",r=200,e="Unsupported core-js use. Try https://npms.io/search?q=ponyfill."').should.deep.equal([{ name: 'lodash', version: '4.17.21' }]);
    detectLibraries('d={timestamp:"L8FE",version:"4.16.2 (Standard)",revision:"x"}').should.deep.equal([{ name: 'ckeditor4', version: '4.16.2' }]);
    detectLibraries('f.version="2.29.1",e=Tt,f.fn=pn,f.min=function(){}').should.deep.equal([{ name: 'moment', version: '2.29.1' }]);
  });

  it('does not take the Underscore.js credit in lodash\'s banner for underscore', () => {
    detectLibraries('/**\n * @license\n * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE\n */').should.deep.equal([]);
  });

  it('names library copies the way npm does and ignores query-string suffixes', () => {
    vendoredLibrary('js/purify.min.js', '/*! @license DOMPurify 2.3.3 | (c) Cure53 and other contributors | Released under the Apache license 2.0 and Mozilla Public License 2.0 */')
      .should.deep.equal({ name: 'dompurify', version: '2.3.3' });
    vendoredLibrary('js/angular.min_0123abcd.js', '/*\n AngularJS v1.8.2\n (c) 2010-2020 Google, Inc. http://angularjs.org\n License: MIT\n*/')
      .should.deep.equal({ name: 'angular', version: '1.8.2' });
  });
});

describe('Dependency table', () => {
  it('reads release dates, the latest version and how far behind a version is', () => {
    const facts = registryFacts(REGISTRY.jquery, '3.4.1');
    facts.should.include({ released: '2019-05-01', latest: '3.7.1', latestReleased: '2023-08-28', versionsBehind: 3, majorsBehind: 0, latestInMajor: '3.7.1', known: true });
    facts.deprecated.should.match(/deprecated/);
  });

  it('links to the project: repository, release notes and homepage', () => {
    registryFacts(REGISTRY.jquery, '3.4.1').should.include({ homepage: 'https://jquery.com', repository: 'https://github.com/jquery/jquery', releaseNotes: 'https://github.com/jquery/jquery/releases' });
    repositoryUrl('github:owner/repo').should.equal('https://github.com/owner/repo');
    repositoryUrl('owner/repo').should.equal('https://github.com/owner/repo');
    repositoryUrl('git@github.com:owner/repo.git').should.equal('https://github.com/owner/repo');
    repositoryUrl({ url: 'git://github.com/owner/repo.git#main' }).should.equal('https://github.com/owner/repo');
    (repositoryUrl('not a url') === undefined).should.equal(true);
  });

  it('matches a version to its release line on endoflife.date', () => {
    supportFacts(EOL.jquery, '3.4.1').should.include({ status: 'supported' });
    supportFacts(EOL.jquery, '1.12.4').should.include({ status: 'unsupported' });
    const angular = supportFacts(EOL.angularjs, '1.8.2');
    angular.status.should.equal('unsupported');
    angular.detail.should.equal('1.8.x reached end of life on 2021-12-31 (paid extended support: HeroDevs)');
    angular.supported.should.deep.equal(['none (all release lines are end of life)']);
    eolProduct('angular-sanitize').should.equal('angularjs');
    eolProduct('@angular/core').should.equal('angular');
  });

  it('lists advisories with their CVE ids and the version that fixes them', () => {
    const [advisory] = advisoryFacts(OSV['jquery@3.4.1'], 'jquery', '3.4.1');
    advisory.should.deep.include({ id: 'GHSA-gxr4-xjj5-5px2', cves: ['CVE-2020-11022'], summary: 'Potential XSS vulnerability in jQuery', severity: 'MEDIUM', fixed: '3.5.0' });
    // the advisory's own references, advisory first, without package links
    advisory.references.map(r => r.type).should.deep.equal(['ADVISORY', 'FIX', 'WEB']);
    advisoryFacts(OSV['angular@1.5.8'], 'angular', '1.5.8')[0].should.include({ fixed: undefined });
  });

  it('combines the three sources, and sorts vulnerable and unsupported packages first', async () => {
    const mock = mockFetch();
    try {
      const { rows, errors } = await dependencyReport([
        { name: 'marked', version: '0.3.6', kinds: ['lockfile'], files: [] },
        { name: 'jquery', version: '3.4.1', kinds: ['bundled library'], files: ['js/vendor.js'] },
        { name: 'angular', version: '1.5.8', kinds: ['bundled library'], files: ['js/vendor.js'] },
        { name: 'private-thing', version: '1.0.0', kinds: ['node_modules'], files: [] },
      ]);
      errors.should.deep.equal([]);
      const byName = Object.fromEntries(rows.map(r => [r.name, r]));
      byName.jquery.support.status.should.equal('unsupported'); // deprecated inside the supported 3.x line
      byName.jquery.support.supported.should.deep.equal(['3.x']);
      byName.jquery.fixedIn.should.equal('3.5.0');
      (byName.angular.fixedIn === null).should.equal(true);
      byName.marked.support.should.include({ status: 'outdated' });
      byName.marked.majorsBehind.should.equal(12);
      byName['private-thing'].support.should.include({ status: 'unknown', detail: 'Not found on npm' });
      sortRows(rows).map(r => r.name).should.deep.equal(['angular', 'jquery', 'marked', 'private-thing']);
      mock.calls.filter(u => u.includes('endoflife')).length.should.equal(2);
    } finally {
      mock.restore();
    }
  });

  it('looks nothing up offline', async () => {
    const mock = mockFetch();
    process.env.ELECTRONEGATIVITY_OFFLINE = '1';
    try {
      const report = await dependencyReport([{ name: 'jquery', version: '3.4.1', kinds: ['lockfile'], files: [] }]);
      report.offline.should.equal(true);
      mock.calls.should.deep.equal([]);
    } finally {
      delete process.env.ELECTRONEGATIVITY_OFFLINE;
      mock.restore();
    }
  });

  it('lists lockfile packages, bundled libraries and Electron in HTML and JSON reports', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-deps-'));
    fs.mkdirSync(path.join(dir, 'js'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'demo', main: 'main.js', dependencies: { marked: '0.3.6' }, devDependencies: { electron: '34.5.8' } }));
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ name: 'demo', lockfileVersion: 3, packages: { '': { name: 'demo' }, 'node_modules/marked': { version: '0.3.6' } } }));
    fs.writeFileSync(path.join(dir, 'main.js'), 'const { app } = require("electron");');
    fs.writeFileSync(path.join(dir, 'js', 'app.js'), '/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(){}();\nwindow.app = 1;');
    const mock = mockFetch();
    try {
      const result = await run({ input: dir, output: path.join(dir, 'report.json') }, false);
      const names = result.dependencies.rows.map(r => `${r.name}@${r.version}`);
      names.should.include.members(['electron@34.5.8', 'marked@0.3.6', 'jquery@3.4.1']);
      result.dependencies.rows.find(r => r.name === 'jquery').files.should.deep.equal([path.join('js', 'app.js')]);
      result.dependencies.rows.find(r => r.name === 'marked').direct.should.equal(true);
      JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8')).dependencies.rows.length.should.equal(result.dependencies.rows.length);

      const html = renderHtmlReport([], { version: '2.0.0', input: dir, electronVersion: '34.5.8', filesScanned: 1, atomicChecks: 1, globalChecks: 1, generatedAt: 'now', errors: [], dependencies: result.dependencies });
      html.should.include('<h2 id="dependencies">Dependencies (3)</h2>');
      html.should.include('CVE-2020-11022');
      html.should.include('All fixed in 3.5.0');
      // references for each advisory and for the latest version
      html.should.include('href="https://nvd.nist.gov/vuln/detail/CVE-2020-11022"');
      html.should.include('href="https://github.com/advisories/GHSA-gxr4-xjj5-5px2"');
      html.should.include('href="https://github.com/jquery/jquery/commit/1d61fd9407e6fbe82fe55cb0b938307aa0791f77"');
      html.should.include('href="https://www.npmjs.com/package/jquery/v/3.7.1"');
      html.should.include('href="https://github.com/jquery/jquery/releases"');
      html.should.include('href="https://www.npmjs.com/package/jquery/v/3.5.0"');
    } finally {
      mock.restore();
    }
  });
});
