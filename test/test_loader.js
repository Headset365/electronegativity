import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';

import { LoaderAsar, LoaderFile } from '../src/loader/index.js';

const should = chaiShould();
await _i18n();

let test_files = new Map()
  .set('asar', 'test/file_formats/electron.asar')
  .set('html', 'test/file_formats/test.html')
  .set('js', 'test/file_formats/test.js');

describe('Loader classes', () => {
  describe('LoaderASAR', () => {
    let loader = null;

    beforeEach(() => {
      loader = new LoaderAsar();
    });

    it('fails if archive does not exist', async () => {
      let error;
      try {
        await loader.load('FOO');
      } catch (e) {
        error = e;
      }
      should.exist(error);
    });

    it('extracts file from ASAR', async () => {
      await loader.load(test_files.get('asar'));
      loader.list_files.size.should.equal(61);
    });

    it('finds Electron version number in package.json', async () => {
      await loader.load(test_files.get('asar'));
      loader.electronVersion.should.equal('6.1.11');
    });
  }),

  describe('LoaderFile', () => {
    let loader = null;

    beforeEach(() => {
      loader = new LoaderFile();
    });

    it('fails if archive does not exist', () => {
      (() => {
        loader.load('FOO');
      }).should.throw();
    });

    it('extracts file from ASAR', () => {
      loader.load(test_files.get('js'));
      loader.list_files.size.should.equal(1);
    });
  });
});

describe('Packaged apps', () => {
  // the usual AngularJS build output: the app's code in scripts/*.min.js, libraries in a vendor bundle, no lockfile
  const build = async () => {
    const { default: fs } = await import('node:fs');
    const { default: os } = await import('node:os');
    const { default: path } = await import('node:path');
    const asar = await import('@electron/asar');
    const src = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-packaged-src-'));
    const write = (file, content) => { fs.mkdirSync(path.dirname(path.join(src, file)), { recursive: true }); fs.writeFileSync(path.join(src, file), content); };
    write('package.json', '{ "name": "docs-app", "main": "main.js", "dependencies": { "angular": "1.5.8" } }');
    write('main.js', 'const { app } = require("electron");');
    write('scripts/scripts.min.js', 'angular.module("docs",[]).controller("Doc",function($scope,$sce,$http){$http.get("/api/doc/1").then(function(r){$scope.body=$sce.trustAsHtml(r.data.body)})});');
    write('scripts/vendor.min.js', '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(){}();');
    write('test/app.spec.js', 'describe("x", () => {});');
    write('node_modules/angular/package.json', '{ "name": "angular", "version": "1.5.8" }');
    write('node_modules/@scope/lib/package.json', '{ "name": "@scope/lib", "version": "2.0.0" }');
    write('node_modules/angular/node_modules/nested/package.json', '{ "name": "nested", "version": "0.1.0" }');
    write('node_modules/angular/lib/package.json', '{ "name": "not-a-package-root", "version": "9.9.9" }');
    const archive = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eng-packaged-')), 'app.asar');
    await asar.createPackage(src, archive);
    return archive;
  };

  it('scans everything that ships (scripts/, .min.js), lists the packages in node_modules and recognizes a vendor bundle', async () => {
    const loader = new LoaderAsar();
    await loader.load(await build());
    const files = [...loader.list_files].map(f => f.split(/[\\/]/).join('/'));
    files.should.include('scripts/scripts.min.js');
    files.should.not.include('scripts/vendor.min.js');
    files.should.not.include('test/app.spec.js');
    loader.vendoredLibraries.map(l => `${l.name}@${l.version}`).should.deep.equal(['jquery@1.12.4']);
    loader.installedPackages.map(p => `${p.name}@${p.version}`).should.have.members(['angular@1.5.8', '@scope/lib@2.0.0', 'nested@0.1.0']);
  });

  it('reports the shipped app code and end-of-life packages of a packaged app', async () => {
    const { default: run } = await import('../src/runner.js');
    const result = await run({ input: await build(), offline: true });
    result.issues.some(i => i.id === 'ANGULAR_TRUST_HTML_JS_CHECK' && /scripts\.min\.js$/.test(i.file) && i.severity.name === 'HIGH').should.equal(true);
    const eol = result.issues.filter(i => i.id === 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK').map(i => i.properties.package);
    eol.should.have.members(['angular', 'jquery']);
  });
});
