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
