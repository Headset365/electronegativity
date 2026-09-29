import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { SevenZipArchive, findEmbedded, safeJoin } from '../src/unpack/sevenzip.js';
import { parseNsis, registryClasses } from '../src/unpack/nsis.js';
import zlib from 'node:zlib';
import { zipEntries, zipRead, extractZip, ZipError } from '../src/unpack/zip.js';
import { decodeLzma, LzmaError } from '../src/unpack/lzma.js';
import { MAX_STREAM } from '../src/unpack/limits.js';
import { unpackTarget, isPackage, UnpackError } from '../src/unpack/index.js';

chaiShould();
await _i18n();

const FIXTURES = path.join(import.meta.dirname, 'unpack');
const fixture = (name) => path.join(FIXTURES, name);
const sha = (data) => crypto.createHash('sha256').update(data).digest('hex');
const EXPECTED = path.join(FIXTURES, '7z', 'expected');

describe('Unpacking installers and packages', () => {
  describe('7z', () => {
    for (const [name, methods] of [['lzma2-bcj2', ['LZMA2', 'LZMA', 'BCJ2']], ['lzma', ['LZMA', 'BCJ']], ['deflate', ['Deflate', 'BCJ']], ['copy', ['Copy', 'BCJ']],
      ['bcj', ['LZMA2', 'BCJ']], ['delta', ['LZMA2', 'Delta']]]) {
      it(`reads what 7-Zip wrote with ${methods.join(' + ')} (${name}.7z)`, () => {
        const archive = SevenZipArchive.open(path.join(FIXTURES, '7z', `${name}.7z`));
        archive.methods().should.include.members(methods);
        const files = Object.fromEntries([...archive.files()].map(([e, data]) => [e.name, sha(data)]));
        for (const file of ['text.txt', 'sub/data.bin', 'app.exe', 'empty.txt']) files[file].should.equal(sha(fs.readFileSync(path.join(EXPECTED, file))), file);
        archive.entries.filter(e => e.isDir).map(e => e.name).should.include('emptydir');
      });
    }

    it('refuses encrypted archives with a clear message', () => {
      const archive = SevenZipArchive.open(path.join(FIXTURES, '7z', 'aes.7z'));
      (() => [...archive.files()]).should.throw(/encrypted/);
    });

    it('extracts electron-builder\'s app package, checking every CRC', () => {
      const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-7z-'));
      const written = SevenZipArchive.open(fixture('insecure-fixture-app-64.7z')).extractAll(dest);
      written.should.include.members(['resources/app.asar', 'Insecure Fixture.exe', 'resources/app-update.yml']);
      fs.statSync(path.join(dest, 'Insecure Fixture.exe')).size.should.be.above(1000);
    });

    it('never writes outside the destination', () => {
      const root = path.resolve('/tmp/root');
      for (const name of ['../escape', 'a/../../etc/passwd', 'C:/Windows/x', '']) (safeJoin(root, name) === undefined).should.equal(true, name);
      safeJoin(root, '/absolute/name').should.equal(path.join(root, 'absolute', 'name'));
      safeJoin(root, 'a/./b').should.equal(path.join(root, 'a', 'b'));
    });

    it('finds a 7z archive embedded in another file', () => {
      const data = fs.readFileSync(fixture('insecure-fixture-setup.exe'));
      findEmbedded(data).length.should.equal(1);
    });
  });

  describe('NSIS', () => {
    it('finds the stored app package and what the installer registers', () => {
      const info = parseNsis(fs.readFileSync(fixture('insecure-fixture-setup.exe')));
      info.should.include({ compression: 'deflate', solid: false });
      info.payloads.map(p => p.kind).should.deep.equal(['7z']);
      registryClasses(info.strings).should.deep.equal({ protocols: ['insecurefx'], extensions: ['.insfx'] });
    });

    for (const [name, compression, solid] of [['nsis-lzma-solid.exe', 'lzma', true], ['nsis-lzma.exe', 'lzma', false], ['nsis-bzip2.exe', 'bzip2', false]]) {
      it(`unpacks a ${solid ? 'solid ' : ''}${compression} installer (${name})`, () => {
        const unpacked = unpackTarget(fixture(name));
        try {
          unpacked.kind.should.equal('nsis-installer');
          unpacked.installer.nsis.should.include({ compression, solid });
          fs.existsSync(unpacked.code).should.equal(true);
          path.basename(unpacked.mainExe).should.equal('Insecure Fixture.exe');
          // bzip2: the script header can't be read, but the stored app package still is
          if (compression === 'bzip2') unpacked.warnings.some(w => /bzip2/.test(w)).should.equal(true);
          else unpacked.installer.nsis.protocols.should.deep.equal(['tinyapp']);
        } finally {
          unpacked.cleanup();
        }
      });
    }

    it('picks the x64 package of a multi-architecture installer', () => {
      const unpacked = unpackTarget(fixture('nsis-multi.exe'));
      try {
        unpacked.installer.nsis.arches.should.deep.equal(['x86', 'x64']);
        unpacked.warnings.some(w => /x64 one was scanned/.test(w)).should.equal(true);
      } finally {
        unpacked.cleanup();
      }
    });

    it('explains that a web installer downloads its app', () => {
      (() => unpackTarget(fixture('nsis-web.exe'))).should.throw(UnpackError, /web installer.*tiny-1\.0\.0-x64\.nsis\.7z/);
    });
  });

  describe('Squirrel, zip and nupkg', () => {
    it('reads zip archives', () => {
      zipEntries(fs.readFileSync(fixture('app.zip'))).some(e => e.name.endsWith('resources/app.asar')).should.equal(true);
    });

    for (const [name, kind] of [['squirrel-setup.exe', 'squirrel-installer'], ['InsecureFixture-1.2.3-full.nupkg', 'nupkg'], ['app.zip', 'zip-package'], ['insecure-fixture-app-64.7z', '7z-package']]) {
      it(`unpacks ${name}`, () => {
        isPackage(fixture(name)).should.equal(true);
        const unpacked = unpackTarget(fixture(name));
        try {
          unpacked.kind.should.equal(kind);
          path.basename(unpacked.code).should.equal('app.asar');
          path.basename(unpacked.mainExe).should.equal('Insecure Fixture.exe');
          unpacked.installer.sha256.should.equal(sha(fs.readFileSync(fixture(name))));
        } finally {
          unpacked.cleanup();
        }
      });
    }

    it('leaves app folders, app.asar and an app\'s own executable to the usual loaders', () => {
      isPackage(FIXTURES).should.equal(false);
      isPackage(path.join(import.meta.dirname, 'file_formats', 'electron.asar')).should.equal(false);
      const exe = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eng-exe-')), 'app.exe');
      fs.writeFileSync(exe, Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200)]));
      isPackage(exe).should.equal(false);
    });
  });

  describe('Size limits', () => {
    // a one-entry zip whose central directory declares `size` for the deflated `content`
    const zipOf = (content, size) => {
      const data = zlib.deflateRawSync(content);
      const name = Buffer.from('bomb.bin');
      const local = Buffer.alloc(30);
      local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(8, 8); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(size, 22); local.writeUInt16LE(name.length, 26);
      const central = Buffer.alloc(46);
      central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(8, 10); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(size, 24); central.writeUInt16LE(name.length, 28);
      const end = Buffer.alloc(22);
      const start = local.length + name.length + data.length;
      end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(central.length + name.length, 12); end.writeUInt32LE(start, 16);
      return Buffer.concat([local, name, data, central, name, end]);
    };

    it('stops a zip entry at its declared size (zip bomb)', () => {
      const bomb = zipOf(Buffer.alloc(8 * 1024 * 1024), 100);
      (() => zipRead(bomb, zipEntries(bomb)[0])).should.throw(ZipError, /more than its declared size/);
      const honest = zipOf(Buffer.from('hello'), 5);
      zipRead(honest, zipEntries(honest)[0]).toString().should.equal('hello');
    });

    it('refuses declared sizes over the limit before allocating anything', () => {
      const huge = zipOf(Buffer.from('x'), 0xfffffff0);
      if (MAX_STREAM < 0xfffffff0) (() => zipRead(huge, zipEntries(huge)[0])).should.throw(ZipError, /limit/);
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-bomb-'));
      try {
        const many = zipOf(Buffer.from('x'), 0xfffffff0);
        (() => extractZip(many, dir)).should.throw(ZipError);
        fs.readdirSync(dir).length.should.equal(0);
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
      (() => decodeLzma(Buffer.from([0x5d, 0, 0, 1, 0]), Buffer.alloc(16), MAX_STREAM + 1)).should.throw(LzmaError, /limit/);
    });
  });

  it('scans the app inside an installer, with what the installer says about itself', async () => {
    const unpacked = unpackTarget(fixture('insecure-fixture-setup.exe'));
    try {
      const result = await run({ input: unpacked.code, installer: unpacked, offline: true });
      const ids = result.issues.map(i => i.id);
      ids.should.include.members(['NODE_INTEGRATION_JS_CHECK', 'INSTALLER_FILE_HANDLER', 'CODE_SIGNING', 'PACKAGED_FUSES', 'UPDATE_SECURITY_PACKAGED']);
      result.issues.filter(i => i.id === 'CODE_SIGNING').map(i => !!i.properties.installer).sort().should.deep.equal([false, true]);
      result.installer.kind.should.equal('nsis-installer');
    } finally {
      unpacked.cleanup();
    }
  });
});
