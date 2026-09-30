import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { varint, snappyDecompress, logKeyValues, tableKeyValues, readStore } from '../src/storage/leveldb.js';
import { decodeDom, localStorageEntries, reviewCookies, reviewWebStorage, defaultProfileDirs } from '../src/storage/at_rest.js';
import { canaryForms, searchRoots, snapshot, changedFiles, credentialTargets, registryText, scanForCanaries } from '../src/storage/canary.js';
import { reviewDataAtRest, appNames, credentialBaseline } from '../src/storage/index.js';

const require = createRequire(import.meta.url);
chaiShould();
await _i18n();

const tmp = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
const encodeVarint = (n) => {
  const out = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return Buffer.from(out);
};
// a LevelDB write-ahead log with one FULL record holding a WriteBatch of puts
function writeLog(file, pairs) {
  const parts = [Buffer.alloc(12)];
  parts[0].writeUInt32LE(pairs.length, 8);
  for (const [key, value] of pairs) parts.push(Buffer.from([1]), encodeVarint(key.length), key, encodeVarint(value.length), value);
  const record = Buffer.concat(parts);
  const header = Buffer.alloc(7);
  header.writeUInt16LE(record.length, 4);
  header[6] = 1;
  fs.writeFileSync(file, Buffer.concat([header, record]));
}
// a table block: entries (no prefix sharing) and a restart array
function block(entries) {
  const parts = entries.map(([key, value]) => Buffer.concat([encodeVarint(0), encodeVarint(key.length), encodeVarint(value.length), key, value]));
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(0, 0); // one restart at 0
  tail.writeUInt32LE(1, 4);
  return Buffer.concat([...parts, tail]);
}
// Snappy: literals only
const snappyLiteral = (data) => Buffer.concat([encodeVarint(data.length), Buffer.from([((data.length - 1) << 2) | 0]), data]);
// Snappy with copies (greedy, brute force: test data is small), so repeated text isn't stored verbatim
function snappyCompress(data) {
  const out = [encodeVarint(data.length)];
  let literal = [];
  const flush = () => {
    if (literal.length === 0) return;
    out.push(Buffer.from([((literal.length - 1) << 2) | 0]), Buffer.from(literal));
    literal = [];
  };
  for (let i = 0; i < data.length;) {
    let best = 0;
    let offset = 0;
    for (let j = Math.max(0, i - 65535); j < i; j++) {
      let n = 0;
      while (n < 64 && i + n < data.length && data[j + n] === data[i + n]) n++;
      if (n > best) [best, offset] = [n, i - j];
    }
    if (best >= 4 && literal.length < 60) {
      flush();
      out.push(Buffer.from([((best - 1) << 2) | 2, offset & 0xff, offset >> 8]));
      i += best;
    } else {
      literal.push(data[i++]);
      if (literal.length === 60) flush();
    }
  }
  flush();
  return Buffer.concat(out);
}
const internalKey = (key, type = 1) => Buffer.concat([key, Buffer.from([type, 0, 0, 0, 0, 0, 0, 0])]);
// a LevelDB table: one Snappy-compressed data block, a raw index block, and the footer
function writeTable(file, entries) {
  const data = block(entries.map(([key, value, type]) => [internalKey(key, type), value]));
  const compressed = snappyCompress(data);
  const dataBlock = Buffer.concat([compressed, Buffer.from([1, 0, 0, 0, 0])]);
  const handle = Buffer.concat([encodeVarint(0), encodeVarint(compressed.length)]);
  const index = block([[Buffer.from('zzz'), handle]]);
  const indexOffset = dataBlock.length;
  const indexBlock = Buffer.concat([index, Buffer.from([0, 0, 0, 0, 0])]);
  const footer = Buffer.alloc(48);
  Buffer.concat([encodeVarint(0), encodeVarint(0), encodeVarint(indexOffset), encodeVarint(index.length)]).copy(footer, 0);
  Buffer.from([0x57, 0xfb, 0x80, 0x8b, 0x24, 0x75, 0x47, 0xdb]).copy(footer, 40);
  fs.writeFileSync(file, Buffer.concat([dataBlock, indexBlock, footer]));
}
const dom = (type, text) => Buffer.concat([Buffer.from([type]), Buffer.from(text, type === 0 ? 'utf16le' : 'latin1')]);
function cookieDb(file, rows) {
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(file);
  db.exec('create table cookies (host_key text, name text, value text, encrypted_value blob, is_secure int, is_httponly int, is_persistent int)');
  const insert = db.prepare('insert into cookies values (?, ?, ?, ?, ?, ?, ?)');
  for (const row of rows) insert.run(...row);
  db.close();
}

describe('Data at rest', () => {
  describe('LevelDB', () => {
    it('decodes varints and Snappy blocks, copies included', () => {
      varint(Buffer.from([0xac, 0x02]), 0).should.deep.equal([300, 2]);
      snappyDecompress(snappyLiteral(Buffer.from('hello'))).toString().should.equal('hello');
      // "abcd" then a copy of 4 bytes at offset 4 (kind 1): "abcdabcd"
      snappyDecompress(Buffer.from([8, 0x0c, 0x61, 0x62, 0x63, 0x64, 0x01, 0x04])).toString().should.equal('abcdabcd');
      (() => snappyDecompress(Buffer.from([4, 0x01, 0x09]))).should.throw();
    });

    it('reads write-ahead logs and tables, skipping deletions', () => {
      const dir = tmp('eng-ldb-');
      writeLog(path.join(dir, '000003.log'), [[Buffer.from('VERSION'), Buffer.from('1')]]);
      writeTable(path.join(dir, '000005.ldb'), [[Buffer.from('a'), Buffer.from('from-table')], [Buffer.from('b'), Buffer.from(''), 0]]);
      [...logKeyValues(fs.readFileSync(path.join(dir, '000003.log')))].map(([k, v]) => `${k}=${v}`).should.deep.equal(['VERSION=1']);
      [...tableKeyValues(fs.readFileSync(path.join(dir, '000005.ldb')))].map(([k, v]) => `${k}=${v}`).should.deep.equal(['a=from-table']);
      const store = readStore(dir);
      store.get('VERSION').value.toString().should.equal('1');
      store.get('a').value.toString().should.equal('from-table');
      readStore(path.join(dir, 'missing')).size.should.equal(0);
      [...tableKeyValues(Buffer.from('not a table'))].length.should.equal(0);
    });
  });

  describe('profile', () => {
    it('decodes Local Storage entries', () => {
      decodeDom(dom(0, 'héllo')).should.equal('héllo');
      decodeDom(dom(1, 'plain')).should.equal('plain');
      const dir = tmp('eng-ls-');
      writeLog(path.join(dir, '000003.log'), [[Buffer.concat([Buffer.from('_http://a.test\0'), dom(1, 'token')]), dom(1, 'SECRETtok')]]);
      localStorageEntries(readStore(dir)).should.deep.include(['http://a.test', 'token', 'SECRETtok']);
    });

    it('finds secrets in web storage and IndexedDB, redacted unless asked', () => {
      const profile = tmp('eng-profile-');
      const ls = path.join(profile, 'Local Storage', 'leveldb');
      fs.mkdirSync(ls, { recursive: true });
      writeLog(path.join(ls, '000003.log'), [[Buffer.concat([Buffer.from('_http://a.test\0'), dom(1, 'authToken')]), dom(1, 'eyJabc.def.ghi-secret')],
        [Buffer.concat([Buffer.from('_http://a.test\0'), dom(1, 'theme')]), dom(1, 'dark')]]);
      const idb = path.join(profile, 'IndexedDB', 'http_a.test_0.indexeddb.leveldb');
      fs.mkdirSync(idb, { recursive: true });
      writeLog(path.join(idb, '000003.log'), [[Buffer.from('k'), Buffer.from('\x00\x01"ghp_' + 'B'.repeat(36) + '"')]]);
      const found = reviewWebStorage(profile);
      found.map(f => `${f.store}:${f.key || ''}`).should.deep.equal(['Local Storage:authToken', 'IndexedDB:']);
      found[0].shown.should.include('redacted');
      reviewWebStorage(profile, { reveal: true })[0].shown.should.equal('eyJabc.def.ghi-secret');
    });

    it('reviews the cookie store: unencrypted values, the fixed-key fallback, missing flags', () => {
      const profile = tmp('eng-cookies-');
      cookieDb(path.join(profile, 'Cookies'), [
        ['a.test', 'sessionid', 'PLAINTEXTVALUE', Buffer.alloc(0), 0, 0, 1],
        ['a.test', 'enc', '', Buffer.concat([Buffer.from('v10'), Buffer.alloc(20)]), 1, 1, 1],
        ['a.test', 'theme', '', Buffer.concat([Buffer.from('v11'), Buffer.alloc(20)]), 1, 1, 0],
      ]);
      const cookies = reviewCookies(profile, { cookieEncryption: false });
      cookies.total.should.equal(3);
      cookies.plaintext.map(c => c.name).should.deep.equal(['sessionid']);
      cookies.plaintext[0].value.should.include('redacted');
      cookies.weakEncryption.should.equal(1);
      cookies.insecureFlags.map(c => c.name).should.deep.equal(['sessionid']);
      reviewCookies(profile, { reveal: true }).plaintext[0].value.should.equal('PLAINTEXTVALUE');
      reviewCookies(tmp('eng-nocookies-')).should.deep.equal({ present: false });
    });

    it('finds the profile folder by the app\'s name', () => {
      const home = tmp('eng-home-');
      fs.mkdirSync(path.join(home, '.config', 'My App'), { recursive: true });
      defaultProfileDirs(['My App', 'missing'], { platform: 'linux', env: {}, home }).should.deep.equal([path.join(home, '.config', 'My App')]);
      const appdata = tmp('eng-appdata-');
      fs.mkdirSync(path.join(appdata, 'My App'));
      defaultProfileDirs(['My App'], { platform: 'win32', env: { APPDATA: appdata }, home }).should.deep.equal([path.join(appdata, 'My App')]);
      appNames({ productName: 'My App', name: 'my-app', author: 'Acme Corp <dev@acme.test>' }).should.deep.equal(['My App', 'my-app', 'Acme Corp']);
    });
  });

  describe('saved-credential trace', () => {
    const CANARY = 'Zq7-test-Pw!2026';

    it('searches for the password in plaintext and in reversible encodings', () => {
      const labels = canaryForms(CANARY).map(([label]) => label);
      labels.should.include.members(['plaintext (UTF-8)', 'plaintext (UTF-16)', 'base64 of UTF-8', 'hex', 'hex of UTF-16', 'URL-encoded']);
      canaryForms('??>>??>>??').map(([label]) => label).should.include('base64url of UTF-8');
      // base64 at any offset inside a larger encoded value
      const forms = canaryForms(CANARY).filter(([label]) => label === 'base64 of UTF-8').map(([, b]) => b.toString());
      for (const prefix of ['', 'x', 'xy']) {
        const encoded = Buffer.from(prefix + CANARY + 'tail').toString('base64');
        forms.some(f => encoded.includes(f)).should.equal(true, `offset ${prefix.length}`);
      }
    });

    it('finds it in files, decoded LevelDB stores and the registry, and shows what changed', () => {
      const root = tmp('eng-canary-');
      fs.writeFileSync(path.join(root, 'plain.txt'), `user=alice\npassword=${CANARY}\n`);
      fs.writeFileSync(path.join(root, 'wide.dat'), Buffer.from(`xx${CANARY}yy`, 'utf16le'));
      fs.writeFileSync(path.join(root, 'b64.json'), JSON.stringify({ saved: Buffer.from('prefix:' + CANARY).toString('base64') }));
      fs.writeFileSync(path.join(root, 'hex.cfg'), Buffer.from(CANARY).toString('hex'));
      fs.writeFileSync(path.join(root, 'protected.json'), JSON.stringify({ blob: 'AQAAANCMnd8BFdERjHoAwE/Cl+sAAAA' }));
      const ldb = path.join(root, 'Local Storage', 'leveldb');
      fs.mkdirSync(ldb, { recursive: true });
      fs.writeFileSync(path.join(ldb, 'CURRENT'), 'MANIFEST-000001\n');
      // the table is Snappy-compressed: the password is only whole once decoded (its first half repeats the key's tail)
      writeTable(path.join(ldb, '000005.ldb'), [[Buffer.from('_app://\0\x01pw-Zq7-test'), Buffer.from('\x01' + CANARY)]]);
      fs.readFileSync(path.join(ldb, '000005.ldb')).includes(CANARY).should.equal(false);
      const reg = (command, args) => command === 'reg' && args[1] === 'HKCU\\Software\\MyApp' ? { status: 0, stdout: `    Password    REG_SZ    ${CANARY}\n` } : { status: 1 };
      const result = scanForCanaries([root], [CANARY], { registryNames: ['MyApp'], platform: 'win32', run: reg });
      const where = (file) => result.hits.filter(h => h.location.includes(file)).map(h => h.encoding);
      where('plain.txt').should.include('plaintext (UTF-8)');
      where('wide.dat').should.include('plaintext (UTF-16)');
      where('b64.json').should.include('base64 of UTF-8');
      where('hex.cfg').should.include('hex');
      result.hits.some(h => h.store === 'LevelDB').should.equal(true);
      result.hits.some(h => h.store === 'registry' && h.location === 'HKCU\\Software\\MyApp').should.equal(true);
      result.markers.some(m => m.path.endsWith('protected.json') && m.markers.includes('DPAPI blob')).should.equal(true);
      result.leveldbStores.should.equal(1);
    });

    it('lists folders, snapshots them, and reads Credential Manager names only on Windows', () => {
      const home = tmp('eng-roots-');
      fs.mkdirSync(path.join(home, '.config', 'MyApp', 'nested'), { recursive: true });
      fs.mkdirSync(path.join(home, '.myapp'));
      const roots = searchRoots(['MyApp'], { platform: 'linux', env: {}, home, extra: [path.join(home, '.config', 'MyApp', 'nested')] });
      // .MyApp and .myapp are one folder where names are case-insensitive (Windows, macOS): searched once
      const fold = (list) => process.platform === 'win32' || process.platform === 'darwin' ? list.map(p => p.toLowerCase()) : list;
      fold(roots).should.deep.equal(fold([fs.realpathSync(path.join(home, '.config', 'MyApp')), fs.realpathSync(path.join(home, '.myapp'))]));
      const before = snapshot(roots);
      fs.writeFileSync(path.join(roots[0], 'new.json'), '{}');
      changedFiles(before, snapshot(roots)).map(d => [path.basename(d.path), d.change]).should.deep.equal([['new.json', 'created']]);
      credentialTargets({ platform: 'linux' }).should.deep.equal([]);
      credentialTargets({ platform: 'win32', run: () => ({ status: 0, stdout: 'Currently stored credentials:\n\n    Target: LegacyGeneric:target=MyApp/alice\n    Type: Generic\n' }) })
        .should.deep.equal(['LegacyGeneric:target=MyApp/alice']);
      registryText(['MyApp'], { platform: 'linux' }).should.deep.equal([]);
    });

    it('reports where it was found, or where the app wrote instead', () => {
      const root = tmp('eng-trace-');
      const names = ['TraceApp'];
      const baseline = credentialBaseline({ names, searchDirs: [root] });
      fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify({ pw: Buffer.from(CANARY).toString('base64') }));
      let result = reviewDataAtRest({ names, canaries: [CANARY], searchDirs: [root], baseline });
      const found = result.issues.find(i => i.id === 'STORAGE_CREDENTIAL_AT_REST');
      found.severity.name.should.equal('HIGH');
      found.description.should.include('encoded but not encrypted');
      found.description.should.not.include(CANARY);
      found.sample.should.include('[canary]');
      result.summary.credentialTrace.locations.should.have.length(1);
      // not found: the trace says what the session wrote instead
      const other = tmp('eng-trace2-');
      const before = credentialBaseline({ names: ['Other'], searchDirs: [other] });
      fs.writeFileSync(path.join(other, 'vault.json'), JSON.stringify({ secret: 'djEwAAAABBBBCCCC' }).replace(':"', ':"'));
      fs.writeFileSync(path.join(other, 'vault.json'), '{"secret":"djEwAAAABBBBCCCC"}');
      result = reviewDataAtRest({ names: ['Other'], canaries: [CANARY], searchDirs: [other], baseline: before });
      const trace = result.issues.find(i => i.id === 'STORAGE_CREDENTIAL_TRACE');
      trace.severity.name.should.equal('INFORMATIONAL');
      trace.description.should.include('safeStorage-encrypted');
      trace.description.should.include('1 file(s) were created or changed');
    });
  });

  it('adds the profile review to a scan (--user-data), without code to scan', async () => {
    const profile = tmp('eng-scan-profile-');
    const ls = path.join(profile, 'Local Storage', 'leveldb');
    fs.mkdirSync(ls, { recursive: true });
    writeLog(path.join(ls, '000003.log'), [[Buffer.concat([Buffer.from('_http://a.test\0'), dom(1, 'refresh_token')]), dom(1, 'Qx7Lm2Vt9Rk4Zp8Wn3Yb6Hs')]]);
    cookieDb(path.join(profile, 'Cookies'), [['a.test', 'remember', 'PLAINVAL123', Buffer.alloc(0), 0, 0, 1]]);
    const input = tmp('eng-scan-code-');
    const result = await run({ input, userData: profile, offline: true });
    result.issues.map(i => i.id).should.include.members(['STORAGE_SECRET_AT_REST', 'STORAGE_COOKIE_AT_REST']);
    result.atRest.profile.path.should.equal(profile);
    const missing = await run({ input, userData: path.join(profile, 'nope'), offline: true });
    missing.errors.some(e => /not a readable folder/.test(e.message)).should.equal(true);
  });
});
