import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as asar from '@electron/asar';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { parsePe, findResources } from '../src/binary/pe.js';
import { machoInfo } from '../src/binary/macho.js';
import { elfInfo } from '../src/binary/elf.js';
import { signerOf, verifySignature } from '../src/binary/signature.js';
import { analyzeBinary, asarHeaderHash, embeddedIntegrity, mitigations } from '../src/binary/index.js';
import { buildPe, versionInfo, fuseWire } from './binary/fakepe.js';

chaiShould();
await _i18n();

const SIGNATURE = fs.readFileSync(path.join(import.meta.dirname, 'binary', 'signature.p7b'));
const tmp = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

// a packaged Windows app: MyApp/MyApp.exe (a fake PE with the fuse wire) and MyApp/resources/app.asar
async function packagedApp({ fuses = '10111000', integrity = 'match', dllCharacteristics, signature } = {}) {
  const root = tmp('eng-binary-app-');
  const source = path.join(root, 'src');
  fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, 'package.json'), '{"name":"my-app","main":"main.js"}');
  fs.writeFileSync(path.join(source, 'main.js'), 'console.log(1);\n');
  const resources = path.join(root, 'MyApp', 'resources');
  fs.mkdirSync(resources, { recursive: true });
  const archive = path.join(resources, 'app.asar');
  await asar.createPackage(source, archive);
  const hash = integrity === 'match' ? asarHeaderHash(archive) : 'ab'.repeat(32);
  const res = [[16, 1, versionInfo({ ProductName: 'My App', CompanyName: 'Fixture Corp' })]];
  if (integrity) res.push(['INTEGRITY', 'ELECTRONASAR', Buffer.from(JSON.stringify([{ file: 'resources\\app.asar', alg: 'SHA256', value: hash }]))]);
  const exe = path.join(root, 'MyApp', 'MyApp.exe');
  fs.writeFileSync(exe, buildPe({ payload: Buffer.concat([Buffer.alloc(64), fuseWire(fuses), Buffer.alloc(64)]), resources: res, dllCharacteristics, signature }));
  return { root, archive, exe };
}

describe('Packaged binary', () => {
  it('reads a PE: mitigations, version information and the embedded asar integrity hash', () => {
    const pe = buildPe({ resources: [[16, 1, versionInfo({ ProductName: 'My App' })], ['INTEGRITY', 'ELECTRONASAR', Buffer.from('[]')]], dllCharacteristics: 0x8160 | 0x4000 });
    const info = parsePe(pe);
    info.should.include({ machine: 'x64', is64: true, aslr: true, dep: true, cfg: true, highEntropyVa: true, signed: false });
    info.versionInfo.ProductName.should.equal('My App');
    findResources(info, 'integrity', 'electronasar').length.should.equal(1);
    (() => parsePe(Buffer.from('not a PE file at all, not even close......................................'))).should.throw();
  });

  it('names the signer of an Authenticode signature, and lets Windows verify it', () => {
    signerOf(SIGNATURE).should.include('Fixture Corp Code Signing');
    const dir = tmp('eng-signed-');
    const signed = path.join(dir, 'signed.exe');
    fs.writeFileSync(signed, buildPe({ signature: SIGNATURE }));
    const unsigned = path.join(dir, 'unsigned.exe');
    fs.writeFileSync(unsigned, buildPe());
    verifySignature(unsigned).should.include({ status: 'NotSigned', format: 'pe' });
    const elsewhere = verifySignature(signed, { platform: 'linux' });
    elsewhere.should.include({ status: 'Present', verifiedBy: 'none' });
    elsewhere.signer.should.include('Fixture Corp Code Signing');
    const powershell = (status) => () => ({ status: 0, stdout: JSON.stringify({ Status: status, Message: status === 'Valid' ? 'Signature verified.' : 'The contents of the file may have been altered', Signer: 'CN=Fixture Corp' }) });
    verifySignature(signed, { platform: 'win32', run: powershell('Valid') }).should.include({ status: 'Valid', verifiedBy: 'windows', signer: 'CN=Fixture Corp' });
    verifySignature(signed, { platform: 'win32', run: powershell('HashMismatch') }).status.should.equal('HashMismatch');
    // the path never becomes part of the command: a name with typographic quotes can't end the string and add commands
    let call;
    verifySignature(signed, { platform: 'win32', run: (cmd, args, options) => { call = { args, options }; return powershell('Valid')(); } });
    call.args.join(' ').should.not.include(path.basename(signed));
    call.options.env.ELECTRONEGATIVITY_SIGNED_FILE.should.equal(path.resolve(signed));
  });

  it('reads Mach-O and ELF headers', () => {
    const macho = Buffer.alloc(64);
    macho.writeUInt32LE(0xfeedfacf, 0);
    macho.writeUInt32LE(1, 16); // one load command
    macho.writeUInt32LE(0x200000, 24); // MH_PIE
    macho.writeUInt32LE(0x1d, 32); // LC_CODE_SIGNATURE
    macho.writeUInt32LE(16, 36);
    machoInfo(macho).should.deep.equal({ codeSignature: true, pie: true, is64: true });
    const elf = Buffer.alloc(64 + 56);
    elf.writeUInt32BE(0x7f454c46, 0);
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf.writeUInt16LE(2, 16); // ET_EXEC: not position-independent
    elf.writeBigUInt64LE(64n, 32);
    elf.writeUInt16LE(56, 54);
    elf.writeUInt16LE(1, 56);
    elf.writeUInt32LE(0x6474e551, 64); // PT_GNU_STACK
    elf.writeUInt32LE(7, 68); // RWX
    elfInfo(elf).should.deep.equal({ pie: false, nxStack: false, relro: false, is64: true });
    const dir = tmp('eng-elf-');
    fs.writeFileSync(path.join(dir, 'app'), elf);
    mitigations(path.join(dir, 'app')).should.deep.equal({ format: 'ELF', missing: ['PIE', 'non-executable stack', 'RELRO'] });
  });

  it('confirms app.asar matches the hash embedded in the executable', async () => {
    const { archive, exe } = await packagedApp({ fuses: '10111000' });
    embeddedIntegrity(exe).should.include({ alg: 'SHA256', value: asarHeaderHash(archive) });
    const { issues, summary } = analyzeBinary(archive);
    summary.integrity.should.equal('verified');
    const integrity = issues.find(i => i.id === 'ASAR_INTEGRITY');
    integrity.severity.name.should.equal('INFORMATIONAL');
  });

  it('reports an app.asar changed after the build, and an integrity fuse without a hash', async () => {
    let app = await packagedApp({ fuses: '10100000', integrity: 'other' });
    let integrity = analyzeBinary(app.archive).issues.find(i => i.id === 'ASAR_INTEGRITY');
    integrity.severity.name.should.equal('HIGH');
    integrity.description.should.include('fuse is off, so the modified code runs');
    app = await packagedApp({ fuses: '10111000', integrity: null });
    integrity = analyzeBinary(app.archive).issues.find(i => i.id === 'ASAR_INTEGRITY');
    integrity.severity.name.should.equal('MEDIUM');
    integrity.description.should.include('no integrity hash');
  });

  it('reports an unsigned executable and missing mitigations in a scan', async () => {
    const { archive } = await packagedApp({ dllCharacteristics: 0 });
    const result = await run({ input: archive, offline: true });
    const signing = result.issues.find(i => i.id === 'CODE_SIGNING');
    signing.severity.name.should.equal('MEDIUM');
    signing.description.should.include('not code-signed');
    result.issues.find(i => i.id === 'BINARY_HARDENING').properties.missing.should.deep.equal(['ASLR', 'DEP', 'CFG', 'high-entropy ASLR']);
    result.binary.integrity.should.equal('verified');
    const without = await run({ input: archive, offline: true, excludeFromScan: ['PackagedBinaryCheck'] });
    without.issues.some(i => ['CODE_SIGNING', 'BINARY_HARDENING', 'ASAR_INTEGRITY'].includes(i.id)).should.equal(false);
  });

  it('reports a signed executable as signed, without claiming it was verified', async () => {
    const { archive } = await packagedApp({ signature: SIGNATURE });
    const signing = analyzeBinary(archive, { platform: 'linux' }).issues.find(i => i.id === 'CODE_SIGNING');
    signing.severity.name.should.equal('INFORMATIONAL');
    signing.description.should.include('not verified on this host');
  });
});
