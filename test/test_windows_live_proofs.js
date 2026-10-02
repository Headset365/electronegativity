import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readWatchLog, analyzeWatchLog } from '../src/watch/analyze.js';
import { watchApp } from '../src/watch/launch.js';
import { proveRunAsNode } from '../src/watch/fuses.js';

const require = createRequire(import.meta.url);
const { readZone, inventory, observePorts } = require('../src/watch/windows.cjs');
let electron;
try { electron = require('electron'); } catch { /* installed by Windows runtime CI */ }
const available = process.platform === 'win32' && !!electron;
if (process.env.ELECTRONEGATIVITY_REQUIRE_WINDOWS_PROOFS === '1' && !available) throw Error('Windows proof tests require Windows and Electron; skipping is forbidden');
const live = available ? it : it.skip;

describe('Native Windows proof regression fixtures', function () {
  this.timeout(120000);
  for (const hardened of [false, true]) live(`${hardened ? 'hardened' : 'permissive'} packaged app: handler/TLS/IPC/fuse proofs and cleanup`, async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-windows-caf\u00e9-\u6d4b\u8bd5-'));
    const fixture = path.join(import.meta.dirname, 'apps', 'proof-app');
    const log = path.join(root, 'session.jsonl');
    try {
      const install = path.join(root, 'installed');
      fs.cpSync(path.dirname(electron), install, { recursive: true });
      const executable = path.join(install, path.basename(electron));
      fs.cpSync(fixture, path.join(install, 'resources', 'app'), { recursive: true });
      const binary = fs.readFileSync(executable);
      const sentinel = binary.indexOf(Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'));
      assert.ok(sentinel > 0, 'fixture binary must contain a fuse wire');
      binary[sentinel + 32 + 2] = hardened ? 48 : 49; // RunAsNode
      binary[sentinel + 32 + 2 + 3] = 49; // CLI inspector, required to install the observer
      fs.writeFileSync(executable, binary);
      const proofFile = path.join(root, 'proof.json');
      fs.writeFileSync(proofFile, JSON.stringify({ enabled: true, profile: { origins: ['https://eng-proof.invalid'] },
        ipc: { handlers: [{ channel: 'read-canary', reviewed: true, contract: 'file-read', args: ['$CANARY_PATH'] }] } }));
      const previous = { hardened: process.env.ENG_PROOF_HARDENED, data: process.env.ENG_PROOF_USER_DATA };
      process.env.ENG_PROOF_HARDENED = hardened ? '1' : '0'; process.env.ENG_PROOF_USER_DATA = path.join(root, 'profile');
      try { await watchApp(executable, { log, proofConfig: proofFile, prove: true, capture: false, traffic: false, stdio: 'ignore' }); }
      finally {
        for (const [name, value] of [['ENG_PROOF_HARDENED', previous.hardened], ['ENG_PROOF_USER_DATA', previous.data]]) {
          if (value === undefined) delete process.env[name]; else process.env[name] = value;
        }
      }
      const rows = readWatchLog(log), tests = rows.filter(r => r.kind === 'proof');
      const outcome = test => tests.find(r => r.test === test)?.outcome;
      assert.equal(outcome('navigation'), hardened ? 'blocked' : 'allowed');
      assert.equal(outcome('window-open'), hardened ? 'blocked' : 'allowed');
      assert.equal(outcome('permission-request'), hardened ? 'blocked' : 'allowed');
      assert.equal(outcome('permission-check'), hardened ? 'blocked' : 'allowed');
      assert.equal(outcome('certificate'), hardened ? 'blocked' : 'accepted');
      assert.equal(outcome('run-as-node'), hardened ? 'skipped' : 'enabled');
      assert.equal(outcome('node-inspector'), 'connected');
      assert.equal(outcome('ipc'), hardened ? 'rejected' : 'canary-read');
      assert.ok(rows.some(r => r.kind === 'windows-acl' && r.status === 'observed'));
      assert.ok(rows.some(r => r.kind === 'windows-acl' && r.paths?.some(p => p.path === executable)), 'ACL paths must preserve Unicode');
      const result = analyzeWatchLog(rows);
      assert.equal(result.summary.windows, 1, 'tool-created windows must not count as app windows');
      assert.equal(result.issues.some(i => i.id === 'RUNTIME_CERTIFICATE_PROOF'), !hardened);
      assert.equal(JSON.stringify(result).includes('engProof.invoke'), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
  live('real NTFS zone streams, app protocol registration and process-owned listening ports', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-windows-inventory-'));
    const { createServer } = await import('node:net');
    const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const scheme = `eng-proof-${Date.now()}`;
    const regKey = `HKCU\\Software\\Classes\\${scheme}`;
    try {
      const file = path.join(root, 'download.docx'); fs.writeFileSync(file, 'tool-owned'); fs.writeFileSync(`${file}:Zone.Identifier`, '[ZoneTransfer]\r\nZoneId=3\r\n');
      assert.equal(readZone(file).zone, 3);
      fs.unlinkSync(`${file}:Zone.Identifier`); assert.equal(readZone(file).status, 'absent');
      const reg = args => { const r = spawnSync('reg.exe', args, { encoding: 'utf8', windowsHide: true }); assert.equal(r.status, 0, r.stderr); };
      reg(['add', regKey, '/v', 'URL Protocol', '/d', '', '/f']);
      reg(['add', `${regKey}\\shell\\open\\command`, '/ve', '/d', `"${process.execPath}" "%1"`, '/f']);
      const rows = []; await inventory(process.execPath, (kind, data) => rows.push({ kind, ...data }));
      const protocols = rows.find(r => r.kind === 'windows-protocol');
      assert.ok(protocols.protocols.some(p => p.scheme === scheme && p.argumentQuoted));
      const portRows = []; const stop = observePorts(process.pid, (kind, data) => portRows.push({ kind, ...data }), { interval: 500 });
      try {
        const deadline = Date.now() + 20000;
        while (!portRows.some(r => r.port === server.address().port) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 250));
        assert.ok(portRows.some(r => r.port === server.address().port && r.pid === process.pid));
      } finally { stop(); }
      const proof = await proveRunAsNode(electron); assert.equal(proof.outcome, 'enabled');
    } finally {
      spawnSync('reg.exe', ['delete', regKey, '/f'], { windowsHide: true });
      await new Promise(resolve => server.close(resolve)); fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
