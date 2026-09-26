import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { should as chaiShould } from 'chai';
import run from '../src/runner.js';

chaiShould();

const NETWORK_CHECKS = ['availablesecurityfixesglobalcheck', 'unsupportedversionglobalcheck', 'dependencyvulnerabilitiesglobalcheck'];
const CLI = path.resolve('src/index.js');

function makeApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-baseline-'));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

const scan = (dir, extra = {}) => run({ input: dir, offline: true, excludeFromScan: NETWORK_CHECKS, ...extra });

describe('Baselines and CI gating', () => {
  let dir;
  beforeEach(() => {
    dir = makeApp({
      'package.json': JSON.stringify({ name: 'app', devDependencies: { electron: '38.2.0' } }),
      'main.js': `ipcMain.handle('a', () => secrets());\nwin.webContents.openDevTools();\n`
    });
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('suppresses accepted findings and keeps recorded reasons', async () => {
    const baseline = path.join(dir, 'baseline.json');
    const first = await scan(dir, { writeBaseline: baseline });
    const written = JSON.parse(fs.readFileSync(baseline, 'utf8'));
    written.findings.length.should.equal(first.issues.length);

    written.findings[0].reason = 'reviewed: renderer is trusted';
    fs.writeFileSync(baseline, JSON.stringify(written));

    const second = await scan(dir, { baseline });
    second.issues.should.have.length(0);
    second.suppressed.length.should.equal(first.issues.length);

    // rewriting keeps the reason
    await scan(dir, { baseline, writeBaseline: baseline });
    JSON.parse(fs.readFileSync(baseline, 'utf8')).findings.some(f => f.reason === 'reviewed: renderer is trusted').should.equal(true);
  });

  it('survives unrelated edits and reports only new findings', async () => {
    const baseline = path.join(dir, 'baseline.json');
    await scan(dir, { writeBaseline: baseline });
    // lines shift and a new problem appears
    fs.writeFileSync(path.join(dir, 'main.js'), `// header\n\nipcMain.handle('a', () => secrets());\nwin.webContents.openDevTools();\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n`);
    const result = await scan(dir, { baseline });
    result.issues.map(i => i.id).should.deep.equal(['NODE_TLS_REJECT_UNAUTHORIZED_JS_CHECK']);
  });

  it('reports baseline entries that no longer match', async () => {
    const baseline = path.join(dir, 'baseline.json');
    await scan(dir, { writeBaseline: baseline });
    fs.writeFileSync(path.join(dir, 'main.js'), `ipcMain.handle('a', () => secrets());\n`);
    const result = await scan(dir, { baseline });
    result.staleBaselineEntries.map(e => e.id).should.include('DEVTOOLS_JS_CHECK');
  });

  it('--fail-on sets the exit code', () => {
    const out = path.join(dir, 'out.json');
    const args = (input) => [CLI, '-i', input, '--offline', '-x', NETWORK_CHECKS.join(','), '-o', out];
    // the sample app has no navigation limits (HIGH)
    spawnSync(process.execPath, [...args(dir), '--fail-on', 'high']).status.should.equal(1);
    spawnSync(process.execPath, [...args(dir), '--fail-on', 'bogus']).status.should.equal(2);
    // the hardened app only has LOW review notes
    spawnSync(process.execPath, [...args('test/apps/hardened-app'), '--fail-on', 'medium']).status.should.equal(0);
    spawnSync(process.execPath, [...args('test/apps/hardened-app'), '--fail-on', 'low']).status.should.equal(1);
  });

  it('--fail-on passes once the findings are baselined', () => {
    const baseline = path.join(dir, 'baseline.json');
    const args = [CLI, '-i', dir, '--offline', '-x', NETWORK_CHECKS.join(','), '-o', path.join(dir, 'out.json')];
    execFileSync(process.execPath, [...args, '--write-baseline', baseline]);
    spawnSync(process.execPath, [...args, '--baseline', baseline, '--fail-on', 'low']).status.should.equal(0);
  });
});
