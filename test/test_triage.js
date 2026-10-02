import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { loadSuppressions, applySuppressions } from '../src/util/triage.js';
import { applyBaseline, writeBaseline, loadBaseline, fingerprints, expiryDate } from '../src/util/baseline.js';
import { severity, confidence } from '../src/finder/attributes.js';

chaiShould();
await _i18n();

const issue = (id, file, description = `${id} here`) => ({ id, file, sample: 'x()', description, location: { line: 1, column: 0 }, severity: severity.HIGH, confidence: confidence.CERTAIN });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'eng-triage-'));
const write = (dir, name, value) => {
  fs.writeFileSync(path.join(dir, name), JSON.stringify(value));
  return path.join(dir, name);
};

describe('Triage', () => {
  it('accepts findings by check family, file glob and text, with a reason, owner and expiry', () => {
    const dir = tmp();
    const file = write(dir, 'suppress.json', { suppressions: [
      { check: 'TRAFFIC_*', file: '*.internal.test*', reason: 'internal hosts', owner: 'platform' },
      { check: 'PACKAGED_FUSES', match: 'v8snapshot', reason: 'n/a' },
      { check: 'XSS_SINK_JS_CHECK', reason: 'old', expires: '2001-01-01' },
      { reason: 'no selector' },
      { file: 'nothing/*', reason: 'stale' },
    ] });
    const { entries, notes } = loadSuppressions(file, '2026-09-28');
    entries.length.should.equal(3);
    notes.should.have.length(2);
    notes[0].should.include('expired on 2001-01-01');
    notes[1].should.include('suppression #4 ignored');
    const issues = [issue('TRAFFIC_CLEARTEXT_HTTP', 'http://api.internal.test'), issue('TRAFFIC_CLEARTEXT_HTTP', 'http://api.example.test'),
      issue('PACKAGED_FUSES', 'app.exe', 'LoadBrowserProcessSpecificV8Snapshot is off'), issue('XSS_SINK_JS_CHECK', 'a.js')];
    const { kept, suppressed, notes: unmatched } = applySuppressions(issues, entries, dir);
    kept.map(i => `${i.id} ${i.file}`).should.deep.equal(['TRAFFIC_CLEARTEXT_HTTP http://api.example.test', 'XSS_SINK_JS_CHECK a.js']);
    suppressed.map(i => i.suppression.reason).should.deep.equal(['internal hosts', 'n/a']);
    suppressed[0].suppression.owner.should.equal('platform');
    unmatched.should.deep.equal(['suppression #5 matched nothing: nothing/* (stale)']);
  });

  it('lets baseline entries expire, and keeps owners and dates when the baseline is rewritten', () => {
    const dir = tmp();
    const issues = [issue('OPEN_EXTERNAL_JS_CHECK', 'main.js'), issue('DEVTOOLS_JS_CHECK', 'main.js')];
    const file = path.join(dir, 'baseline.json');
    writeBaseline(file, issues, dir);
    const baseline = loadBaseline(file);
    baseline.findings[0].reason = 'accepted';
    baseline.findings[0].owner = 'appsec';
    baseline.findings[0].expires = '2001-01-01';
    baseline.findings[1].expires = '2999-01-01';
    fs.writeFileSync(file, JSON.stringify(baseline));
    const { kept, suppressed, expired, stale } = applyBaseline(issues, loadBaseline(file), dir, '2026-09-28');
    kept.map(i => i.id).should.deep.equal(['OPEN_EXTERNAL_JS_CHECK']);
    suppressed.map(i => i.id).should.deep.equal(['DEVTOOLS_JS_CHECK']);
    expired.map(e => e.id).should.deep.equal(['OPEN_EXTERNAL_JS_CHECK']);
    stale.should.deep.equal([]);
    writeBaseline(file, issues, dir, loadBaseline(file));
    loadBaseline(file).findings[0].should.include({ owner: 'appsec', expires: '2001-01-01', reason: 'accepted' });
  });

  it('reads expiry dates as dates: unpadded ones expire, unreadable ones are not applied', () => {
    expiryDate('2026-9-1').should.equal('2026-09-01');
    (expiryDate('31/12/2026') === undefined).should.equal(true);
    (expiryDate('2026-02-30') === undefined).should.equal(true);
    const dir = tmp();
    const file = write(dir, 'suppress.json', { suppressions: [
      { check: 'A', reason: 'unpadded, past', expires: '2026-9-1' },
      { check: 'B', reason: 'unreadable', expires: '31/12/2099' },
      { check: 'C', reason: 'fine', expires: '2099-1-1' },
    ] });
    const { entries, notes } = loadSuppressions(file, '2026-09-28');
    entries.map(e => e.check).should.deep.equal(['C']);
    notes[0].should.include('expired on 2026-9-1');
    notes[1].should.include('not a date in the form YYYY-MM-DD');
    const issues = [issue('OPEN_EXTERNAL_JS_CHECK', 'main.js')];
    const baseline = path.join(dir, 'baseline.json');
    writeBaseline(baseline, issues, dir);
    const data = loadBaseline(baseline);
    data.findings[0].expires = 'next year';
    const { kept, expired } = applyBaseline(issues, data, dir, '2026-09-28');
    kept.length.should.equal(1);
    expired[0].invalidExpiry.should.equal(true);
  });

  it('keeps the fingerprint of a finding without code when only upstream counts change, and still matches old ones', () => {
    const finding = (description) => ({ id: 'CHROMIUM_ADVISORIES', file: 'Chromium 87', sample: '', description, location: { line: 0 } });
    const [before] = fingerprints([finding('misses 4157 upstream security fixes (376 critical, 1974 high), 51 exploited (CISA KEV: CVE-1, CVE-2)')], '/x');
    const [after] = fingerprints([finding('misses 4201 upstream security fixes (380 critical, 1990 high), 52 exploited (CISA KEV: CVE-1, CVE-2, CVE-3)')], '/x');
    after.fingerprint.should.equal(before.fingerprint);
    before.legacy.should.not.equal(before.fingerprint);
    // a baseline written by an earlier version (the legacy fingerprint) still accepts the finding
    const issues = [finding('same text')];
    const [print] = fingerprints(issues, '/x');
    const { suppressed } = applyBaseline(issues, { findings: [{ fingerprint: print.legacy, reason: 'ok' }] }, '/x');
    suppressed.length.should.equal(1);
  });

  it('compares a scan with the previous one, and marks accepted risks in every output', async () => {
    const dir = tmp();
    const app = path.join(dir, 'app');
    fs.mkdirSync(app);
    fs.writeFileSync(path.join(app, 'main.js'), "const { BrowserWindow, shell } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, webSecurity: false } });\nwin.webContents.openDevTools();\n");
    const first = path.join(dir, 'first.json');
    await run({ input: app, offline: true, output: first });
    const before = JSON.parse(fs.readFileSync(first, 'utf8'));
    before.issues.every(i => /^[0-9a-f]{24}$/.test(i.fingerprint)).should.equal(true);
    // the next build: web security fixed, a new openExternal, DevTools accepted
    fs.writeFileSync(path.join(app, 'main.js'), "const { BrowserWindow, shell } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\nwin.webContents.openDevTools();\nipcMain.on('open', (e, url) => shell.openExternal(url));\n");
    const suppress = write(dir, 'suppress.json', { suppressions: [{ check: 'DEVTOOLS_JS_CHECK', reason: 'dev only', owner: 'team', expires: '2999-01-01' }] });
    const out = (name) => path.join(dir, name);
    const result = await run({ input: app, offline: true, suppress, compare: first, output: [out('second.json'), out('second.sarif'), out('second.html')].join(',') });
    result.suppressed.map(i => i.id).should.deep.equal(['DEVTOOLS_JS_CHECK']);
    result.comparison.fixed.map(f => f.id).should.include('WEB_SECURITY_JS_CHECK');
    result.comparison.fixed.map(f => f.id).should.not.include('DEVTOOLS_JS_CHECK'); // accepted, not fixed
    result.reported.filter(i => i.comparison === 'new').map(i => i.id).should.include('OPEN_EXTERNAL_JS_CHECK');
    const json = JSON.parse(fs.readFileSync(out('second.json'), 'utf8'));
    json.suppressed[0].should.include({ id: 'DEVTOOLS_JS_CHECK', reason: 'dev only', owner: 'team', source: 'suppressions' });
    // in full, so the client findings can be written again from the JSON report (--rerender)
    json.suppressed[0].should.include.keys('sample', 'confidence', 'line', 'column', 'reference', 'suppression');
    json.suppressed[0].suppression.should.include({ reason: 'dev only', owner: 'team' });
    const sarif = JSON.parse(fs.readFileSync(out('second.sarif'), 'utf8')).runs[0].results;
    sarif.find(r => r.ruleId === 'DEVTOOLS_JS_CHECK').suppressions[0].justification.should.include('dev only');
    sarif.find(r => r.ruleId === 'OPEN_EXTERNAL_JS_CHECK').baselineState.should.equal('new');
    sarif.every(r => r.partialFingerprints['electronegativity/v1']).should.equal(true);
    const html = fs.readFileSync(out('second.html'), 'utf8');
    html.should.include('Accepted risks (1)');
    html.should.include('Since the previous scan');
    html.should.include('id="onlynew"');
  });
});
