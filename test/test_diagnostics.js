import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { Parser } from '../src/parser/index.js';
import { Finder } from '../src/finder/index.js';
import { sourceTypes } from '../src/parser/types.js';
import { sensitiveTerms, makeSanitizer } from '../src/util/diagnostics.js';

chaiShould();
await _i18n();

const project = (files) => {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eng-diag-')), 'acme-notes');
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
};

describe('Diagnostics', () => {
  describe('sanitizing', () => {
    it('replaces the app name in its variants, the home folder, extra terms, and pseudonymizes hosts', () => {
      const dir = project({ 'package.json': JSON.stringify({ name: '@acme/acme-notes', productName: 'Acme Notes', build: { appId: 'com.acmecorp.notes' } }) });
      const terms = sensitiveTerms(dir, ['Globex']);
      const sanitize = makeSanitizer(terms);
      const text = sanitize(`acme-notes AcmeNotes acme_notes Acme Notes acmecorp Globex ${os.homedir()}/work https://api.acmecorp.example/v1 electron preload.js`);
      text.should.not.match(/acme|globex/i);
      text.should.not.include(os.homedir());
      text.should.include('<home>/work');
      text.should.match(/https:\/\/host-[0-9a-f]{8}\/v1/);
      text.should.include('electron preload.js'); // generic words stay readable
    });

    it('keeps the same pseudonym for the same host and sanitizes object keys and nested values', () => {
      const sanitize = makeSanitizer(['acme']);
      const out = sanitize({ 'acme.js': ['https://a.example.com/x', 'https://a.example.com/y'], nested: { note: 'ACME failed' } });
      Object.keys(out).should.deep.equal(['<redacted>.js', 'nested']);
      out['<redacted>.js'][0].split('/')[2].should.equal(out['<redacted>.js'][1].split('/')[2]);
      out.nested.note.should.equal('<redacted> failed');
    });
  });

  describe('report', () => {
    it('describes the scan without naming the app, and without code or finding text', async () => {
      const dir = project({
        'package.json': JSON.stringify({ name: 'acme-notes', devDependencies: { electron: '38.0.0' } }),
        'src/main.js': `const w = new BrowserWindow({ webPreferences: { nodeIntegration: true } });\nconst secretToken = 'acme-internal';`,
        'src/broken.js': 'const = ;',
        'test/main.test.js': 'x();',
      });
      const output = path.join(os.tmpdir(), `eng-diag-${process.pid}.json`);
      await run({ input: dir, offline: true, diagnostics: output, redact: ['internal'] });
      const raw = fs.readFileSync(output, 'utf8');
      raw.should.not.match(/acme|internal|secretToken|nodeIntegration is enabled/i);
      const report = JSON.parse(raw);
      report.input.should.include({ type: 'directory', electronVersion: '38.0.0', electronVersionSource: 'detected' });
      report.input.skipped.nonAppFiles.should.equal(1);
      report.errors.map(e => e.file).should.include(path.join('src', 'broken.js'));
      report.findings.byCheck.NODE_INTEGRATION_JS_CHECK['HIGH/CERTAIN'].should.equal(1);
      report.checks.slowest.length.should.be.above(0);
      report.phasesMs.should.have.keys('load', 'checks', 'globalChecks');
    });
  });

  describe('check isolation', () => {
    it('a check that crashes is recorded, and the other checks still run on the file', async () => {
      const finder = new Finder(null, null);
      const checks = finder.checks_by_type.get(sourceTypes.JAVASCRIPT);
      const broken = checks.find(c => c.id === 'DEVTOOLS_JS_CHECK');
      broken.match = () => { throw new Error('boom'); };
      const parser = new Parser(false, true);
      const file = 'main.js';
      const [type, data, content] = parser.parse(file, 'win.webContents.openDevTools();\nconst w = new BrowserWindow({ webPreferences: { nodeIntegration: true } });');
      const issues = await finder.find(file, data, type, content, null, '38.0.0');
      issues.some(i => i.id === 'NODE_INTEGRATION_JS_CHECK').should.equal(true);
      finder.checkErrors.should.have.length(1); // recorded once per file, not once per node
      finder.checkErrors[0].message.should.match(/DEVTOOLS_JS_CHECK failed: boom/);
    });
  });
});
