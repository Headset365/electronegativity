import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { cached, enrichDependencies, chromiumAdvisories, chromeMatch, backportedCves, chromiumOf, KEV_URL } from '../src/intel/index.js';
import { cycloneDx } from '../src/report/cyclonedx.js';
import { renderDocx, groupFindings, appendixRows } from '../src/report/docx.js';
import { riskScore } from '../src/report/scores.js';
import { notesFor, applyFindingNotes } from '../src/report/notes.js';
import { zipEntries, zipRead } from '../src/unpack/zip.js';
import { severity, confidence } from '../src/finder/attributes.js';
import { cacheDir, writeCacheFile } from '../src/util/cache.js';

chaiShould();
await _i18n();

// every intel request answered from this table; the cache goes to a folder of its own
const responses = new Map();
const fakeFetch = async (url) => {
  const match = [...responses.entries()].find(([prefix]) => url.startsWith(prefix));
  if (!match) return { ok: false, status: 404 };
  const body = match[1];
  return { ok: true, status: 200, json: async () => body, text: async () => body };
};
const options = { fetchImpl: fakeFetch };

const issue = (id, sev, conf = confidence.CERTAIN, extra = {}) => ({ id, file: 'main.js', sample: 'code()', location: { line: 3, column: 0 }, description: `${id} found`,
  severity: severity[sev], confidence: conf, shortenedURL: 'https://example.test/doc', ...extra });

describe('Reports and vulnerability intelligence', () => {
  let previousCache;
  before(() => {
    previousCache = process.env.ELECTRONEGATIVITY_CACHE_DIR;
    process.env.ELECTRONEGATIVITY_CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-intel-cache-'));
  });
  after(() => {
    if (previousCache === undefined) delete process.env.ELECTRONEGATIVITY_CACHE_DIR;
    else process.env.ELECTRONEGATIVITY_CACHE_DIR = previousCache;
  });

  describe('intel', () => {
    it('caches lookups and falls back to the cached copy when a source fails', async () => {
      responses.set('https://intel.test/a', { value: 1 });
      (await cached('https://intel.test/a', options)).should.deep.equal({ value: 1 });
      responses.delete('https://intel.test/a');
      (await cached('https://intel.test/a', { ...options, ttl: 0 })).should.deep.equal({ value: 1 });
      (await cached('https://intel.test/missing', options) === undefined).should.equal(true);
    });

    it('marks advisories exploited in the wild (KEV), their EPSS score, and malicious versions', async () => {
      responses.set(KEV_URL, { vulnerabilities: [{ cveID: 'CVE-2020-11022', vulnerabilityName: 'jQuery XSS', dateAdded: '2025-01-23', knownRansomwareCampaignUse: 'Unknown' }] });
      responses.set('https://api.first.org/data/v1/epss', { data: [{ cve: 'CVE-2020-11022', epss: '0.25', percentile: '0.97' }] });
      const report = { offline: false, rows: [
        { name: 'jquery', version: '3.4.1', advisories: [{ id: 'GHSA-gxr4-xjj5-5px2', cves: ['CVE-2020-11022'] }] },
        { name: 'event-stream', version: '3.3.6', advisories: [] },
        { name: 'evil-pkg', version: '1.0.0', advisories: [{ id: 'MAL-2024-1', cves: [], summary: 'Malicious code in evil-pkg' }] },
      ] };
      const summary = await enrichDependencies(report, options);
      summary.should.deep.equal({ checked: true, kev: 1, malicious: 2 });
      report.rows[0].advisories[0].kev.should.include({ added: '2025-01-23' });
      report.rows[0].advisories[0].epss.should.deep.equal({ epss: 0.25, percentile: 0.97 });
      report.rows[1].malicious.source.should.equal('known list');
      report.rows[2].malicious.id.should.equal('MAL-2024-1');
    });

    it('matches Chrome CVEs to a Chromium build the way NVD models them', () => {
      const cve = (criteria) => ({ configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, ...criteria }] }] }] });
      chromeMatch(cve({ criteria: 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', versionEndExcluding: '120.0.6099.62' }), [108, 0, 5359, 215]).should.deep.equal([true, '120.0.6099.62']);
      chromeMatch(cve({ criteria: 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', versionEndExcluding: '100.0.0.0' }), [108, 0, 5359, 215])[0].should.equal(false);
      chromeMatch(cve({ criteria: 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*' }), [108])[0].should.equal(false); // unbounded
      chromeMatch(cve({ criteria: 'cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*', versionEndExcluding: '999' }), [108])[0].should.equal(false);
      backportedCves('<li>Security: backported fix for CVE-2023-4863 and CVE-2023-5217.</li><li>Backported fixes for CVE-2023-1111, CVE-2023-2222</li>')
        .should.deep.equal(new Set(['CVE-2023-4863', 'CVE-2023-5217', 'CVE-2023-1111', 'CVE-2023-2222']));
      chromiumOf([{ version: '22.3.27', chrome: '108.0.5359.215' }], 'v22.3.27').should.equal('108.0.5359.215');
    });

    it('counts the Chromium CVEs a build misses, minus Electron\'s backports', async () => {
      const cpe = (fixed) => ({ configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', versionEndExcluding: fixed }] }] }] });
      const nvd = (id, sev, fixed) => ({ cve: { id, published: '2023-09-12T00:00:00', descriptions: [{ lang: 'en', value: `${id} description` }],
        metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: sev, baseScore: 8.8 } }] }, ...cpe(fixed) } });
      responses.set('https://services.nvd.nist.gov/', { totalResults: 3, vulnerabilities: [nvd('CVE-2023-4863', 'HIGH', '116.0.5845.187'), nvd('CVE-2023-9999', 'CRITICAL', '117.0.0.0'), nvd('CVE-2023-5217', 'HIGH', '117.0.5938.132')] });
      responses.set('https://releases.electronjs.org/release/v22.3.26', '<p>Security: backported fix for CVE-2023-4863.</p>');
      responses.set('https://releases.electronjs.org/release/v22.3.27', '<p>Nothing</p>');
      const releases = [{ version: '22.3.26', chrome: '108.0.5359.215' }, { version: '22.3.27', chrome: '108.0.5359.215' }, { version: '27.0.0', chrome: '118.0.5993.54' }];
      const result = await chromiumAdvisories({ electron: '22.3.27', chromium: '108.0.5359.215', releases, kev: new Map([['CVE-2023-5217', {}]]), options, sleep: async () => {} });
      result.should.include({ checked: true, total: 2, kev: 1, backported: 1 });
      result.counts.should.include({ critical: 1, high: 1 });
      result.top[0].should.include({ id: 'CVE-2023-5217', kev: true, electronFix: '27.0.0' });
    });
  });

  describe('outputs', () => {
    const meta = {
      version: '2.0.0', generatedAt: '2026-09-28T00:00:00Z', input: '/app', electronVersion: '22.3.27', app: { name: 'My App', version: '1.2.3' },
      dependencies: { rows: [
        { name: 'electron', version: '22.3.27', kinds: ['Electron runtime'], files: [], advisories: [], support: { status: 'unsupported', detail: 'EOL' }, latest: '38.0.0' },
        { name: '@scope/lib', version: '1.0.0', kinds: ['lockfile'], files: [], advisories: [{ id: 'GHSA-xxxx', cves: ['CVE-2021-1'], severity: 'HIGH', summary: 'bad', fixed: '1.0.1', kev: { added: '2024-01-01' }, epss: { epss: 0.5, percentile: 0.9 } }],
          support: { status: 'current', detail: '' }, latest: '1.2.0', kev: true },
        { name: 'fine', version: '2.0.0', kinds: ['lockfile'], files: [], advisories: [], support: { status: 'current', detail: '' }, versionsBehind: 0 },
      ], chromium: { checked: true, chromium: '108.0.5359.215', total: 1, kev: 0, counts: { critical: 1 }, backported: 0, top: [{ id: 'CVE-2023-9999', severity: 'critical', score: 9.8, fixedIn: '117.0.0.0', electronFix: '27.0.0', summary: 'x' }] } },
    };

    it('writes a CycloneDX 1.5 SBOM with the vulnerabilities, KEV and EPSS', () => {
      const bom = cycloneDx(meta);
      bom.should.include({ bomFormat: 'CycloneDX', specVersion: '1.5' });
      bom.metadata.component.should.include({ name: 'My App', version: '1.2.3' });
      bom.components.map(c => c.purl).should.deep.equal(['pkg:npm/electron@22.3.27', 'pkg:npm/%40scope/lib@1.0.0', 'pkg:npm/fine@2.0.0']);
      bom.components[0].type.should.equal('framework');
      const vulnerability = bom.vulnerabilities.find(v => v.id === 'CVE-2021-1');
      vulnerability.affects.should.deep.equal([{ ref: 'pkg:npm/%40scope/lib@1.0.0' }]);
      vulnerability.properties.map(p => p.name).should.include.members(['cisa:kev', 'first:epss']);
      bom.vulnerabilities.find(v => v.id === 'CVE-2023-9999').recommendation.should.equal('Upgrade Electron to 27.0.0 or later');
    });

    it('writes a Word report grouped by who can exploit each finding, with Appendix A', () => {
      const issues = [issue('OPEN_EXTERNAL_JS_CHECK', 'HIGH'), issue('OPEN_EXTERNAL_JS_CHECK', 'MEDIUM'), issue('FUSES_JS_CHECK', 'LOW'), issue('WINDOW_SUMMARY_JS_CHECK', 'INFORMATIONAL')];
      const groups = groupFindings(issues);
      groups.map(([route, list]) => [route, list.map(g => [g.id, g.issues.length])]).should.deep.equal([['content', [['OPEN_EXTERNAL_JS_CHECK', 2]]], ['local', [['FUSES_JS_CHECK', 1]]]]);
      appendixRows(meta.dependencies).map(r => r.name).should.deep.equal(['electron', '@scope/lib']);
      const docx = renderDocx(applyFindingNotes(issues, { rules: { 'OPEN_EXTERNAL_*': { recommendation: 'Allow only https links.' } }, fuses: {} }), meta);
      const entries = zipEntries(docx);
      entries.map(e => e.name).should.include.members(['word/document.xml', 'word/styles.xml', '[Content_Types].xml']);
      const document = zipRead(docx, entries.find(e => e.name === 'word/document.xml')).toString();
      document.should.include('Appendix A');
      document.should.include('Allow only https links.');
      document.should.include('Chromium advisories');
      document.should.not.include('WINDOW_SUMMARY_JS_CHECK');
    });

    it('scores risk with diminishing returns, and separately what outsiders can exploit', () => {
      riskScore([]).should.equal(0);
      riskScore([issue('OPEN_EXTERNAL_JS_CHECK', 'HIGH')]).should.equal(20);
      riskScore([issue('OPEN_EXTERNAL_JS_CHECK', 'HIGH'), issue('OPEN_EXTERNAL_JS_CHECK', 'HIGH')]).should.equal(20); // the same finding twice
      riskScore([issue('FUSES_JS_CHECK', 'HIGH', confidence.FIRM)]).should.equal(16);
      riskScore([issue('FUSES_JS_CHECK', 'HIGH')], { externalOnly: true }).should.equal(0); // local access only
    });

    it('takes notes per check or family', () => {
      const notes = { rules: { 'TRAFFIC_*': { about: 'family' }, TRAFFIC_BASIC_AUTH: { about: 'exact' } }, fuses: { RunAsNode: 'node' } };
      notesFor(notes, 'TRAFFIC_BASIC_AUTH').about.should.equal('exact');
      notesFor(notes, 'TRAFFIC_CLEARTEXT_HTTP').about.should.equal('family');
      (notesFor(notes, 'XSS_SINK_JS_CHECK') === undefined).should.equal(true);
      applyFindingNotes([issue('PACKAGED_FUSES', 'HIGH', confidence.CERTAIN, { properties: { fuse: 'RunAsNode' } })], notes)[0].notes.impact.should.equal('node');
    });

    it('writes several outputs in one scan', async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-outputs-'));
      fs.writeFileSync(path.join(dir, 'main.js'), "const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n");
      fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"out-app","version":"0.1.0","dependencies":{"electron":"22.3.27"}}');
      const out = (name) => path.join(dir, name);
      await run({ input: dir, offline: true, output: [out('r.html'), out('r.json'), out('r.cdx.json'), out('r.docx')].join(',') });
      JSON.parse(fs.readFileSync(out('r.json'), 'utf8')).scores.risk.should.be.above(0);
      JSON.parse(fs.readFileSync(out('r.cdx.json'), 'utf8')).metadata.component.name.should.equal('out-app');
      fs.readFileSync(out('r.html'), 'utf8').should.include('Risk score');
      zipEntries(fs.readFileSync(out('r.docx'))).length.should.equal(8);
    });
  });

  describe('Download cache', () => {
    it('lives in a folder of the user\'s own, not the shared temporary folder', () => {
      const previous = process.env.ELECTRONEGATIVITY_CACHE_DIR;
      delete process.env.ELECTRONEGATIVITY_CACHE_DIR;
      try {
        cacheDir().startsWith(os.tmpdir()).should.equal(false);
        cacheDir().should.include('electronegativity');
      } finally {
        if (previous !== undefined) process.env.ELECTRONEGATIVITY_CACHE_DIR = previous;
      }
    });

    it('replaces a planted link instead of writing through it', function () {
      if (process.platform === 'win32') this.skip();
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-cache-'));
      try {
        const victim = path.join(dir, 'victim.txt');
        fs.writeFileSync(victim, 'keep');
        const file = path.join(dir, 'cache', 'entry.json');
        fs.mkdirSync(path.dirname(file));
        fs.symlinkSync(victim, file);
        writeCacheFile(file, '{"a":1}');
        fs.readFileSync(victim, 'utf8').should.equal('keep');
        fs.lstatSync(file).isSymbolicLink().should.equal(false);
        fs.readFileSync(file, 'utf8').should.equal('{"a":1}');
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    });
  });
});
