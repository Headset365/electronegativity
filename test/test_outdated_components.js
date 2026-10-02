import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { should as chaiShould } from 'chai';
import YAML from 'yaml';
import _i18n from '../src/locales/i18n.js';
import { severity, confidence } from '../src/finder/attributes.js';
import { renderClientMarkdown } from '../src/report/markdown.js';
import { vulnerabilityKinds } from '../src/report/markdown_outdated.js';
import { linksToValidate } from '../src/report/xlsx.js';
import { checkComponentLinks } from '../src/util/link_check.js';
import { mergeDependencies } from '../src/report/combined.js';
import run from '../src/runner.js';

chaiShould();
await _i18n();

const issue = (id, extra = {}) => ({ id, severity: severity.HIGH, confidence: confidence.CERTAIN, file: 'package.json', location: { line: 1, column: 0 },
  description: `Observed ${id}`, sample: '', shortenedURL: 'https://osv.dev', ...extra });
const advisory = (id, severityName, cwes, summary = '') => ({ id, severity: severityName, cwes, summary });
const DEPENDENCIES = { rows: [
  { name: 'electron', version: '22.3.27', latest: '44.5.1', versionsBehind: 500, kinds: ['Electron runtime'], support: { status: 'unsupported' },
    advisories: [advisory('GHSA-e1', 'HIGH', ['CWE-416']), advisory('GHSA-e2', 'HIGH', ['CWE-94']), advisory('GHSA-e3', 'HIGH', ['CWE-693'])] },
  { name: 'jquery', version: '1.12.4', latest: '4.0.0', versionsBehind: 29, kinds: ['lockfile'], support: { status: 'unsupported' },
    advisories: [advisory('GHSA-j1', 'MEDIUM', ['CWE-79'])] },
  { name: 'moment', version: '2.19.1', latest: '2.31.0', versionsBehind: 26, kinds: ['lockfile'], support: { status: 'current' },
    advisories: [advisory('GHSA-m1', 'HIGH', [], 'Regular Expression Denial of Service in moment')] },
  { name: 'current', version: '1.0.0', latest: '1.0.0', kinds: ['lockfile'], support: { status: 'current' }, advisories: [] },
], chromium: { checked: true, top: [{ id: 'CVE-2026-1', severity: 'critical', cwes: ['CWE-787'] }] } };

describe('Outdated Software Components', () => {
  it('names the kinds of vulnerability published for the components, every affected component before a repeat', () => {
    const kinds = vulnerabilityKinds(DEPENDENCIES);
    kinds.length.should.equal(5);
    // the Chromium memory corruption rates highest; jQuery's Cross-Site Scripting and moment's ReDoS (by its summary) are named
    kinds[0].should.include({ label: 'Memory corruption' });
    kinds[0].components.should.deep.equal(['electron 22.3.27']);
    kinds.find(k => k.label === 'Cross-Site Scripting').components.should.deep.equal(['jquery 1.12.4']);
    kinds.find(k => k.label === 'Denial of service').components.should.deep.equal(['moment 2.19.1']);
    kinds.flatMap(k => k.components).should.not.include('current 1.0.0');
    vulnerabilityKinds({ rows: [] }).should.deep.equal([]);
  });

  it('is one Informational finding that refers to the components workbook, with examples and both notes', () => {
    const md = renderClientMarkdown([issue('UNSUPPORTED_VERSION_GLOBAL_CHECK'), issue('AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK', { properties: { advisories: ['GHSA-e1'] } }),
      issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', { file: 'package-lock.json', properties: { package: 'jquery', version: '1.12.4', advisories: ['GHSA-j1'] } })],
    { app: { name: 'Example' }, dependencies: DEPENDENCIES });
    (md.match(/^# /gm) || []).length.should.equal(1);
    const front = YAML.parse(md.split(/^---\s*$/m)[1]);
    front.Title.should.equal('Outdated Software Components');
    front.Consequence.should.equal('N/A');
    front.Likelihood.should.equal('N/A');
    const section = (heading) => md.split(`## ${heading}\n`)[1].split(/^## /m)[0].trim();
    section('Issue Description').should.include('Testing identified the use of outdated software components in Example, including its Electron runtime (version 22.3.27; the latest release is 44.5.1)');
    section('Affected').should.equal('Refer to the attached spreadsheet (`components.xlsx`) for a list of affected components.');
    section('Implication').should.include('- **Cross-Site Scripting** (jquery 1.12.4):');
    section('Implication').should.include('*Note:* An application that uses a library or framework with a known security issue is not necessarily vulnerable to that issue.');
    section('Implication').should.match(/\*Note:\* This issue was rated as Informational because the known vulnerabilities could not be exploited during the engagement\. However, it could be indicative of weaknesses within the patch management process\.$/);
    section('Reproduction and Evidence').should.equal('Refer to the Support status column and the advisory links for each identified component in the attached spreadsheet (`components.xlsx`).');
    section('Recommendations').should.include('Recommended action column').and.include('patch management process');
    section('References').should.include('- Refer to the attached spreadsheet (`components.xlsx`) for a list of affected components.\n\n  Refer to the Latest version column for each component for the latest identified version. Follow vendor guidance when upgrading.');
    section('References').should.include('CWE-1104');
    // the advisory ids are in the workbook, not the finding
    md.should.not.include('GHSA-j1');
  });

  it('leaves out the examples when no advisory names a known kind of vulnerability', () => {
    const md = renderClientMarkdown([issue('END_OF_LIFE_LIBRARY_GLOBAL_CHECK')], { app: { name: 'Example' },
      dependencies: { rows: [{ name: 'old', version: '1.0.0', latest: '2.0.0', versionsBehind: 1, support: { status: 'unsupported' }, advisories: [] }] } });
    md.should.not.include('were subject to publicly disclosed vulnerabilities');
    md.should.include('*Note:* This issue was rated as Informational');
    md.should.not.include('including its Electron runtime');
  });
});

describe('Components workbook links', () => {
  const row = (name, extra = {}) => ({ name, version: '1.0.0', latest: '2.0.0', versionsBehind: 1, known: true, kinds: ['lockfile'], support: { status: 'outdated' }, advisories: [], ...extra });

  it('checks each link against the data behind it and lists the ones to validate by hand', async () => {
    const asked = [];
    const fetchImpl = async (url) => {
      asked.push(url);
      // deps.dev knows "good" only; Snyk knows both
      const missing = url.includes('api.deps.dev') && !url.includes('/good/');
      return { ok: !missing, status: missing ? 404 : 200, body: { cancel: async () => {} } };
    };
    const dependencies = { rows: [row('good'), row('unknown-to-deps-dev'), row('private', { latest: undefined, known: undefined, support: { status: 'unsupported' } })] };
    await checkComponentLinks(dependencies, { fetchImpl });
    dependencies.rows[0].linkChecks.should.deep.equal([true, true, true, true, true]);
    linksToValidate(dependencies.rows[0]).should.equal('');
    linksToValidate(dependencies.rows[1]).should.equal('deps.dev');
    // not on npm: no version pages and no GitHub search worth linking
    linksToValidate(dependencies.rows[2]).should.equal('Installed version link, Latest version link, deps.dev, GitHub');
    asked.some(url => url.startsWith('https://www.npmjs.com/')).should.equal(false, 'npm pages are checked against the registry, not loaded');
    // never checked: all five are left for manual validation
    linksToValidate(row('unchecked')).should.equal('Installed version link, Latest version link, deps.dev, Snyk, GitHub');
  });

  it('checks nothing offline, and leaves every link for manual validation', async () => {
    process.env.ELECTRONEGATIVITY_OFFLINE = '1';
    try {
      const dependencies = { rows: [row('lib')] };
      await checkComponentLinks(dependencies, { fetchImpl: () => { throw new Error('no network'); } });
      linksToValidate(dependencies.rows[0]).should.equal('Installed version link, Latest version link, deps.dev, Snyk, GitHub');
    } finally {
      delete process.env.ELECTRONEGATIVITY_OFFLINE;
    }
  });
});

describe('Reports folder', () => {
  it('is written next to the first output, with the client findings and components workbook', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-reports-'));
    const app = path.join(import.meta.dirname, 'apps', 'vulnerable-app');
    try {
      fs.mkdirSync(path.join(dir, 'out'));
      const result = await run({ input: app, offline: true, output: [path.join(dir, 'out', 'report.sarif')] }, false);
      result.reports.dir.should.equal(path.join(dir, 'out', 'reports'));
      fs.readdirSync(result.reports.dir).should.include('components.xlsx').and.include('Insufficient Renderer Process Isolation.md');
      // a step of a guided run leaves them out; the run writes them once
      const step = await run({ input: app, offline: true, output: [path.join(dir, 'step.json')], reports: false }, false);
      (step.reports === undefined).should.equal(true);
      fs.existsSync(path.join(dir, 'reports')).should.equal(false);
      // and with no output at all, where the caller says
      await run({ input: app, offline: true, reportsBase: dir }, false);
      fs.existsSync(path.join(dir, 'reports', 'components.xlsx')).should.equal(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }).timeout(60000);

  it('merges the components every step found, keeping what a step could look up', () => {
    const merged = mergeDependencies([
      { rows: [{ name: 'a', version: '1', kinds: ['lockfile'], files: [], locations: ['package-lock.json'], advisories: [], dev: false }], offline: false },
      { rows: [{ name: 'a', version: '1', kinds: ['bundled library'], files: ['js/a.min.js'], locations: ['js/a.min.js'], latest: '2', advisories: [{ id: 'X' }], dev: false },
        { name: 'b', version: '3', kinds: ['bundled library'], files: [], locations: ['https://app.example.com/b.js'], advisories: [] }], offline: false, chromium: { checked: true } },
    ]);
    merged.rows.map(r => `${r.name}@${r.version}`).should.deep.equal(['a@1', 'b@3']);
    merged.rows[0].should.include({ latest: '2' });
    merged.rows[0].kinds.should.deep.equal(['lockfile', 'bundled library']);
    merged.rows[0].locations.should.deep.equal(['package-lock.json', 'js/a.min.js']);
    merged.rows[0].advisories.should.have.length(1);
    merged.chromium.should.deep.equal({ checked: true });
    (mergeDependencies([undefined]) === undefined).should.equal(true);
  });
});
