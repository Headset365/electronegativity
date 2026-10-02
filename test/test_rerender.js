import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import run from '../src/runner.js';
import { severity } from '../src/finder/attributes.js';
import { issueFromReport, compareFinding, rerender } from '../src/report/rerender.js';
import { parseFinding, findingFingerprints } from '../src/report/markdown.js';

chaiShould();
await _i18n();

const CLI = path.join(import.meta.dirname, '..', 'src', 'index.js');
const APP = path.join(import.meta.dirname, 'apps', 'vulnerable-app');

describe('Re-rendering the client findings of an earlier scan (--rerender)', function () {
  this.timeout(60000);
  let dir;
  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-rerender-'));
    await run({ input: APP, offline: true, output: [path.join(dir, 'report.html')], suppress: undefined }, false);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
  const reports = () => path.join(dir, 'reports');
  const findingFile = (name) => path.join(reports(), name);

  it('always writes a complete report.json next to the findings, with what the tool wrote in each', () => {
    const data = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
    data.tool.should.equal('Electronegativity');
    data.issues.length.should.be.above(0);
    const written = fs.readdirSync(reports()).filter(name => name.endsWith('.md'));
    Object.keys(data.markdown.findings).sort().should.deep.equal(written.sort());
    for (const name of written) data.markdown.findings[name].should.deep.equal(findingFingerprints(fs.readFileSync(findingFile(name), 'utf8')));
  });

  it('writes the findings again from report.json into newReports and lists the manual edits to carry over', () => {
    const name = 'Renderer Isolation Weakened.md';
    const original = fs.readFileSync(findingFile(name), 'utf8');
    // the tester raised the rating, added a sentence, added a section and deleted References; saved with Windows line endings
    const edited = original.replace(/^Consequence: .*$/m, 'Consequence: Critical').replace('## Implication\n\n', '## Implication\n\nConfirmed by the tester in build 4.2.\n\n')
      .replace(/## References[\s\S]*$/, '## Tester Appendix\n\nScreens 3 and 4.\n').replace(/\n/g, '\r\n');
    fs.writeFileSync(findingFile(name), edited);
    // an untouched finding re-saved with Windows line endings is not an edit
    const other = fs.readdirSync(reports()).find(f => f.endsWith('.md') && f !== name);
    fs.writeFileSync(findingFile(other), fs.readFileSync(findingFile(other), 'utf8').replace(/\n/g, '\r\n'));
    fs.writeFileSync(findingFile('my notes.md'), 'tester notes, not a finding');

    const cli = spawnSync(process.execPath, [CLI, '--rerender', path.join(dir, 'report.json')], { encoding: 'utf8' });
    cli.status.should.equal(0, cli.stderr);
    cli.stdout.should.include('1 earlier finding edited by hand');
    const out = path.join(reports(), 'newReports');
    fs.readdirSync(out).should.include(name).and.include('components.xlsx').and.include('report.json').and.not.include('my notes.md');
    // the new finding comes from the data: the tool's rating and text, not the tester's
    const fresh = parseFinding(fs.readFileSync(path.join(out, name), 'utf8'));
    fresh.front.Consequence.should.not.equal('Critical');
    fresh.sections.Implication.should.not.include('Confirmed by the tester');
    fresh.sections.should.have.property('References');
    // the earlier findings are only read
    fs.readFileSync(findingFile(name), 'utf8').should.equal(edited);

    const review = fs.readFileSync(path.join(reports(), 'newReports-review.md'), 'utf8');
    const section = review.split('## Manual changes to carry over')[1].split(/^## /m)[0];
    section.should.include(`### Renderer Isolation Weakened (\`${name}\`)`);
    section.should.include('**Rating**: edited by hand').and.include('> Consequence: Critical');
    section.should.include('**Implication**: edited by hand').and.include('> Confirmed by the tester in build 4.2.');
    section.should.include('**Tester Appendix**: a section added by hand').and.include('> Screens 3 and 4.');
    section.should.include('**References**: the section was removed by hand.');
    section.should.not.include(other);
    review.split('## Unchanged since the tool wrote them')[1].should.include(other);

    // the new findings carry their own fingerprints: they can be re-rendered again in turn
    const again = rerender({ dataFile: path.join(out, 'report.json'), version: 'test' });
    again.dir.should.equal(path.join(out, 'newReports'));
    again.compared.every(c => c.known && c.changes.length === 0).should.equal(true);
  });

  it('flags every difference for a report written before fingerprints, and maps merged findings', () => {
    const data = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
    delete data.markdown;
    // an earlier layout: findings in markdown/, two outdated findings since merged into one
    const old = path.join(dir, 'markdown');
    fs.renameSync(reports(), old);
    fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(data));
    fs.writeFileSync(path.join(old, 'Outdated Electron Runtime.md'), '---\nTitle: Outdated Electron Runtime\nGeneratedBy: Electronegativity\n---\n\n# Outdated Electron Runtime\n\n## Affected\n\npackage.json\n');
    const name = 'Renderer Isolation Weakened.md';
    fs.writeFileSync(path.join(old, name), fs.readFileSync(path.join(old, name), 'utf8').replace('## Implication\n\n', '## Implication\n\nTester text.\n\n'));

    const result = rerender({ dataFile: path.join(dir, 'report.json'), version: 'test' });
    result.dir.should.equal(path.join(old, 'newReports'));
    const review = fs.readFileSync(result.review, 'utf8');
    review.should.include('## Differences that may be manual changes');
    review.split('## Differences that may be manual changes')[1].should.include('**Implication** (differs)').and.include('> Tester text.');
    review.should.include('## Earlier findings not written any more');
    review.should.include('`Outdated Electron Runtime.md` (Outdated Electron Runtime)');
    review.should.include('## Identical to the new findings');
  });

  it('reads findings and accepted risks back from the JSON report, including the earlier flattened form', () => {
    const issue = issueFromReport({ id: 'X_CHECK', severity: 'HIGH', confidence: 'FIRM', file: 'main.js', line: 3, column: 4, reference: 'https://example.com',
      session: 2, validation: { status: 'confirmed' }, properties: { url: 'https://app.test' } });
    issue.should.include({ id: 'X_CHECK', shortenedURL: 'https://example.com', session: 2 });
    issue.severity.should.equal(severity.HIGH);
    issue.location.should.deep.equal({ line: 3, column: 4 });
    issueFromReport({ id: 'Y', severity: 'LOW', confidence: 'CERTAIN', reason: 'accepted', owner: 'team' }).suppression.should.include({ reason: 'accepted', owner: 'team' });
    issueFromReport({ id: 'Y', severity: 'LOW', confidence: 'CERTAIN', suppression: { reason: 'full' } }).suppression.should.deep.equal({ reason: 'full' });
  });

  it('compares one finding against what the tool wrote', () => {
    const text = '---\nTitle: T\nConsequence: Low\nLikelihood: Rare\nNotes:\n  - a\n---\n\n# T\n\n## Affected\n\nx\n\n## Implication\n\ny\n';
    const recorded = findingFingerprints(text);
    compareFinding(parseFinding(text), recorded).should.deep.equal({ known: true, changes: [] });
    const notes = compareFinding(parseFinding(text.replace('  - a', '  - b')), recorded);
    notes.changes.map(c => c.part).should.deep.equal(['Notes']);
    // blank lines and trailing spaces are not edits
    compareFinding(parseFinding(text.replace('\n\ny\n', '\n\n\n\ny   \n')), recorded).changes.should.deep.equal([]);
  });

  it('refuses a file that is not an Electronegativity JSON report', () => {
    fs.writeFileSync(path.join(dir, 'other.json'), '{"a":1}');
    (() => rerender({ dataFile: path.join(dir, 'other.json'), version: 'test' })).should.throw(/not an Electronegativity JSON report/);
  });
});
