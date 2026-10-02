import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { should as chaiShould } from 'chai';
import YAML from 'yaml';
import { severity, confidence } from '../src/finder/attributes.js';
import { groupClientFindings, ratingOf, renderClientMarkdown, renderClientFindings, renderTesterNotes, writeClientMarkdown, combineRuns, findingFileName } from '../src/report/markdown.js';
import { VARIATIONS, matchingVariations } from '../src/report/markdown_variations.js';
import { CLIENT_COPY, CLIENT_LABELS } from '../src/report/markdown_client_copy.js';
import { componentTable, renderComponentsXlsx, statusLabels, componentLinks } from '../src/report/xlsx.js';
import { outputFormat, splitOutputs, writeIssues } from '../src/util/file.js';

chaiShould();
const issue = (id, sev = severity.MEDIUM, conf = confidence.FIRM, extra = {}) => ({
  id, severity: sev, confidence: conf, file: '/client/app/main.js', location: { line: 8, column: 1 },
  description: `Observed ${id}`, sample: 'const x = "value";', shortenedURL: 'https://www.electronjs.org/docs/latest/tutorial/security', ...extra,
});

function zipEntry(buffer, wanted) {
  let offset = 0;
  while (buffer.readUInt32LE(offset) === 0x04034b50) {
    const size = buffer.readUInt32LE(offset + 18);
    const nameLength = buffer.readUInt16LE(offset + 26);
    const extraLength = buffer.readUInt16LE(offset + 28);
    const name = buffer.toString('utf8', offset + 30, offset + 30 + nameLength);
    const start = offset + 30 + nameLength + extraLength;
    if (name === wanted) return zlib.inflateRawSync(buffer.subarray(start, start + size)).toString();
    offset = start + size;
  }
  throw new Error(`${wanted} not in workbook`);
}

describe('Client report outputs', () => {
  it('maps every specified group and retains supporting observations without making findings from them', () => {
    const checks = [
      'NODE_INTEGRATION_JS_CHECK', 'WEB_SECURITY_JS_CHECK', 'CONTEXT_BRIDGE_EXPOSURE_JS_CHECK', 'IPC_FILE_ACCESS_JS_CHECK',
      'OPEN_EXTERNAL_JS_CHECK', 'COMMAND_INJECTION_JS_CHECK', 'WORD_LAUNCH_JS_CHECK', 'PROTOCOL_HANDLER_JS_CHECK',
      'LIMIT_NAVIGATION_JS_CHECK', 'PERMISSION_REQUEST_HANDLER_GLOBAL_CHECK', 'XSS_SINK_JS_CHECK', 'CSP_GLOBAL_CHECK',
      'DOCUMENT_PIPELINE_JS_CHECK', 'FUSES_GLOBAL_CHECK', 'ASAR_INTEGRITY', 'CODE_SIGNING', 'UPDATE_SECURITY_JS_CHECK',
      'DEVTOOLS_JS_CHECK', 'HARDCODED_SECRET_JS_CHECK', 'STORAGE_SECRET_AT_REST', 'HTTP_RESOURCES_JS_CHECK',
      'TRAFFIC_SECRET_IN_URL', 'UNSUPPORTED_VERSION_GLOBAL_CHECK', 'DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', 'MALICIOUS_DEPENDENCY',
    ];
    const groups = groupClientFindings([
      ...checks.map(id => issue(id)), issue('CSP_JS_CHECK', severity.INFORMATIONAL),
      issue('WINDOW_SUMMARY_JS_CHECK', severity.INFORMATIONAL),
    ]);
    // the Electron runtime and third-party components are one finding
    groups.length.should.equal(24);
    groups.filter(g => g.definition[0] === 'Outdated Software Components').length.should.equal(1);
    groups.find(g => g.definition[0] === 'Missing or Insufficient Content Security Policy').evidence.map(i => i.id).should.include('CSP_JS_CHECK');
    groups.some(g => g.definition[0] === 'Additional Security Observations').should.equal(false);
    for (const group of groups) {
      const variants = matchingVariations(group.definition[0], group.issues, id => id.replace(/_(JS|HTML|JSON|GLOBAL|LOCK)_CHECK$/, ''));
      variants.length.should.be.greaterThan(0);
      for (const finding of group.issues) variants.some(v => v.issues.includes(finding)).should.equal(true);
      const one = renderClientMarkdown(group.issues, { app: { name: 'Example App' } });
      // the outdated components finding refers to the components workbook instead of listing its scenarios
      if (group.definition[0] === 'Outdated Software Components') {
        for (const heading of ['Affected', 'Reproduction and Evidence', 'References']) one.split(`## ${heading}\n`)[1].should.include('the attached spreadsheet (`components.xlsx`)');
        continue;
      }
      // each scenario under its client label where the finding describes it, and its advice under Recommendations
      for (const heading of ['Issue Description', 'Affected', 'Implication']) {
        const section = one.split(`## ${heading}\n`)[1].split(/^## /m)[0];
        for (const variant of variants) section.should.include(CLIENT_LABELS[variant.label], `${group.definition[0]} ${heading} omitted ${variant.label}`);
      }
      for (const variant of variants) one.split('## Recommendations\n')[1].should.include(variant.recommendation);
    }
    const markdown = renderClientMarkdown(checks.map(id => issue(id, severity.MEDIUM, confidence.FIRM, { sample: '' })), { app: { name: 'Example App' } });
    const headings = ['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References'];
    for (const heading of headings) (markdown.match(new RegExp(`^## ${heading}$`, 'gm')) || []).length.should.equal(24);
    for (const section of markdown.split(/^## (?:Issue Description|Affected|Implication|Reproduction and Evidence|Recommendations|References)$/m).slice(1))
      section.trim().length.should.be.greaterThan(0);
    markdown.should.include('The issue can be reproduced as follows:');
    markdown.should.include('Example App');
  });

  it('groups, excludes evidence-only checks and sorts by consequence and likelihood', () => {
    const findings = groupClientFindings([
      issue('WINDOW_SUMMARY_JS_CHECK', severity.INFORMATIONAL),
      issue('CSP_JS_CHECK', severity.MEDIUM),
      issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH, confidence.CERTAIN),
      issue('SOURCE_MAP_SHIPPED_GLOBAL_CHECK', severity.INFORMATIONAL),
      issue('CSP_GLOBAL_CHECK', severity.MEDIUM),
      issue('RUNTIME_MARKER', severity.INFORMATIONAL, confidence.CERTAIN, { properties: { live: false } }),
      issue('EXOTIC_CHECK', severity.LOW),
      issue('CODE_SIGNING_GLOBAL_CHECK', severity.LOW),
    ]);
    findings.map(g => g.definition[0]).should.deep.equal([
      'Insufficient Renderer Process Isolation', 'Missing or Insufficient Content Security Policy', 'Additional Security Observations',
      'Application Code Not Protected Against Tampering or Disclosure', 'Missing Code Signing or Exploit Mitigations',
    ]);
    findings.slice(-2).every(g => g.rating.consequence === 'N/A' && g.rating.likelihood === 'N/A').should.equal(true);
    findings.find(g => g.definition[0] === 'Missing or Insufficient Content Security Policy').issues.length.should.equal(1);
  });

  it('uses paired N/A ratings, local route caps and confirmed execution', () => {
    ratingOf(issue('SOURCE_MAP_SHIPPED_GLOBAL_CHECK', severity.INFORMATIONAL), 'Application Code Not Protected Against Tampering or Disclosure')
      .should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    ratingOf(issue('CODE_SIGNING_GLOBAL_CHECK', severity.LOW), 'Missing Code Signing or Exploit Mitigations')
      .should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    ratingOf(issue('FUSES_GLOBAL_CHECK', severity.HIGH, confidence.CERTAIN), 'Insecure Electron Fuse Configuration')
      .should.deep.equal({ consequence: 'Medium', likelihood: 'Unlikely' });
    // outdated components are Informational: their published vulnerabilities were not exploited
    for (const id of ['DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', 'END_OF_LIFE_LIBRARY_GLOBAL_CHECK', 'UNSUPPORTED_VERSION_GLOBAL_CHECK', 'AVAILABLE_SECURITY_FIXES_GLOBAL_CHECK'])
      ratingOf(issue(id, severity.HIGH, confidence.CERTAIN), 'Outdated Software Components').should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    ratingOf(issue('RUNTIME_ACTIVE_SCRIPT', severity.MEDIUM, confidence.FIRM, { properties: { execution: 'observed' } }),
      'Cross-Site Scripting in Content Rendering').consequence.should.equal('Medium');
    ratingOf(issue('MALICIOUS_DEPENDENCY', severity.HIGH), 'Known Malicious Software Package').consequence.should.equal('Critical');
  });

  it('emits parseable YAML and unredacted evidence, accepted risks, references and the components workbook', () => {
    const findings = renderClientMarkdown([
      issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { properties: { advisories: ['OSV-1'] } }),
      issue('WORD_LAUNCH_JS_CHECK', severity.INFORMATIONAL),
    ], { app: { name: 'Client: Example #1' }, outputs: ['/tmp/components.xlsx'], suppressed: [
      issue('OPEN_EXTERNAL_JS_CHECK', severity.MEDIUM, confidence.FIRM, { suppression: { reason: 'Approved: #42', owner: 'Client' } }),
    ] });
    const blocks = findings.split(/^---\s*$/m).filter(s => /\bTitle:/.test(s));
    blocks.length.should.equal(3);
    for (const block of blocks) {
      const front = YAML.parse(block);
      front.Title.should.be.a('string');
      // Notes hold the accepted risks only
      if (front.Notes) front.Notes.should.be.an('array');
      (front.Consequence === 'N/A').should.equal(front.Likelihood === 'N/A');
    }
    findings.should.include('Client: Example #1');
    findings.should.include('/client/app/main.js:8');
    blocks.map(block => YAML.parse(block)).flatMap(front => front.Notes).join(' ').should.include('Approved: #42');
    findings.should.include('Refer to the attached spreadsheet (`components.xlsx`) for a list of affected components.');
    findings.should.include('https://cwe.mitre.org/data/definitions/');
  });

  it('carries custom finding notes and recorded evidence into the appropriate sections', () => {
    const findings = [issue('OPEN_EXTERNAL_JS_CHECK', severity.HIGH, confidence.FIRM, {
      notes: {
        about: 'The reviewed link comes from a document.',
        impact: 'The client confirmed the operating system hand-off.',
        reachability: 'A recipient can click the link.',
        preconditions: ['Open a shared document.'],
        steps: ['Click the crafted link.'],
        confirm: 'Observe the handler invocation.',
        recommendation: 'Allow only the approved host.',
      },
      properties: { evidence: ['GET https://example.test/open?target=custom'], screenshot: '/evidence/hand-off.png' },
      validation: { status: 'confirmed', text: 'Observed in the watch session.' },
    })];
    const markdown = renderClientMarkdown(findings, { app: { name: 'Client App' } });
    const section = (heading) => markdown.split(`## ${heading}\n`)[1].split(/^## /m)[0];
    section('Issue Description').should.include('The reviewed link comes from a document.');
    section('Implication').should.include('The client confirmed the operating system hand-off.').and.include('A recipient can click the link.');
    section('Reproduction and Evidence').should.include('Open a shared document.').and.include('- Click the crafted link.')
      .and.include('During testing, observed in the watch session.').and.include('`hand-off.png`');
    section('Recommendations').should.include('- Allow only the approved host.');
    // what the tester checks by hand, and the raw evidence, are in the tester notes
    const [notes] = renderTesterNotes(findings, { app: { name: 'Client App' } });
    for (const value of ['Observe the handler invocation.', 'GET https://example.test/open?target=custom', '/evidence/hand-off.png', 'Observed in the watch session.'])
      notes.content.should.include(value);
    markdown.should.include('## Implication');
    markdown.should.include('## Reproduction and Evidence');
    markdown.should.include('## Recommendations');
  });

  it('explains global findings and highlights HTML remediation examples', () => {
    const markdown = renderClientMarkdown([
      issue('CSP_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { file: 'N/A', sample: '' }),
      issue('IFRAME_SANDBOX_HTML_CHECK', severity.MEDIUM, confidence.FIRM, { file: '/client/app/index.html', sample: '', manualReview: true }),
    ], { app: { name: 'Client App' } });
    markdown.should.include('- Client App (application-wide) — ');
    markdown.should.include('Review the configuration of Client App, which shows that');
    markdown.should.match(/```html\n\s*<iframe/);
    markdown.should.include('- Electron security checklist\n\n  https://');
    const notes = renderTesterNotes([issue('IFRAME_SANDBOX_HTML_CHECK', severity.MEDIUM, confidence.FIRM, { file: '/client/app/index.html', sample: '', manualReview: true })])[0].content;
    notes.should.include('requires reachability or configuration review');
  });

  it('keeps several alternatives inside one finding and across all six sections', () => {
    const issues = [issue('OPEN_EXTERNAL_JS_CHECK'), issue('OPEN_PATH_JS_CHECK')];
    const markdown = renderClientMarkdown(issues, { app: { name: 'Client App' } });
    (markdown.match(/^# Unvalidated URLs and Files Passed to the Operating System$/gm) || []).length.should.equal(1);
    const sections = ['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References'];
    for (const label of ['External URL or protocol', 'File path handed to the host']) {
      const [description, implication, recommendation] = CLIENT_COPY[label];
      const parts = [[CLIENT_LABELS[label], description], [CLIENT_LABELS[label]], [CLIENT_LABELS[label], implication], [], [recommendation], []];
      sections.forEach((heading, n) => {
        const section = markdown.split(`## ${heading}\n`)[1].split(/^## /m)[0];
        for (const value of parts[n]) section.should.include(value, `${heading} omitted ${label}`);
        section.trim().length.should.be.greaterThan(0);
      });
    }
    markdown.split('## Implication\n')[1].split('## Reproduction and Evidence')[0].should.not.include('Potential worst case');
    const fuseVariants = matchingVariations('Insecure Electron Fuse Configuration', [issue('PACKAGED_FUSES')], id => id);
    fuseVariants.length.should.equal(3);
  });

  it('groups every finding that can reach the client report under a named problem, never under Other', () => {
    const titleOf = (id, sev = severity.MEDIUM) => groupClientFindings([issue(id, sev)])[0]?.definition[0];
    titleOf('DYNAMIC_MODULE_JS_CHECK', severity.HIGH).should.equal('Command or Code Execution from Variable Input');
    titleOf('RUNTIME_MARKER_MODULE').should.equal('Command or Code Execution from Variable Input');
    for (const id of ['RUNTIME_CAMPAIGN_FS_READ', 'RUNTIME_CAMPAIGN_NODE', 'RUNTIME_CAMPAIGN_ELECTRON', 'PRELOAD_JS_CHECK']) titleOf(id).should.equal('Insufficient Renderer Process Isolation', id);
    titleOf('RUNTIME_CAMPAIGN_EVAL', severity.LOW).should.equal('Missing or Insufficient Content Security Policy');
    titleOf('UNTRUSTED_LOAD_URL_JS_CHECK', severity.HIGH).should.equal('Insufficient Navigation and New Window Restrictions');
    titleOf('CERTIFICATE_PINNING_GLOBAL_CHECK', severity.INFORMATIONAL).should.equal('Certificate Pinning Not Implemented');
    titleOf('CERTIFICATE_VERIFY_PROC_JS_CHECK', severity.HIGH).should.equal('Insecure Network Transport and Certificate Validation');
    // the tool's own housekeeping is not a finding about the app
    groupClientFindings([issue('RUNTIME_CAMPAIGN_RESTORE'), issue('RUNTIME_CAMPAIGN_CLEANUP', severity.INFORMATIONAL)]).should.have.length(0);
    // a campaign's file read is runtime evidence: the payload's script ran and signalled it
    ratingOf(issue('RUNTIME_CAMPAIGN_FS_READ', severity.HIGH), 'Insufficient Renderer Process Isolation').likelihood.should.equal('Very Likely');
    // "no pinning" is described as a hardening gap, not a validation bypass
    const pinning = renderClientMarkdown([issue('CERTIFICATE_PINNING_GLOBAL_CHECK', severity.INFORMATIONAL)], { app: { name: 'Demo' } });
    pinning.should.include('No certificate pinning').and.not.include('Certificate validation bypass');
  });

  it('lists the most severe instances first, so a cut-off list keeps the one that rates the finding', () => {
    // (validated: the Cross-Site Scripting evidence lists validated instances only)
    const seen = { validation: { status: 'observed' } };
    const many = [...Array.from({ length: 13 }, (_, n) => issue('XSS_SINK_JS_CHECK', severity.LOW, confidence.FIRM, { file: `/app/low${n}.js`, ...seen })),
      issue('XSS_SINK_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/app/high.js', ...seen })];
    const [finding] = renderClientFindings(many, { root: '/app', app: { name: 'Demo' } });
    const evidence = finding.content.split('## Reproduction and Evidence')[1];
    evidence.should.include('high.js');
    evidence.indexOf('high.js').should.be.below(evidence.indexOf('low0.js'));
  });

  it('defines several complete variants for every named group and falls back for new checks', () => {
    Object.keys(VARIATIONS).length.should.equal(25);
    for (const entries of Object.values(VARIATIONS)) {
      entries.length.should.be.at.least(2);
      for (const entry of entries) {
        entry.length.should.be.oneOf([3, 4]);
        if (entry.length === 4) entry[3].should.be.a('function');
        entry[1].should.be.instanceOf(RegExp);
        for (const text of [entry[0], entry[2], ...CLIENT_COPY[entry[0]]]) text.trim().length.should.be.greaterThan(0);
        CLIENT_COPY[entry[0]].length.should.equal(3);
      }
    }
    matchingVariations('Additional Security Observations', [issue('NEW_CHECK')], id => id).map(v => v.label).should.deep.equal(['NEW_CHECK']);
  });

  it('lists the components needing action, most urgent first, with plain status labels and an action', () => {
    const rows = [
      { name: 'current', version: '1.0.0', latest: '1.0.0', kinds: ['lockfile'], locations: ['package-lock.json'], advisories: [], support: { status: 'current' } },
      { name: 'old', version: '1.0.0', latest: '2.0.0', versionsBehind: 3, majorsBehind: 1, kinds: ['node_modules'], locations: ['node_modules/old'], advisories: [], support: { status: 'outdated' } },
      { name: 'malicious', version: '1.0.0', kinds: ['bundled library'], files: ['js/app.js'], advisories: [], malicious: { id: 'OSV-BAD' }, support: { status: 'unknown' } },
      { name: 'electron', version: '25.0.0', latest: '38.0.0', versionsBehind: 99, kinds: ['Electron runtime'], locations: ['MyApp.exe'],
        advisories: [{ id: 'OSV-1', severity: 'HIGH', kev: true, fixed: '30.0.0' }], fixedIn: '30.0.0', support: { status: 'unsupported' } },
      { name: 'request', version: '2.88.2', latest: '2.88.2', latestDeprecated: true, deprecated: 'no longer maintained', kinds: ['lockfile'], locations: ['package-lock.json (line 40)'],
        advisories: [{ id: 'GHSA-p8p7-x288-28g6', severity: 'MEDIUM' }], fixedIn: null, support: { status: 'unsupported' } },
      { name: 'lodash', version: '4.17.4', latest: '4.18.1', versionsBehind: 17, kinds: ['lockfile'], advisories: [{ id: 'GHSA-1', severity: 'CRITICAL', fixed: '4.17.21' }],
        fixedIn: '4.17.21', support: { status: 'current' } },
      { name: 'private-thing', version: '1.0.0', kinds: ['node_modules'], advisories: [], support: { status: 'unknown' } },
    ];
    const table = componentTable({ rows });
    table.header.should.deep.equal(['Component', 'Type', 'Installed version', 'Installed version release date', 'Latest version', 'Latest version release date',
      'Support status', 'Recommended action', 'Path found', 'Installed version link', 'Latest version link',
      'Advisories: deps.dev (this version)', 'Advisories: Snyk (this version)', 'Advisories: GitHub (all versions)', 'Links to validate manually']);
    const byName = Object.fromEntries(table.rows.map(r => [r[0], r]));
    table.rows.map(r => r[0]).should.deep.equal(['malicious', 'electron', 'lodash', 'request', 'old']);
    byName.malicious[1].should.equal('JS library');
    byName.electron[1].should.equal('Electron runtime');
    byName.old[1].should.equal('npm package');
    byName.electron[6].should.equal('Unsupported, Known advisories');
    byName.electron[7].should.equal('Upgrade to a supported release line (latest 38.0.0)');
    byName.request[6].should.equal('Latest, End of life, Known advisories');
    byName.request[7].should.equal('Replace with a maintained alternative: request is no longer maintained');
    byName.lodash[6].should.equal('Outdated, Known advisories');
    byName.lodash[7].should.equal('Upgrade to 4.17.21 or later (latest 4.18.1)');
    byName.old[6].should.equal('Outdated');
    byName.old[7].should.equal('Upgrade to 2.0.0');
    byName.malicious[6].should.equal('Malicious');
    byName.malicious[7].should.equal('Remove immediately: known malicious version (OSV-BAD)');
    byName.request[8].should.equal('package-lock.json (line 40)');
    byName.malicious[8].should.equal('js/app.js');
    // every component is in the catalog, with where it was found and whether it needs action
    table.catalogHeader.should.deep.equal(['Component', 'Type', 'Version', 'Identified from', 'Path found', 'Needs action']);
    table.catalog.map(r => r[0]).should.deep.equal(['current', 'electron', 'lodash', 'malicious', 'old', 'private-thing', 'request']);
    table.catalog.find(r => r[0] === 'old').should.deep.equal(['old', 'npm package', '1.0.0', 'Installed package (node_modules)', 'node_modules/old', 'Yes']);
    table.catalog.find(r => r[0] === 'current')[5].should.equal('No');
    table.catalog.find(r => r[0] === 'private-thing')[5].should.equal('No');
  });

  it('marks a deprecated version or ended release line Unsupported, and a discontinued project End of life', () => {
    statusLabels({ name: 'jquery', version: '3.4.1', latest: '4.0.0', versionsBehind: 9, deprecated: 'use 3.5', support: { status: 'unsupported' }, advisories: [] })
      .should.deep.equal(['Unsupported']);
    statusLabels({ name: 'old-framework', version: '1.8.0', latest: '1.8.3', versionsBehind: 3, support: { status: 'unsupported', discontinued: true }, advisories: [] })
      .should.deep.equal(['End of life']);
    statusLabels({ name: 'next', version: '2.0.0-beta', latest: '1.9.0', versionsBehind: 0, support: { status: 'current' }, advisories: [] }).should.deep.equal(['Latest']);
  });

  it('links each component to its version pages and to its advisories on deps.dev, Snyk and GitHub', () => {
    const row = { name: '@example/library', version: '1.0.0', known: true, latest: '3.0.0', versionsBehind: 4, kinds: ['lockfile'], advisories: [{ id: 'GHSA-1' }], fixedIn: '2.0.0',
      released: '2020-01-02', latestReleased: '2026-03-04', support: { status: 'current' } };
    const electron = { name: 'electron', version: '22.3.27', latest: '44.5.1', versionsBehind: 1, kinds: ['Electron runtime'], advisories: [], support: { status: 'unsupported' } };
    componentLinks(row).map(l => l.url).should.deep.equal([
      'https://www.npmjs.com/package/%40example/library/v/1.0.0', 'https://www.npmjs.com/package/%40example/library/v/3.0.0',
      'https://deps.dev/npm/%40example%2Flibrary/1.0.0', 'https://security.snyk.io/package/npm/%40example%2Flibrary/1.0.0',
      'https://github.com/advisories?query=ecosystem%3Anpm%20affects%3A%40example%2Flibrary']);
    componentLinks(row)[4].text.should.equal('GitHub: all advisories for @example/library (every version)');
    componentLinks(electron).slice(0, 2).map(l => l.url).should.deep.equal(['https://releases.electronjs.org/release/v22.3.27', 'https://releases.electronjs.org/release/v44.5.1']);
    // a version npm doesn't know: the package page
    componentLinks({ ...row, known: false })[0].url.should.equal('https://www.npmjs.com/package/%40example/library');

    const buffer = renderComponentsXlsx({ rows: [row, electron] });
    const sheet = zipEntry(buffer, 'xl/worksheets/sheet1.xml');
    const rels = zipEntry(buffer, 'xl/worksheets/_rels/sheet1.xml.rels');
    sheet.should.include('state="frozen"').and.include('<autoFilter ref="A1:O3"/>');
    // five links a row, each its own cell and relationship
    (sheet.match(/<hyperlink ref=/g) || []).length.should.equal(10);
    (rels.match(/TargetMode="External"/g) || []).length.should.equal(10);
    sheet.should.include('<hyperlink ref="J2" r:id="rId1"/>').and.include('<hyperlink ref="N3" r:id="rId10"/>');
    rels.should.include('https://deps.dev/npm/%40example%2Flibrary/1.0.0');
    // release dates are Excel dates (2020-01-02 is day 43832), shown as yyyy-mm-dd
    sheet.should.include('<c r="D2" s="4"><v>43832</v></c>');
    zipEntry(buffer, 'xl/styles.xml').should.include('formatCode="yyyy-mm-dd"');
    const workbook = zipEntry(buffer, 'xl/workbook.xml');
    workbook.should.include('name="Components needing action" sheetId="1"').and.include('name="All components" sheetId="2"');
    zipEntry(buffer, 'xl/worksheets/sheet2.xml').should.include('<autoFilter ref="A1:F3"/>').and.not.include('<hyperlinks>');
  });

  it('escapes link targets and cell text, and never writes formulas', () => {
    const row = { name: 'a&b"<x>', version: '1.0.0', latest: '2.0.0', versionsBehind: 1, kinds: ['lockfile'], locations: ['=HYPERLINK("bad")'], advisories: [], support: { status: 'outdated' } };
    const buffer = renderComponentsXlsx({ rows: [row] });
    const sheet = zipEntry(buffer, 'xl/worksheets/sheet1.xml');
    sheet.should.not.include('<f>');
    sheet.should.include('=HYPERLINK(&quot;bad&quot;)');
    zipEntry(buffer, 'xl/worksheets/_rels/sheet1.xml.rels').should.include('a%26b%22%3Cx%3E').and.not.include('a&b');
  });

  it('writes both sheets for an empty or offline dependency report without lookups', () => {
    const empty = renderComponentsXlsx({ rows: [], offline: true });
    zipEntry(empty, 'xl/worksheets/sheet1.xml').should.include('<autoFilter ref="A1:O1"/>').and.not.include('<hyperlinks>');
    zipEntry(empty, 'xl/worksheets/sheet2.xml').should.include('<autoFilter ref="A1:F1"/>');
    zipEntry(empty, 'xl/worksheets/_rels/sheet1.xml.rels').should.not.include('TargetMode');
    // nothing looked up: Unknown, listed in the catalog only
    const offline = componentTable({ offline: true, rows: [{ name: 'local', version: '1', kinds: ['lockfile'], support: { status: 'unknown' } }] });
    offline.rows.should.deep.equal([]);
    offline.catalog.should.deep.equal([['local', 'npm package', '1', 'Lockfile', '', 'No']]);
  });

  it('dispatches mixed outputs through the existing writer', () => {
    const dir = fs.mkdtempSync(path.join(process.cwd(), 'eng-client-'));
    try {
      const md = path.join(dir, 'findings.md');
      const xlsx = path.join(dir, 'components.xlsx');
      splitOutputs(`${md} ${xlsx}`).should.deep.equal([md, xlsx]);
      outputFormat(md).should.equal('md');
      outputFormat(xlsx).should.equal('xlsx');
      for (const output of [md, xlsx]) writeIssues(dir, false, output, [issue('NODE_INTEGRATION_JS_CHECK')], false,
        { app: { name: 'Example' }, outputs: [md, xlsx], dependencies: { rows: [] } });
      fs.existsSync(md).should.equal(false);
      // the .md asks for the reports folder: the findings and the components workbook they refer to
      fs.readFileSync(path.join(dir, 'reports', 'Insufficient Renderer Process Isolation.md'), 'utf8').should.include('# Insufficient Renderer Process Isolation');
      zipEntry(fs.readFileSync(path.join(dir, 'reports', 'components.xlsx')), 'xl/worksheets/sheet1.xml').should.include('Component');
      zipEntry(fs.readFileSync(xlsx), 'xl/worksheets/sheet1.xml').should.include('Component');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it('selects the scenarios a finding\'s own data supports', () => {
    const labels = (title, findings) => matchingVariations(title, findings, id => id.replace(/_(JS|HTML|JSON|GLOBAL|LOCK)_CHECK$/, '')).map(v => v.label);
    labels('Missing or Insufficient Content Security Policy', [issue('CSP_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { description: 'No CSP has been detected in the target application' })])
      .should.deep.equal(['No effective policy']);
    labels('Missing or Insufficient Content Security Policy', [issue('CSP_GLOBAL_CHECK', severity.LOW, confidence.CERTAIN, { description: 'One or more CSP directives detected are vulnerable' })])
      .should.deep.equal(['Unsafe script directives']);
    labels('Insecure Electron Fuse Configuration', [issue('PACKAGED_FUSES', severity.HIGH, confidence.CERTAIN, { properties: { fuse: 'RunAsNode', value: true } })])
      .should.deep.equal(['Local Node entry points']);
    labels('Hard-coded Secrets in the Application Package', [issue('HARDCODED_SECRET', severity.HIGH, confidence.FIRM, { properties: { kind: 'Stripe secret key' } })])
      .should.deep.equal(['Credential or token in code']);
    labels('Hard-coded Secrets in the Application Package', [issue('HARDCODED_SECRET', severity.HIGH, confidence.FIRM, { properties: { kind: 'Google API key' } })])
      .should.deep.equal(['Public key or false positive']);
    labels('Unvalidated URLs and Files Passed to the Operating System', [issue('OPEN_EXTERNAL_JS_CHECK', severity.LOW, confidence.CERTAIN, { properties: { value: 'http://example.com' } })])
      .should.deep.equal(['External URL or protocol']);
    labels('Unvalidated URLs and Files Passed to the Operating System', [issue('OPEN_EXTERNAL_JS_CHECK', severity.LOW, confidence.CERTAIN, { properties: { value: '\\\\server\\share' } })])
      .should.deep.equal(['External URL or protocol', 'Non-web protocol launch', 'Network-share credential exposure']);
    labels('Cross-Site Scripting in Content Rendering', [issue('RUNTIME_MARKER', severity.HIGH, confidence.CERTAIN, { properties: { live: true, executed: true } })])
      .should.not.include('Markup without proven execution');
    // a finding its data selects nothing for still gets its check's first scenario
    labels('Insecure Software Update Mechanism', [issue('UPDATE_SECURITY_JS_CHECK')]).should.deep.equal(['Update feed transport']);
    // one fallback scenario per unknown check, however many findings it has
    labels('Additional Security Observations', [issue('EXOTIC'), issue('EXOTIC', severity.LOW), issue('OTHER')]).should.deep.equal(['EXOTIC', 'OTHER']);
  });

  it('rates runtime settings by confidence and leaves accepted risks out of the rating', () => {
    ratingOf(issue('RUNTIME_NODE_INTEGRATION', severity.LOW, confidence.TENTATIVE), 'Insufficient Renderer Process Isolation').likelihood.should.equal('Unlikely');
    ratingOf(issue('RUNTIME_NODE_INTEGRATION', severity.LOW, confidence.TENTATIVE, { validation: { status: 'confirmed', text: 'ran' } }), 'Insufficient Renderer Process Isolation')
      .likelihood.should.equal('Very Likely');
    const [group] = groupClientFindings([issue('NODE_INTEGRATION_JS_CHECK', severity.LOW, confidence.TENTATIVE),
      issue('CONTEXT_ISOLATION_JS_CHECK', severity.HIGH, confidence.CERTAIN, { suppression: { reason: 'accepted' } })]);
    group.rating.should.deep.equal({ consequence: 'Low', likelihood: 'Unlikely' });
    group.basis.id.should.equal('NODE_INTEGRATION_JS_CHECK');
    const [onlyAccepted] = groupClientFindings([issue('CONTEXT_ISOLATION_JS_CHECK', severity.HIGH, confidence.CERTAIN, { suppression: { reason: 'accepted' } })]);
    onlyAccepted.accepted.should.equal(true);
    onlyAccepted.rating.consequence.should.equal('High');
  });

  it('shows paths relative to the scanned folder and keeps the home folder out', () => {
    const root = path.join(os.homedir(), 'engagements', 'acme', 'app');
    const markdown = renderClientMarkdown([issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH, confidence.CERTAIN, {
      file: path.join(root, 'src', 'main.js'), description: `Seen in ${path.join(root, 'src', 'main.js')} and ${path.join(os.homedir(), 'notes.txt')}`,
      properties: { screenshot: path.join(os.homedir(), 'shots', 'one.png') } })], { app: { name: 'Acme' }, root });
    markdown.should.include('`src/main.js:8`');
    markdown.should.not.include(os.homedir());
    // app text is Markdown-escaped, so a Windows backslash is written as \\ (it renders as one)
    const notes = renderTesterNotes([issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH, confidence.CERTAIN, {
      file: path.join(root, 'src', 'main.js'), description: `Seen in ${path.join(root, 'src', 'main.js')} and ${path.join(os.homedir(), 'notes.txt')}` })], { app: { name: 'Acme' }, root })[0].content;
    notes.should.not.include(os.homedir());
    notes.should.include(path.sep === '\\' ? '~\\\\notes.txt' : '~/notes.txt');
    notes.should.include('Seen in src/main.js');
  });

  it('escapes what the app supplies, cuts long code and keeps code out of the finding separators', () => {
    const markdown = renderClientMarkdown([
      issue('XSS_SINK_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/x/[a](javascript:alert(1)).js', description: '<img src=x onerror=alert(1)> **bold**',
        sample: `${'a'.repeat(5000)}\n---\nb: 2`, validation: { status: 'observed' } }),
    ], { app: { name: "<script>alert(1)</script> Evil$'App" } });
    markdown.should.not.match(/(^|[^\\])<(script|img)/m);
    markdown.should.include('\\<script\\>alert(1)\\</script\\> Evil$\'App');
    markdown.should.include('`/x/[a](javascript:alert(1)).js:8`');
    markdown.length.should.be.below(20000);
    markdown.should.include('characters are not shown');
    // one finding: its two YAML delimiters are the only lines that are exactly ---
    (markdown.match(/^---\s*$/gm) || []).length.should.equal(2);
    const front = YAML.parse(markdown.split(/^---\s*$/m)[1]);
    front.Title.should.equal('Cross-Site Scripting in Content Rendering');
  });

  it('lists only validated instances in the Cross-Site Scripting evidence, keeping the rest under Affected', () => {
    const notRun = issue('XSS_SINK_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/client/app/static-only.js', sample: 'el.innerHTML = notRunValue;' });
    const observed = issue('XSS_SINK_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/client/app/viewer.js', sample: 'el.innerHTML = seenValue;',
      validation: { status: 'observed', scope: 'data-flow', text: 'marker markup reached innerHTML' } });
    const inconclusive = issue('RUNTIME_CAMPAIGN_SCRIPT', severity.MEDIUM, confidence.FIRM, { file: 'https://app.test/editor', sample: '',
      description: 'Campaign payload delivered without an execution signal', validation: { status: 'inconclusive', scope: 'workflow', text: 'no execution signal' } });
    const [finding] = renderClientFindings([notRun, observed, inconclusive], { root: '/client/app', app: { name: 'Demo' } });
    const section = (heading) => finding.content.split(`## ${heading}\n`)[1].split(/^## /m)[0];
    const evidence = section('Reproduction and Evidence');
    evidence.should.include('viewer.js').and.include('seenValue').and.include('During testing, test markup reached innerHTML.');
    evidence.should.not.include('static-only.js').and.not.include('notRunValue').and.not.include('editor').and.not.include('execution signal');
    // the tester notes say what was left out, and keep it
    const [notes] = renderTesterNotes([notRun, observed, inconclusive], { root: '/client/app', app: { name: 'Demo' } });
    notes.content.should.include('2 instances were not validated at runtime, or had an inconclusive result').and.include('static-only.js').and.include('**inconclusive**');
    // still listed as affected, and in every other report
    section('Affected').should.include('static-only.js').and.include('app.test/editor');
    // a screenshot is runtime evidence: kept
    const pictured = { ...notRun, properties: { screenshot: '/client/app/shots/xss.png' } };
    renderClientFindings([pictured], { root: '/client/app', app: { name: 'Demo' } })[0].content.split('## Reproduction and Evidence\n')[1].should.include('static-only.js');
    // nothing validated: one sentence instead of the evidence
    const [none] = renderClientFindings([notRun], { root: '/client/app', app: { name: 'Demo' } });
    none.content.split('## Reproduction and Evidence\n')[1].should.include('No instance of this issue was validated at runtime during testing.');
    // other findings keep every instance
    const [other] = renderClientFindings([issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/client/app/static-only.js' })], { root: '/client/app', app: { name: 'Demo' } });
    other.content.split('## Reproduction and Evidence\n')[1].should.include('Open `static-only.js`');
  });

  it('says so when nothing is reportable', () => {
    renderClientMarkdown([], { app: { name: 'Example' } }).should.equal('No reportable findings were identified in Example.\n');
  });

  it('writes one file per finding, named after its title, into a reports folder', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-md-'));
    try {
      fs.mkdirSync(path.join(dir, 'reports'));
      fs.writeFileSync(path.join(dir, 'reports', 'Fixed Since.md'), '---\nTitle: Fixed Since\n---\n');
      // A legacy generated report is recognisable by its known title and six report sections.
      fs.writeFileSync(path.join(dir, 'reports', 'Debugging Features Enabled in Production.md'), renderClientMarkdown([issue('DEVTOOLS_JS_CHECK')]).replace('GeneratedBy: Electronegativity\n', ''));
      fs.writeFileSync(path.join(dir, 'reports', 'my notes.md'), 'kept');
      const files = writeClientMarkdown(dir, [issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH), issue('CSP_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { file: 'N/A' }),
        issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { properties: { advisories: ['OSV-1'] } })],
      { app: { name: 'Example' }, outputs: [path.join(dir, 'components.xlsx')] });
      files.map(f => path.basename(f)).sort().should.deep.equal(['Insufficient Renderer Process Isolation.md', 'Missing or Insufficient Content Security Policy.md', 'Outdated Software Components.md']);
      fs.readdirSync(path.join(dir, 'reports')).should.include('my notes.md').and.include('Fixed Since.md').and.not.include('Debugging Features Enabled in Production.md');
      for (const file of files) {
        const text = fs.readFileSync(file, 'utf8');
        (text.match(/^---$/gm) || []).length.should.equal(2);
        YAML.parse(text.split(/^---$/m)[1]).Title.should.equal(path.basename(file, '.md'));
      }
      fs.readFileSync(path.join(dir, 'reports', 'Outdated Software Components.md'), 'utf8').should.include('the attached spreadsheet (`components.xlsx`)');
      // the tester's notes for each finding, next to the client findings
      fs.readdirSync(path.join(dir, 'testerNotes')).sort().should.deep.equal(['How to Prepare Findings for Release.md', 'Insufficient Renderer Process Isolation - tester notes.md',
        'Missing or Insufficient Content Security Policy - tester notes.md', 'Outdated Software Components - tester notes.md']);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    findingFileName('A/B: C?').should.equal('A-B- C-.md');
    renderClientFindings([]).should.deep.equal([]);
  });

  it('combines the static scan and the watch sessions, each finding once', () => {
    const staticIssue = issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH);
    const withRuntime = { ...staticIssue, validation: { status: 'confirmed', text: 'the window ran with nodeIntegration' } };
    const runtime = issue('RUNTIME_NODE_INTEGRATION', severity.HIGH, confidence.CERTAIN, { file: 'app://index.html', sample: '' });
    const accepted = { ...issue('DEVTOOLS_JS_CHECK'), suppression: { reason: 'debug build' } };
    const { reported, suppressed } = combineRuns([
      { reported: [staticIssue, issue('DEVTOOLS_JS_CHECK')], suppressed: [] },
      { reported: [withRuntime, runtime], suppressed: [accepted] },
      { reported: [staticIssue, runtime], suppressed: [accepted] },
    ]);
    reported.map(i => i.id).should.deep.equal(['NODE_INTEGRATION_JS_CHECK', 'RUNTIME_NODE_INTEGRATION']);
    reported[0].validation.status.should.equal('confirmed');
    suppressed.map(i => i.id).should.deep.equal(['DEVTOOLS_JS_CHECK']);
    // static and runtime evidence of the same problem end up in one finding
    const findings = renderClientFindings(reported, { suppressed });
    const isolation = findings.find(f => f.title === 'Insufficient Renderer Process Isolation').content;
    isolation.should.include('During testing, the window ran with nodeIntegration.').and.include('`app://index.html:8`');
    renderTesterNotes(reported, { suppressed }).find(f => f.title === 'Insufficient Renderer Process Isolation').content
      .should.include('**RUNTIME_NODE_INTEGRATION**').and.include('**NODE_INTEGRATION_JS_CHECK**');
  });

  it('lists each reference as its title with the address on its own line', () => {
    const markdown = renderClientMarkdown([issue('SOURCE_MAP_SHIPPED', severity.INFORMATIONAL, confidence.CERTAIN, {
      sample: '', shortenedURL: 'https://developer.mozilla.org/en-US/docs/Glossary/Source_map' })]);
    markdown.slice(markdown.indexOf('## References')).should.equal([
      '## References', '',
      '- CWE-494: Download of Code Without Integrity Check', '', '  https://cwe.mitre.org/data/definitions/494.html', '',
      '- MDN Web Docs: Source map', '', '  https://developer.mozilla.org/en-US/docs/Glossary/Source_map', '',
      '- Electron security checklist', '', '  https://www.electronjs.org/docs/latest/tutorial/security', ''].join('\n'));
  });
});
