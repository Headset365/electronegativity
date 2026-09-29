import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { should as chaiShould } from 'chai';
import YAML from 'yaml';
import { severity, confidence } from '../src/finder/attributes.js';
import { groupClientFindings, ratingOf, renderClientMarkdown } from '../src/report/markdown.js';
import { componentTable, renderComponentsXlsx } from '../src/report/xlsx.js';
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
    groups.length.should.equal(25);
    groups.find(g => g.definition[0] === 'Missing or Weak Content Security Policy').evidence.map(i => i.id).should.include('CSP_JS_CHECK');
    groups.some(g => g.definition[0] === 'Other Security Observations').should.equal(false);
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
      'Renderer Isolation Weakened', 'Missing or Weak Content Security Policy', 'Other Security Observations',
      'Application Code Not Protected Against Inspection or Tampering', 'Executable Signing and Exploit Mitigations (hardening)',
    ]);
    findings.slice(-2).every(g => g.rating.consequence === 'N/A' && g.rating.likelihood === 'N/A').should.equal(true);
    findings.find(g => g.definition[0] === 'Missing or Weak Content Security Policy').issues.length.should.equal(1);
  });

  it('uses paired N/A ratings, local route caps and confirmed execution', () => {
    ratingOf(issue('SOURCE_MAP_SHIPPED_GLOBAL_CHECK', severity.INFORMATIONAL), 'Application Code Not Protected Against Inspection or Tampering')
      .should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    ratingOf(issue('CODE_SIGNING_GLOBAL_CHECK', severity.LOW), 'Executable Signing and Exploit Mitigations (hardening)')
      .should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    ratingOf(issue('FUSES_GLOBAL_CHECK', severity.HIGH, confidence.CERTAIN), 'Insecure Electron Fuse Configuration')
      .should.deep.equal({ consequence: 'Medium', likelihood: 'Unlikely' });
    ratingOf(issue('END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity.MEDIUM), 'Outdated Third-Party Components')
      .should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    ratingOf(issue('RUNTIME_ACTIVE_SCRIPT', severity.MEDIUM, confidence.FIRM, { properties: { execution: 'observed' } }),
      'Cross-Site Scripting Exposure in Content Rendering').consequence.should.equal('Critical');
    ratingOf(issue('MALICIOUS_DEPENDENCY', severity.HIGH), 'Known Malicious Package').consequence.should.equal('Critical');
  });

  it('emits parseable YAML and unredacted evidence, accepted risks, references and a spreadsheet link', () => {
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
      front.Notes.should.be.an('array');
      (front.Consequence === 'N/A').should.equal(front.Likelihood === 'N/A');
    }
    findings.should.include('Client: Example #1');
    findings.should.include('/client/app/main.js:8');
    blocks.map(block => YAML.parse(block)).flatMap(front => front.Notes).join(' ').should.include('Approved: #42');
    findings.should.include('[components.xlsx](components.xlsx)');
    findings.should.include('https://cwe.mitre.org/data/definitions/');
    /^(?:\s*)\d+[.)]\s/m.test(findings).should.equal(false);
  });

  it('writes a valid workbook with only flagged rows, filter and frozen header', () => {
    const rows = [
      { name: 'current', version: '1.0.0', latest: '1.0.0', kinds: ['lockfile'], files: [], advisories: [], support: { status: 'supported' } },
      { name: 'old-dev', version: '1.0.0', latest: '2.0.0', kinds: ['lockfile'], files: ['package-lock.json'], versionsBehind: 1, majorsBehind: 1, advisories: [], support: { status: 'outdated' } },
      { name: 'malicious', version: '1.0.0', kinds: ['bundled library'], files: ['app.js'], advisories: [], malicious: { id: 'OSV-BAD' }, support: { status: 'unknown' } },
      { name: 'electron', version: '25.0.0', kinds: ['Electron runtime'], files: [], advisories: [{ id: 'OSV-1', severity: 'HIGH', cves: ['CVE-2026-1'], kev: true }], support: { status: 'unsupported' } },
    ];
    const table = componentTable({ rows });
    table.rows.map(r => r[0]).should.deep.equal(['malicious', 'electron', 'old-dev']);
    table.header.length.should.equal(19);
    const buffer = renderComponentsXlsx({ rows });
    const sheet = zipEntry(buffer, 'xl/worksheets/sheet1.xml');
    sheet.should.include('state="frozen"');
    sheet.should.include('<autoFilter ref="A1:S4"/>');
    sheet.should.include('CVE-2026-1');
    sheet.should.not.include('current');
    zipEntry(buffer, 'xl/workbook.xml').should.include('Outdated components');
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
      fs.readFileSync(md, 'utf8').should.include('Renderer Isolation Weakened');
      zipEntry(fs.readFileSync(xlsx), 'xl/worksheets/sheet1.xml').should.include('Component');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
