import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { should as chaiShould } from 'chai';
import YAML from 'yaml';
import { severity, confidence } from '../src/finder/attributes.js';
import { groupClientFindings, ratingOf, renderClientMarkdown, renderClientFindings, writeClientMarkdown, combineRuns, findingFileName } from '../src/report/markdown.js';
import { VARIATIONS, matchingVariations } from '../src/report/markdown_variations.js';
import { CLIENT_COPY } from '../src/report/markdown_client_copy.js';
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
    for (const group of groups) {
      const variants = matchingVariations(group.definition[0], group.issues, id => id.replace(/_(JS|HTML|JSON|GLOBAL|LOCK)_CHECK$/, ''));
      variants.length.should.be.greaterThan(0);
      for (const finding of group.issues) variants.some(v => v.issues.includes(finding)).should.equal(true);
      const one = renderClientMarkdown(group.issues, { app: { name: 'Example App' } });
      for (const heading of ['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References']) {
        const section = one.split(`## ${heading}\n`)[1].split(/^## /m)[0];
        for (const variant of variants) section.should.include(variant.label, `${group.definition[0]} ${heading} omitted ${variant.label}`);
      }
    }
    const markdown = renderClientMarkdown(checks.map(id => issue(id, severity.MEDIUM, confidence.FIRM, { sample: '' })), { app: { name: 'Example App' } });
    const headings = ['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References'];
    for (const heading of headings) (markdown.match(new RegExp(`^## ${heading}$`, 'gm')) || []).length.should.equal(25);
    for (const section of markdown.split(/^## (?:Issue Description|Affected|Implication|Reproduction and Evidence|Recommendations|References)$/m).slice(1))
      section.trim().length.should.be.greaterThan(0);
    markdown.should.include('Static observations identify code or configuration');
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
    ratingOf(issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', severity.MEDIUM), 'Outdated Third-Party Components')
      .should.deep.equal({ consequence: 'N/A', likelihood: 'N/A' });
    // an unsupported release line is rated like an unsupported Electron, advisories or not
    ratingOf(issue('END_OF_LIFE_LIBRARY_GLOBAL_CHECK', severity.MEDIUM), 'Outdated Third-Party Components')
      .should.deep.equal({ consequence: 'Medium', likelihood: 'Possible' });
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

  it('carries custom finding notes and recorded evidence into the appropriate sections', () => {
    const markdown = renderClientMarkdown([issue('OPEN_EXTERNAL_JS_CHECK', severity.HIGH, confidence.FIRM, {
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
    })], { app: { name: 'Client App' } });
    for (const value of ['The reviewed link comes from a document.', 'The client confirmed the operating system hand-off.',
      'A recipient can click the link.', 'Open a shared document.', 'Click the crafted link.', 'Observe the handler invocation.',
      'Allow only the approved host.', 'GET https://example.test/open?target=custom', '/evidence/hand-off.png',
      'Observed in the watch session.']) markdown.should.include(value);
    markdown.should.include('## Implication');
    markdown.should.include('## Reproduction and Evidence');
    markdown.should.include('## Recommendations');
  });

  it('explains global findings and highlights HTML remediation examples', () => {
    const markdown = renderClientMarkdown([
      issue('CSP_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { file: 'N/A', sample: '' }),
      issue('IFRAME_SANDBOX_HTML_CHECK', severity.MEDIUM, confidence.FIRM, { file: '/client/app/index.html', sample: '', manualReview: true }),
    ], { app: { name: 'Client App' } });
    markdown.should.include('Application-wide');
    markdown.should.include('**CSP_GLOBAL_CHECK** at Application-wide');
    markdown.should.match(/```html\n\s*<iframe/);
    markdown.should.include('- Embedded content (IFRAME_SANDBOX_HTML_CHECK)\n\n  https://');
    markdown.should.include('requires reachability or configuration review');
  });

  it('keeps several alternatives inside one finding and across all six sections', () => {
    const issues = [issue('OPEN_EXTERNAL_JS_CHECK'), issue('OPEN_PATH_JS_CHECK')];
    const markdown = renderClientMarkdown(issues, { app: { name: 'Client App' } });
    (markdown.match(/^# Unsafe Hand-off of URLs and Files to the Operating System$/gm) || []).length.should.equal(1);
    const sections = ['Issue Description', 'Affected', 'Implication', 'Reproduction and Evidence', 'Recommendations', 'References'];
    for (const label of ['External URL or protocol', 'File path handed to the host']) {
      for (const heading of sections) {
        const section = markdown.split(`## ${heading}\n`)[1].split(/^## /m)[0];
        section.should.include(label, `${heading} omitted ${label}`);
      }
    }
    markdown.should.include('The relevant boundary is whether a page, document or other external input can select the destination.');
    markdown.should.include('Confirm path validation using a harmless file');
    markdown.split('## Implication\n')[1].split('## Reproduction and Evidence')[0].should.not.include('Potential worst case');
    const fuseVariants = matchingVariations('Insecure Electron Fuse Configuration', [issue('PACKAGED_FUSES')], id => id);
    fuseVariants.length.should.equal(3);
  });

  it('groups every finding that can reach the client report under a named problem, never under Other', () => {
    const titleOf = (id, sev = severity.MEDIUM) => groupClientFindings([issue(id, sev)])[0]?.definition[0];
    titleOf('DYNAMIC_MODULE_JS_CHECK', severity.HIGH).should.equal('Code or Command Execution from Untrusted Data');
    titleOf('RUNTIME_MARKER_MODULE').should.equal('Code or Command Execution from Untrusted Data');
    for (const id of ['RUNTIME_CAMPAIGN_FS_READ', 'RUNTIME_CAMPAIGN_NODE', 'RUNTIME_CAMPAIGN_ELECTRON', 'PRELOAD_JS_CHECK']) titleOf(id).should.equal('Renderer Isolation Weakened', id);
    titleOf('RUNTIME_CAMPAIGN_EVAL', severity.LOW).should.equal('Missing or Weak Content Security Policy');
    titleOf('UNTRUSTED_LOAD_URL_JS_CHECK', severity.HIGH).should.equal('Insufficient Navigation and Window Controls');
    titleOf('CERTIFICATE_PINNING_GLOBAL_CHECK', severity.INFORMATIONAL).should.equal('Certificate Pinning Not Implemented (hardening)');
    titleOf('CERTIFICATE_VERIFY_PROC_JS_CHECK', severity.HIGH).should.equal('Insecure Transport and Certificate Validation');
    // the tool's own housekeeping is not a finding about the app
    groupClientFindings([issue('RUNTIME_CAMPAIGN_RESTORE'), issue('RUNTIME_CAMPAIGN_CLEANUP', severity.INFORMATIONAL)]).should.have.length(0);
    // a campaign's file read is runtime evidence: the payload's script ran and signalled it
    ratingOf(issue('RUNTIME_CAMPAIGN_FS_READ', severity.HIGH), 'Renderer Isolation Weakened').likelihood.should.equal('Very Likely');
    // "no pinning" is described as a hardening gap, not a validation bypass
    const pinning = renderClientMarkdown([issue('CERTIFICATE_PINNING_GLOBAL_CHECK', severity.INFORMATIONAL)], { app: { name: 'Demo' } });
    pinning.should.include('No certificate pinning').and.not.include('Certificate validation bypass');
  });

  it('lists the most severe instances first, so a cut-off list keeps the one that rates the finding', () => {
    const many = [...Array.from({ length: 13 }, (_, n) => issue('XSS_SINK_JS_CHECK', severity.LOW, confidence.FIRM, { file: `/app/low${n}.js` })),
      issue('XSS_SINK_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/app/high.js' })];
    const [finding] = renderClientFindings(many, { root: '/app', app: { name: 'Demo' } });
    const evidence = finding.content.split('## Reproduction and Evidence')[1];
    evidence.should.include('high.js');
    evidence.indexOf('high.js').should.be.below(evidence.indexOf('low0.js'));
  });

  it('defines several complete variants for every named group and falls back for new checks', () => {
    Object.keys(VARIATIONS).length.should.equal(26);
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
    matchingVariations('Other Security Observations', [issue('NEW_CHECK')], id => id).map(v => v.label).should.deep.equal(['NEW_CHECK']);
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
      fs.existsSync(md).should.equal(false);
      fs.readFileSync(path.join(dir, 'markdown', 'Renderer Isolation Weakened.md'), 'utf8').should.include('# Renderer Isolation Weakened');
      zipEntry(fs.readFileSync(xlsx), 'xl/worksheets/sheet1.xml').should.include('Component');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it('selects the scenarios a finding\'s own data supports', () => {
    const labels = (title, findings) => matchingVariations(title, findings, id => id.replace(/_(JS|HTML|JSON|GLOBAL|LOCK)_CHECK$/, '')).map(v => v.label);
    labels('Missing or Weak Content Security Policy', [issue('CSP_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { description: 'No CSP has been detected in the target application' })])
      .should.deep.equal(['No effective policy']);
    labels('Missing or Weak Content Security Policy', [issue('CSP_GLOBAL_CHECK', severity.LOW, confidence.CERTAIN, { description: 'One or more CSP directives detected are vulnerable' })])
      .should.deep.equal(['Unsafe script directives']);
    labels('Insecure Electron Fuse Configuration', [issue('PACKAGED_FUSES', severity.HIGH, confidence.CERTAIN, { properties: { fuse: 'RunAsNode', value: true } })])
      .should.deep.equal(['Local Node entry points']);
    labels('Hard-coded Secrets in the Application Package', [issue('HARDCODED_SECRET', severity.HIGH, confidence.FIRM, { properties: { kind: 'Stripe secret key' } })])
      .should.deep.equal(['Credential or token in code']);
    labels('Hard-coded Secrets in the Application Package', [issue('HARDCODED_SECRET', severity.HIGH, confidence.FIRM, { properties: { kind: 'Google API key' } })])
      .should.deep.equal(['Public key or false positive']);
    labels('Unsafe Hand-off of URLs and Files to the Operating System', [issue('OPEN_EXTERNAL_JS_CHECK', severity.LOW, confidence.CERTAIN, { properties: { value: 'http://example.com' } })])
      .should.deep.equal(['External URL or protocol']);
    labels('Unsafe Hand-off of URLs and Files to the Operating System', [issue('OPEN_EXTERNAL_JS_CHECK', severity.LOW, confidence.CERTAIN, { properties: { value: '\\\\server\\share' } })])
      .should.deep.equal(['External URL or protocol', 'Non-web protocol launch', 'Network-share credential exposure']);
    labels('Cross-Site Scripting Exposure in Content Rendering', [issue('RUNTIME_MARKER', severity.HIGH, confidence.CERTAIN, { properties: { live: true, executed: true } })])
      .should.not.include('Markup without proven execution');
    // a finding its data selects nothing for still gets its check's first scenario
    labels('Insecure Update Mechanism', [issue('UPDATE_SECURITY_JS_CHECK')]).should.deep.equal(['Update feed transport']);
    // one fallback scenario per unknown check, however many findings it has
    labels('Other Security Observations', [issue('EXOTIC'), issue('EXOTIC', severity.LOW), issue('OTHER')]).should.deep.equal(['EXOTIC', 'OTHER']);
  });

  it('rates runtime settings by confidence and leaves accepted risks out of the rating', () => {
    ratingOf(issue('RUNTIME_NODE_INTEGRATION', severity.LOW, confidence.TENTATIVE), 'Renderer Isolation Weakened').likelihood.should.equal('Unlikely');
    ratingOf(issue('RUNTIME_NODE_INTEGRATION', severity.LOW, confidence.TENTATIVE, { validation: { status: 'confirmed', text: 'ran' } }), 'Renderer Isolation Weakened')
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
    markdown.should.include(path.sep === '\\' ? '~\\\\notes.txt' : '~/notes.txt');
  });

  it('escapes what the app supplies, cuts long code and keeps code out of the finding separators', () => {
    const markdown = renderClientMarkdown([
      issue('XSS_SINK_JS_CHECK', severity.HIGH, confidence.FIRM, { file: '/x/[a](javascript:alert(1)).js', description: '<img src=x onerror=alert(1)> **bold**',
        sample: `${'a'.repeat(5000)}\n---\nb: 2` }),
    ], { app: { name: "<script>alert(1)</script> Evil$'App" } });
    markdown.should.not.match(/(^|[^\\])<(script|img)/m);
    markdown.should.include('\\<script\\>alert(1)\\</script\\> Evil$\'App');
    markdown.should.include('`/x/[a](javascript:alert(1)).js:8`');
    markdown.length.should.be.below(20000);
    markdown.should.include('more characters not shown');
    // one finding: its two YAML delimiters are the only lines that are exactly ---
    (markdown.match(/^---\s*$/gm) || []).length.should.equal(2);
    const front = YAML.parse(markdown.split(/^---\s*$/m)[1]);
    front.Title.should.equal('Cross-Site Scripting Exposure in Content Rendering');
  });

  it('says so when nothing is reportable', () => {
    renderClientMarkdown([], { app: { name: 'Example' } }).should.equal('No reportable findings were identified in Example.\n');
  });

  it('writes one file per finding, named after its title, into a markdown folder', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-md-'));
    try {
      fs.mkdirSync(path.join(dir, 'markdown'));
      fs.writeFileSync(path.join(dir, 'markdown', 'Fixed Since.md'), '---\nTitle: Fixed Since\n---\n');
      fs.writeFileSync(path.join(dir, 'markdown', 'my notes.md'), 'kept');
      const files = writeClientMarkdown(dir, [issue('NODE_INTEGRATION_JS_CHECK', severity.HIGH), issue('CSP_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { file: 'N/A' }),
        issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', severity.MEDIUM, confidence.CERTAIN, { properties: { advisories: ['OSV-1'] } })],
      { app: { name: 'Example' }, outputs: [path.join(dir, 'components.xlsx')] });
      files.map(f => path.basename(f)).sort().should.deep.equal(['Missing or Weak Content Security Policy.md', 'Outdated Third-Party Components.md', 'Renderer Isolation Weakened.md']);
      fs.readdirSync(path.join(dir, 'markdown')).should.include('my notes.md').and.not.include('Fixed Since.md');
      for (const file of files) {
        const text = fs.readFileSync(file, 'utf8');
        (text.match(/^---$/gm) || []).length.should.equal(2);
        YAML.parse(text.split(/^---$/m)[1]).Title.should.equal(path.basename(file, '.md'));
      }
      fs.readFileSync(path.join(dir, 'markdown', 'Outdated Third-Party Components.md'), 'utf8').should.include('[components.xlsx](../components.xlsx)');
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
    findings.find(f => f.title === 'Renderer Isolation Weakened').content.should.include('RUNTIME_NODE_INTEGRATION').and.include('**NODE_INTEGRATION_JS_CHECK**');
  });

  it('lists each reference as its title with the address on its own line', () => {
    const markdown = renderClientMarkdown([issue('SOURCE_MAP_SHIPPED', severity.INFORMATIONAL, confidence.CERTAIN, {
      sample: '', shortenedURL: 'https://developer.mozilla.org/en-US/docs/Glossary/Source_map' })]);
    markdown.slice(markdown.indexOf('## References')).should.equal([
      '## References', '',
      '- CWE-494: Download of Code Without Integrity Check', '', '  https://cwe.mitre.org/data/definitions/494.html', '',
      '- Source map exposure (SOURCE_MAP_SHIPPED)', '', '  https://developer.mozilla.org/en-US/docs/Glossary/Source_map', '',
      '- Electron security guidance', '', '  https://www.electronjs.org/docs/latest/tutorial/security', ''].join('\n'));
  });
});
