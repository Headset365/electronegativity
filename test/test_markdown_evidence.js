import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { severity, confidence } from '../src/finder/attributes.js';
import { recordValidation, validationResults } from '../src/finder/validation.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { reconcileRuntime } from '../src/watch/reconcile.js';
import { reconcileTraffic } from '../src/traffic/reconcile.js';
import { validationHint } from '../src/finder/consequences.js';
import { combineRuns, renderClientMarkdown, renderClientFindings, renderTesterNotes, ratingOf, writeClientMarkdown } from '../src/report/markdown.js';

const issue = (id, extra = {}) => ({ id, file: '/app/main.js', location: { line: 8, column: 0 },
  sample: '', description: `Review ${id}`, severity: severity.MEDIUM, confidence: confidence.FIRM, ...extra });
const send = extra => ({ kind: 'campaign-send', campaignId: 'run-1', case: 'event-handler', slot: 2,
  field: 'body', route: 'POST https://app.test/save', ok: true, status: 201, ...extra });
const event = (kind, extra) => ({ kind, campaignId: 'run-1', case: 'event-handler', slot: 2, ...extra });
// the client findings and the tester's notes: together they hold every recorded fact
const everything = (issues, meta) => `${renderClientMarkdown(issues, meta)}\n${renderTesterNotes(issues, meta).map(d => d.content).join('\n')}`;

describe('Markdown validation evidence', () => {
  it('retains confirmations, later inconclusive outcomes and screenshots across sessions without mutating inputs', () => {
    const first = issue('XSS_SINK_JS_CHECK', { session: 'first', properties: { evidence: ['first request'], screenshot: '/report/first.png' },
      validation: { status: 'confirmed', scope: 'execution', text: 'first execution' } });
    const later = issue('XSS_SINK_JS_CHECK', { session: 'later', properties: { evidence: ['later request'], screenshot: '/report/later.png' },
      validation: { status: 'inconclusive', scope: 'execution', text: 'not viewed later' } });
    const original = JSON.stringify([first, later]);
    const { reported } = combineRuns([{ reported: [first] }, { reported: [later] }, { reported: [later] }]);
    assert.equal(reported.length, 1);
    assert.equal(reported[0].validation.status, 'confirmed');
    assert.equal(validationResults(reported[0]).length, 2);
    const md = everything(reported);
    for (const value of ['first request', 'later request', 'first.png', 'later.png', 'first execution', 'not viewed later', 'session first', 'session later'])
      assert.ok(md.includes(value), value);
    assert.equal(JSON.stringify([first, later]), original);
  });

  it('keeps validation evidence when a finding becomes an accepted risk', () => {
    const confirmed = issue('OPEN_EXTERNAL_JS_CHECK', { validation: { status: 'confirmed', text: 'manual test recorded' } });
    const accepted = { ...issue('OPEN_EXTERNAL_JS_CHECK'), suppression: { reason: 'accepted by owner' } };
    const combined = combineRuns([{ reported: [confirmed] }, { suppressed: [accepted] }]);
    assert.equal(combined.reported.length, 0);
    assert.equal(combined.suppressed[0].validation.status, 'confirmed');
    assert.match(everything([], combined), /manual test recorded/);
  });

  it('retains every instance and every observation beyond the former display limits', () => {
    const issues = Array.from({ length: 20 }, (_, n) => issue('XSS_SINK_JS_CHECK', { file: `/app/view${n}.js`,
      properties: { evidence: [`proof-${n}`] }, validation: { status: 'observed', scope: 'data-flow', text: `marker-${n}` } }));
    const md = everything(issues);
    for (let n = 0; n < 20; n++) for (const value of [`view${n}.js`, `proof-${n}`, `marker-${n}`]) assert.ok(md.includes(value), value);
    const support = Array.from({ length: 11 }, (_, n) => issue('RUNTIME_MARKER_IPC', { severity: severity.INFORMATIONAL,
      description: `sender-${n}`, properties: { channel: 'open' } }));
    const ipc = everything([issue('IPC_FILE_ACCESS_JS_CHECK'), ...support]);
    for (let n = 0; n < 11; n++) assert.ok(ipc.includes(`sender-${n}`));
  });

  it('includes each check-specific validation instruction and labels instructions separately from results', () => {
    const ids = ['NODE_INTEGRATION_JS_CHECK', 'CONTEXT_ISOLATION_JS_CHECK', 'SANDBOX_JS_CHECK', 'PRELOAD_JS_CHECK', 'REMOTE_MODULE_JS_CHECK'];
    const md = everything(ids.map(id => issue(id)));
    assert.match(md, /## Validation steps/);
    for (const id of ids) if (validationHint(id)) assert.ok(md.includes(validationHint(id)), id);
    assert.match(md, /not run; static or artifact observation only/);
  });

  it('does not rate live markup or confirmed configuration as a confirmed exploit', () => {
    const marker = issue('RUNTIME_MARKER', { properties: { live: true } });
    assert.equal(ratingOf(marker, 'Cross-Site Scripting in Content Rendering').likelihood, 'Possible');
    const { issues } = analyzeWatchLog([{ kind: 'page', id: 1, url: 'https://app.test/', type: 'window', prefs: { contextIsolation: false } }]);
    const setting = issues.find(i => i.id === 'RUNTIME_CONTEXT_ISOLATION');
    assert.equal(setting.validation.scope, 'configuration');
    // an observed setting is certain, but not an exploit: at most Possible
    assert.equal(ratingOf(setting, 'Insufficient Renderer Process Isolation').likelihood, 'Possible');
    assert.match(everything(issues), /configuration, not exploitability/);
  });

  it('preserves campaign correlation, save read-back and actual execution page in the Markdown', () => {
    const { issues } = analyzeWatchLog([send(), event('campaign-verification', { verification: 'matched' }),
      event('campaign-view', { opened: true }), event('campaign-result', { signal: 'probe-started', url: 'https://wrong.test/' }),
      event('campaign-result', { signal: 'executed', url: 'https://app.test/view' })]);
    const execution = issues.find(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT');
    assert.equal(execution.file, 'https://app.test/view');
    assert.equal(execution.validation.scope, 'execution');
    assert.equal(ratingOf(execution, 'Cross-Site Scripting in Content Rendering').consequence, 'Medium');
    const md = everything(issues);
    for (const value of ['campaignId: run-1', 'field: body', 'slot: 2', 'savedValue: matched', 'view: opened', 'execution: observed', 'https://app.test/view'])
      assert.ok(md.includes(value), value);
    assert.match(md, /Account boundaries/);
    assert.ok(!md.includes('Source column: 0'));
  });

  for (const [name, records] of [
    ['accepted without execution', [send()]],
    ['execution in another campaign', [send(), event('campaign-result', { campaignId: 'other', signal: 'executed' })]],
    ['execution in another slot', [send(), event('campaign-result', { slot: 3, signal: 'executed' })]],
    ['ambiguous legacy sends', [send({ campaignId: undefined }), send({ campaignId: undefined }), event('campaign-result', { campaignId: undefined, signal: 'executed' })]],
    ['ambiguous campaign sends', [send(), send(), event('campaign-result', { signal: 'executed' })]],
    ['rejected request with an unrelated signal', [send({ ok: false, status: 403 }), event('campaign-result', { signal: 'executed' })]],
    ['unexpected execution signal in a resource case', [send({ case: 'external-image' }), event('campaign-result', { case: 'external-image', signal: 'executed' })]],
  ]) it(`records ${name} as inconclusive, without inventing confirmation`, () => {
    const { issues } = analyzeWatchLog(records);
    assert.ok(!issues.some(i => i.id === 'RUNTIME_CAMPAIGN_SCRIPT'));
    assert.ok(issues.filter(i => i.id === 'RUNTIME_CAMPAIGN_CASE').every(i => i.validation.status === 'inconclusive'));
    assert.ok(renderTesterNotes(issues).some(d => d.title === 'Validation Coverage and Test Outcomes'));
    assert.equal(renderClientFindings(issues).length, 0);
    assert.match(everything(issues), /inconclusive/);
  });

  it('shows a canary file-read signal with its field and limits its claimed scope', () => {
    const { issues } = analyzeWatchLog([send({ case: 'fs-read' }), event('campaign-result', { case: 'fs-read', signal: 'fs-read', url: 'https://app.test/view' })]);
    const read = issues.find(i => i.id === 'RUNTIME_CAMPAIGN_FS_READ');
    assert.equal(read.properties.field, 'body');
    assert.match(read.validation.text, /other files or accounts was not tested/);
    assert.match(everything(issues), /tool-owned file canary/);
  });

  it('does not accept a capability signal from a different probe type', () => {
    const { issues } = analyzeWatchLog([send(), event('campaign-result', { signal: 'fs-read' })]);
    assert.ok(!issues.some(i => i.id === 'RUNTIME_CAMPAIGN_FS_READ'));
  });

  it('keeps separate campaign sessions and slots from inheriting one another\'s proof', () => {
    const run = (id, slot, executed) => analyzeWatchLog([send({ campaignId: id, slot }),
      ...(executed ? [event('campaign-result', { campaignId: id, slot, signal: 'executed', url: 'https://app.test/view' })] : [])]).issues;
    const combined = combineRuns([{ reported: run('one', 1, true) }, { reported: run('two', 1, false) }, { reported: run('two', 2, false) }]);
    const cases = combined.reported.filter(i => i.id === 'RUNTIME_CAMPAIGN_CASE');
    assert.equal(cases.length, 3);
    assert.deepEqual(cases.map(i => i.validation.status), ['confirmed', 'inconclusive', 'inconclusive']);
  });

  it('keeps accepted DOCX cases, restoration failures and cleanup warnings visible without vulnerability findings', () => {
    const { issues } = analyzeWatchLog([
      { kind: 'docx-send', case: 'external-image', route: 'https://app.test/import', ok: true, status: 200, sha256: 'abc123', bytes: 4096 },
      { kind: 'campaign-restore', ok: false, status: 409 }, { kind: 'campaign-cleanup', ok: false, count: 1 },
    ]);
    assert.equal(renderClientFindings(issues).length, 0);
    const [coverage] = renderTesterNotes(issues);
    assert.match(coverage.content, /^<!-- Electronegativity tester notes/);
    assert.match(coverage.content, /# Validation Coverage and Test Outcomes/);
    for (const value of ['Acceptance does not prove conversion', 'sha256: abc123', 'bytes: 4096', 'HTTP 409', 'canaries']) assert.ok(coverage.content.includes(value), value);
  });

  it('shows CSP blocking as supporting evidence rather than a weak-policy finding', () => {
    const blocked = issue('RUNTIME_CSP_VIOLATION', { description: 'Policy blocked the probe', properties: { directive: 'script-src', blocked: 'inline' } });
    assert.equal(renderClientFindings([blocked]).length, 0);
    const md = everything([issue('CSP_GLOBAL_CHECK'), blocked]);
    assert.match(md, /Policy blocked the probe/);
    assert.match(md, /directive: script-src/);
  });

  it('links marker evidence to IPC argument/path checks without claiming missing authorization', () => {
    const checks = ['IPC_FILE_ACCESS_JS_CHECK', 'IPC_HANDLER_JS_CHECK', 'IPC_SENDER_VALIDATION_JS_CHECK']
      .map(id => issue(id, { properties: { channel: 'files:read' } }));
    const source = issue('RUNTIME_MARKER_IPC', { properties: { channel: 'files:read', sender: 'https://app.test/view' } });
    reconcileRuntime([...checks, source]);
    assert.equal(source.properties.staticFindings.length, 3);
    for (const check of checks) {
      assert.equal(check.validation.status, 'observed');
      assert.equal(check.validation.scope, 'data-flow');
      assert.match(check.validation.text, /remain unverified/);
      assert.match(check.validation.evidence[0], /RUNTIME_MARKER_IPC/);
    }
  });

  it('does not correlate scripts from different servers or ambiguous local path tails', () => {
    const sink = issue('RUNTIME_MARKER_SINK', { properties: { sink: 'innerHTML', frames: [{ url: 'https://a.test/js/app.js', line: 8, column: 1 }] } });
    const crossOrigin = issue('XSS_SINK_JS_CHECK', { file: 'https://b.test/js/app.js' });
    const a = issue('XSS_SINK_JS_CHECK', { file: '/one/js/app.js' });
    const b = issue('XSS_SINK_JS_CHECK', { file: '/two/js/app.js' });
    reconcileRuntime([crossOrigin, a, b, sink]);
    for (const check of [crossOrigin, a, b]) assert.equal(check.validation, undefined);
  });

  it('preserves distinct marker observations and their source references', () => {
    const check = issue('XSS_SINK_JS_CHECK', { file: 'https://app.test/js/app.js' });
    const sink = (method) => issue('RUNTIME_MARKER_SINK', { description: `marker at ${method}`, properties: { sink: method, frames: [{ url: check.file, line: 8, column: 1 }] } });
    reconcileRuntime([check, sink('innerHTML'), sink('insertAdjacentHTML')]);
    assert.equal(validationResults(check).length, 2);
    const md = everything([check]);
    assert.match(md, /insertAdjacentHTML/);
    assert.match(md, /Script execution and exploitability remain untested/);
  });

  it('limits traffic confirmation to observed transport and avoids claiming updater execution or a pinning bypass', () => {
    const http = issue('HTTP_RESOURCES_JS_CHECK', { sample: "win.loadURL('http://app.test/main')" });
    const updater = issue('UPDATE_SECURITY_JS_CHECK', { sample: "setFeedURL('https://app.test/feed')" });
    const pin = issue('CERTIFICATE_PINNING_GLOBAL_CHECK', { severity: severity.INFORMATIONAL });
    const traffic = issue('TRAFFIC_CLEARTEXT_HTTP', { properties: { host: 'app.test', evidence: ['GET http://app.test/other'] } });
    reconcileTraffic([http, updater, pin, traffic], { interceptedHttps: 2 });
    assert.equal(http.validation.scope, 'transport');
    assert.equal(updater.validation.status, 'observed');
    assert.equal(pin.validation.status, 'observed');
    assert.ok(traffic.properties.staticFindings.some(f => f.includes('UPDATE_SECURITY_JS_CHECK')));
    const md = everything([http, updater, pin, traffic]);
    assert.match(md, /updater workflow/);
    assert.match(md, /originating app, hosts and proxy certificate/);
    assert.ok(!md.includes('the application accepted a certificate issued by the proxy'));
    assert.equal(ratingOf(http, 'Insecure Network Transport and Certificate Validation').likelihood, 'Possible');
  });

  it('appends weaker traffic results instead of erasing independent confirmations', () => {
    const pin = issue('CERTIFICATE_PINNING_GLOBAL_CHECK');
    recordValidation(pin, { status: 'confirmed', scope: 'exploit', text: 'Independent authorized verification' });
    reconcileTraffic([pin], { interceptedHttps: 1 });
    assert.equal(pin.validation.status, 'confirmed');
    assert.equal(validationResults(pin).length, 2);
    assert.match(everything([pin]), /HTTPS exchanges in a proxy capture/);
  });

  it('renders binary, storage and advisory facts while escaping untrusted evidence', () => {
    const md = everything([
      issue('ASAR_INTEGRITY', { properties: { expected: 'aaa', actual: 'bbb', enforced: false } }),
      issue('CODE_SIGNING', { properties: { signer: 'Publisher', verifiedBy: 'os', status: 'HashMismatch' } }),
      issue('STORAGE_SECRET_AT_REST', { properties: { store: 'Local Storage', origin: 'https://app.test', basis: 'canary' } }),
      issue('DEPENDENCY_VULNERABILITIES_GLOBAL_CHECK', { properties: { package: 'fixture', version: '1', advisories: ['OSV-1', { id: 'OSV-2', cves: ['CVE-2026-1234'] }] } }),
      issue('XSS_SINK_JS_CHECK', { validation: { status: 'observed', text: '<script>evil()</script>', evidence: ['<img src=x> **fake**'] } }),
    ]);
    for (const value of ['expected: aaa', 'actual: bbb', 'enforced: false', 'verifiedBy: os', 'store: Local Storage', 'basis: canary']) assert.ok(md.includes(value), value);
    // advisories are listed in the components workbook, which the outdated components finding refers to
    assert.ok(md.includes('# Outdated Software Components') && md.includes('the attached spreadsheet (`components.xlsx`)'));
    assert.ok(!md.includes('<script>evil()'));
    assert.ok(!md.includes('<img src=x>'));
  });

  it('attaches all page screenshots to a sink finding located in its script', () => {
    const { issues } = analyzeWatchLog([
      { kind: 'sink', live: true, sink: 'innerHTML', url: 'https://app.test/view', frames: [{ url: 'https://app.test/app.js', line: 8, column: 3 }] },
      { kind: 'screenshot', url: 'https://app.test/view', file: '/report/before.png' },
      { kind: 'screenshot', url: 'https://app.test/view', file: '/report/after.png' },
    ]);
    const md = everything(issues);
    assert.match(md, /before.png/);
    assert.match(md, /after.png/);
    assert.match(md, /Stack frame: `https:\/\/app.test\/app.js:8:3`/);
  });

  it('links screenshots from sibling session folders inside the report root', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-md-evidence-'));
    try {
      const [file] = writeClientMarkdown(dir, [issue('XSS_SINK_JS_CHECK', { properties: { screenshot: path.join(dir, 'session', 'proof (1)#v2.png') } })]);
      assert.match(fs.readFileSync(file, 'utf8'), /\]\(\.\.\/session\/proof%20%281%29%23v2\.png\)/);
      const [again] = writeClientMarkdown(dir, [issue('XSS_SINK_JS_CHECK', { properties: { screenshot: path.join(dir + '-outside', 'proof.png') } })]);
      assert.ok(!fs.readFileSync(again, 'utf8').includes('](../'));
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('preserves user Markdown and checks collisions before removing stale reports', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-md-owned-'));
    try {
      const [prior] = writeClientMarkdown(dir, [issue('DEVTOOLS_JS_CHECK')]);
      const collision = path.join(dir, 'reports', 'Insufficient Renderer Process Isolation.md');
      fs.writeFileSync(collision, '---\nTitle: Insufficient Renderer Process Isolation\n---\nUser notes\n');
      assert.throws(() => writeClientMarkdown(dir, [issue('NODE_INTEGRATION_JS_CHECK')]), /Refusing to overwrite/);
      assert.ok(fs.existsSync(prior));
      assert.match(fs.readFileSync(collision, 'utf8'), /User notes/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('writes and removes only its own stale coverage document, with the tester notes', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-md-coverage-'));
    try {
      const { issues } = analyzeWatchLog([send()]);
      assert.deepEqual(writeClientMarkdown(dir, issues), []);
      // test outcomes are the tester's: next to the findings, in testerNotes
      const coverage = path.join(dir, 'testerNotes', 'Validation Coverage and Test Outcomes.md');
      assert.match(fs.readFileSync(coverage, 'utf8'), /test outcomes and coverage limitations/);
      fs.writeFileSync(path.join(dir, 'testerNotes', 'mine.md'), 'my own notes');
      writeClientMarkdown(dir, []);
      assert.ok(!fs.existsSync(coverage));
      assert.ok(fs.existsSync(path.join(dir, 'testerNotes', 'mine.md')));
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
