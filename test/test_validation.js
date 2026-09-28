import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { stripVTControlCharacters } from 'node:util';
import { should as chaiShould } from 'chai';
import _i18n from '../src/locales/i18n.js';
import { createAssistant, followLog, writeMarkerFiles, markerForms } from '../src/watch/assistant.js';
import { analyzeWatchLog } from '../src/watch/analyze.js';
import { reconcileRuntime } from '../src/watch/reconcile.js';
import { mapFrames, MANIFEST } from '../src/remote/sources.js';
import { validationHint } from '../src/finder/consequences.js';
import { renderHtmlReport } from '../src/util/report_html.js';
import { severity, confidence } from '../src/finder/attributes.js';

chaiShould();
await _i18n();

// hook.cjs runs no instrumentation when required outside Electron (its top guard is false), so its pure helpers can be tested
const { fillMarkerBody, canReplayBody } = createRequire(import.meta.url)('../src/watch/hook.cjs');

const M = 'ENGTEST01';
const strip = (text) => stripVTControlCharacters(text);
const assistantWith = (options = {}) => {
  const lines = [];
  const assistant = createAssistant({ marker: M, print: (line) => lines.push(strip(line)), ...options });
  return { assistant, lines };
};
const staticIssue = (id, file, line, extra = {}) => ({ id, file, location: { line, column: 4 }, manualReview: true, severity: severity.MEDIUM, confidence: confidence.TENTATIVE, description: id, ...extra });

describe('Validation assistant', () => {
  it('tailors its opening to what the static scan flagged for review', () => {
    const { assistant, lines } = assistantWith({ staticIssues: [staticIssue('XSS_SINK_JS_CHECK', 'app.js', 3), staticIssue('OPEN_EXTERNAL_JS_CHECK', 'main.js', 9), staticIssue('IPC_SENDER_VALIDATION_JS_CHECK', 'main.js', 20)] });
    assistant.intro();
    lines.join('\n').should.include(`<span data-${M}="1">${M}</span>`);
    lines.some(l => /1 place\(s\) that write data as HTML/.test(l)).should.equal(true);
    lines.some(l => l.includes(`https://example.invalid/${M}`) && /links and navigation/.test(l)).should.equal(true);
    lines.some(l => /event\.senderFrame/.test(l)).should.equal(true);
  });

  it('asks for a request to be sent again with the marker, then acknowledges it', () => {
    const { assistant, lines } = assistantWith();
    const api = (fields) => ({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/matters/12/documents/99', status: 200, fields });
    assistant.handle(api([{ name: 'title', html: false, marker: false }, { name: 'body', html: true, marker: false }]));
    assistant.handle(api([{ name: 'title', html: false, marker: false }, { name: 'body', html: true, marker: false }]));
    lines.should.have.length(1, 'asked once per endpoint');
    lines[0].should.equal(`[validate] → Saw PUT https://srv.test/api/matters/{id}/documents/{id} carrying HTML in: body; text in: title. Send it again with the marker: ${M} in the text fields and <span data-${M}="1">${M}</span> in body. Use the app (the editor's HTML/source view if it has one), or replay this request from your proxy.`);
    assistant.handle(api([{ name: 'title', html: false, marker: true }, { name: 'body', html: true, marker: true }]));
    lines[1].should.match(/^\[validate\] ✓ The marker was sent with PUT .* in: title, body \(as HTML in: body\)/);
    assistant.summary().some(i => i.status === 'done' && /title, body/.test(i.text)).should.equal(true);
    assistant.summary().some(i => i.status === 'todo' && /send PUT/.test(i.text)).should.equal(false);
  });

  it('offers to re-send a save request itself, and sends it on Y', async () => {
    const commands = [];
    const { assistant, lines } = assistantWith();
    assistant.useChannel({ confirm: async () => true, send: (command) => commands.push(command) });
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/matters/12/documents', status: 200, replay: 7,
      fields: [{ name: 'title', html: false, marker: false }, { name: 'body', html: true, marker: false }] });
    // the marker goes only into the HTML field (body), not the plain title
    lines[0].should.match(/I can re-send it for you, through the app's own session, with the marker in: body —/);
    await new Promise(resolve => setImmediate(resolve));
    commands.should.deep.equal([{ kind: 'send-marker', replay: 7, method: 'PUT', route: 'https://srv.test/api/matters/{id}/documents',
      fields: [{ name: 'body', html: true }] }]);
    lines.some(l => /Sending PUT .* with the marker/.test(l)).should.equal(true);
  });

  it('falls back to a manual instruction when the tester declines', async () => {
    const commands = [];
    const { assistant, lines } = assistantWith();
    assistant.useChannel({ confirm: async () => false, send: (command) => commands.push(command) });
    assistant.handle({ kind: 'api', method: 'POST', url: 'https://srv.test/api/notes', status: 201, replay: 1, fields: [{ name: 'text', html: true, marker: false }] });
    await new Promise(resolve => setImmediate(resolve));
    commands.should.have.length(0);
    lines.some(l => /Send it again with the marker/.test(l)).should.equal(true);
  });

  it('asks one question at a time and works through the queue', async () => {
    const commands = [];
    const gate = [];
    const { assistant, lines } = assistantWith();
    assistant.useChannel({ confirm: (q) => new Promise(resolve => gate.push({ q, resolve })), send: (c) => commands.push(c) });
    const api = (name, replay) => ({ kind: 'api', method: 'PUT', url: `https://srv.test/api/${name}`, status: 200, replay, fields: [{ name: 'body', html: true, marker: false }] });
    assistant.handle(api('a', 1));
    assistant.handle(api('b', 2));
    gate.should.have.length(1, 'only one question is open at first');
    gate[0].q.should.include('PUT https://srv.test/api/a');
    gate[0].resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    commands.should.deep.equal([{ kind: 'send-marker', replay: 1, method: 'PUT', route: 'https://srv.test/api/a', fields: [{ name: 'body', html: true }] }]);
    gate.should.have.length(2, 'the next question follows once the first is answered');
    gate[1].q.should.include('PUT https://srv.test/api/b');
    gate[1].resolve(false);
    await new Promise(resolve => setImmediate(resolve));
    commands.should.have.length(1, 'answering no sends nothing');
    lines.some(l => /Send it again with the marker/.test(l) && /api\/b/.test(l)).should.equal(true);
  });

  it('asks about a repeated endpoint only once', async () => {
    const gate = [];
    const { assistant } = assistantWith();
    assistant.useChannel({ confirm: (q) => new Promise(resolve => gate.push({ q, resolve })), send: () => {} });
    const rec = { kind: 'api', method: 'POST', url: 'https://srv.test/api/notes', status: 201, replay: 1, fields: [{ name: 'text', html: true, marker: false }] };
    assistant.handle(rec);
    assistant.handle(rec);
    gate.should.have.length(1);
    gate[0].resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    gate.should.have.length(1, 'the duplicate was never queued');
  });

  it('skips a queued endpoint that meanwhile carried the marker', async () => {
    const commands = [];
    const gate = [];
    const { assistant } = assistantWith();
    assistant.useChannel({ confirm: (q) => new Promise(resolve => gate.push({ q, resolve })), send: (c) => commands.push(c) });
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/a', status: 200, replay: 1, fields: [{ name: 'body', html: true, marker: false }] });
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/b', status: 200, replay: 2, fields: [{ name: 'body', html: true, marker: false }] });
    // b is sent some other way while a's question is open
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/b', status: 200, fields: [{ name: 'body', html: true, marker: true }] });
    gate[0].resolve(true);
    await new Promise(resolve => setImmediate(resolve));
    gate.should.have.length(1, 'b was skipped, not asked, because it already carried the marker');
    commands.should.deep.equal([{ kind: 'send-marker', replay: 1, method: 'PUT', route: 'https://srv.test/api/a', fields: [{ name: 'body', html: true }] }]);
  });

  it('prints the manual instructions for anything still queued when the session ends', () => {
    const gate = [];
    const { assistant, lines } = assistantWith();
    assistant.useChannel({ confirm: (q) => new Promise(resolve => gate.push({ q, resolve })), send: () => {} });
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/a', status: 200, replay: 1, fields: [{ name: 'body', html: true, marker: false }] });
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/b', status: 200, replay: 2, fields: [{ name: 'body', html: true, marker: false }] });
    assistant.clearChannel();
    lines.some(l => /Send it again with the marker/.test(l) && /api\/b/.test(l)).should.equal(true);
  });

  it('cancels an open question when the session ends, and falls back to manual for it', async () => {
    let reject;
    const { assistant, lines } = assistantWith();
    const confirm = () => new Promise((resolve, r) => { reject = r; });
    confirm.cancel = () => reject(new Error('cancelled'));
    assistant.useChannel({ confirm, send: () => {}, cancel: confirm.cancel });
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/a', status: 200, replay: 1, fields: [{ name: 'body', html: true, marker: false }] });
    lines.some(l => /Send it again with the marker/.test(l)).should.equal(false, 'the question is still open, no manual yet');
    assistant.clearChannel();
    await new Promise(resolve => setImmediate(resolve));
    lines.some(l => /Send it again with the marker/.test(l) && /api\/a/.test(l)).should.equal(true);
  });

  it('reports a request it re-sent itself, and does not announce the same one twice', () => {
    const { assistant, lines } = assistantWith();
    assistant.handle({ kind: 'marker-request', ok: true, status: 200, method: 'PUT', route: 'https://srv.test/api/matters/{id}/documents', fields: ['title', 'body'], html: ['body'] });
    lines[0].should.match(/^\[validate\] ✓ Sent PUT .* in: title, body \(as HTML in: body\) \(status 200\)/);
    // the same request, once observed carrying the marker, is not announced a second time
    assistant.handle({ kind: 'api', method: 'PUT', url: 'https://srv.test/api/matters/12/documents', status: 200, fields: [{ name: 'title', html: false, marker: true }, { name: 'body', html: true, marker: true }] });
    lines.should.have.length(1);
    assistant.summary().some(i => i.status === 'done' && /title, body/.test(i.text)).should.equal(true);
  });

  it('notes when it could not re-send a request', () => {
    const { assistant, lines } = assistantWith();
    assistant.handle({ kind: 'marker-request', ok: false, status: 403, method: 'POST', route: 'https://srv.test/api/notes' });
    lines[0].should.match(/couldn't send POST .* automatically \(status 403\)/);
  });

  it('ties an HTML sink hit to the static finding at that line', () => {
    const { assistant, lines } = assistantWith({ staticIssues: [staticIssue('XSS_SINK_JS_CHECK', 'https://srv.test/js/app.js', 120)] });
    assistant.handle({ kind: 'sink', sink: 'innerHTML', live: true, url: 'https://srv.test/', frames: [{ url: 'https://srv.test/js/app.js', line: 120, column: 17 }] });
    assistant.handle({ kind: 'sink', sink: 'innerHTML', live: false, url: 'https://srv.test/', frames: [{ url: 'https://srv.test/js/other.js', line: 5, column: 1 }] });
    lines.should.deep.equal(['[validate] ✗ Markup carrying the marker was written with innerHTML by https://srv.test/js/app.js:120:17: confirms XSS_SINK_JS_CHECK at https://srv.test/js/app.js:120.']);
  });

  it('suggests the next link to try, and reports what the app did with links from content', () => {
    const { assistant, lines } = assistantWith();
    assistant.handle({ kind: 'start', platform: 'win32' });
    assistant.handle({ kind: 'shell', method: 'openExternal', marker: true, scheme: 'https' });
    lines.pop().should.include(`file:///C:/Windows/#${M}`);
    assistant.handle({ kind: 'shell', method: 'openExternal', marker: true, scheme: 'file' });
    lines.pop().should.equal('[validate] ✗ A file: link from content was passed to the operating system by shell.openExternal: the app has no scheme allowlist.');
    assistant.handle({ kind: 'window-open', marker: true, action: 'allow', default: true });
    lines.pop().should.equal('[validate] ✗ A link from content opened a new app window (the app has no setWindowOpenHandler).');
    assistant.handle({ kind: 'will-navigate', marker: true, prevented: true, url: `https://example.invalid/${M}` });
    lines.pop().should.match(/✓ The app blocked the window/);
    assistant.handle({ kind: 'process', marker: true, program: 'cmd.exe', method: 'exec' });
    lines.pop().should.match(/✗ The marker reached a command the app runs \(cmd\.exe/);
    const summary = assistant.summary();
    summary.some(i => i.status === 'confirmed' && /no scheme allowlist/.test(i.text)).should.equal(true);
    summary.some(i => i.status === 'safe' && /navigation to the marker link was blocked/.test(i.text)).should.equal(true);
  });

  it('asks for formatted content after a plain-text paste', () => {
    const { assistant, lines } = assistantWith({ files: { page: '/out/ENGTEST01-paste-me.html', file: '/out/ENGTEST01.txt' } });
    assistant.handle({ kind: 'entry', detail: 'paste-text' });
    lines[0].should.equal('[validate] → You pasted plain text. Also paste formatted content: open /out/ENGTEST01-paste-me.html in a browser, select all, copy, and paste it here.');
    assistant.summary().some(i => i.status === 'todo' && /formatted/.test(i.text)).should.equal(true);
  });

  it('only points to --watch-marker when there is no marker', () => {
    const lines = [];
    const assistant = createAssistant({ print: (line) => lines.push(strip(line)) });
    assistant.intro();
    assistant.handle({ kind: 'shell', method: 'openExternal', marker: true, scheme: 'file' });
    lines.should.have.length(1);
    lines[0].should.match(/--watch-marker/);
  });

  it('writes the marker files: a page to copy formatted content from, and a file to attach', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-marker-'));
    const files = writeMarkerFiles(dir, M);
    fs.readFileSync(files.page, 'utf8').should.include(markerForms(M).html).and.include(`href="https://example.invalid/${M}"`);
    path.basename(files.file).should.equal(`${M}.txt`);
  });

  it('follows a log while it is being written', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-follow-'));
    const log = path.join(dir, 'session.jsonl');
    fs.writeFileSync(log, '');
    const seen = [];
    const stop = followLog(log, record => seen.push(record.kind), 20);
    fs.appendFileSync(log, '{"kind":"start"}\n{"kind":"ap');
    await new Promise(resolve => setTimeout(resolve, 60));
    fs.appendFileSync(log, 'i"}\n');
    stop();
    seen.should.deep.equal(['start', 'api']);
  });
});

describe('Marker evidence', () => {
  const records = [
    { kind: 'start' },
    { kind: 'sink', id: 1, url: 'https://srv.test/', sink: 'innerHTML', live: true, frames: [{ url: 'https://srv.test/js/app.js', line: 1, column: 50 }] },
    { kind: 'sink', id: 1, url: 'https://srv.test/', sink: 'innerHTML', live: false, frames: [{ url: 'https://srv.test/js/app.js', line: 9, column: 1 }] },
    { kind: 'api', method: 'POST', url: 'https://srv.test/api/notes', status: 201, fields: [{ name: 'text', html: true, marker: true }] },
    { kind: 'shell', method: 'openExternal', target: 'file:///C:/Windows/', marker: true, scheme: 'file' },
    { kind: 'shell', method: 'openPath', target: `C:\\Users\\me\\Downloads\\${M}.txt`, marker: true },
    { kind: 'will-navigate', id: 1, url: `https://example.invalid/${M}`, marker: true, prevented: false },
    { kind: 'window-open', id: 1, url: `https://example.invalid/${M}`, marker: true, action: 'deny' },
    { kind: 'ipc', channel: 'files:open', sender: 'https://srv.test/', args: ['string'], marker: true },
    { kind: 'process', method: 'exec', program: 'cmd.exe', marker: true },
  ];

  it('turns where the marker went into runtime findings', () => {
    const { issues } = analyzeWatchLog(records);
    const byId = (id) => issues.filter(i => i.id === id);
    byId('RUNTIME_MARKER_SINK').should.have.length(1, 'escaped text reaching innerHTML is not evidence');
    byId('RUNTIME_MARKER_SINK')[0].should.include({ file: 'https://srv.test/js/app.js' });
    byId('RUNTIME_MARKER_SINK')[0].location.should.deep.equal({ line: 1, column: 50 });
    byId('RUNTIME_MARKER_SENT')[0].properties.fields.should.deep.equal(['text']);
    byId('RUNTIME_MARKER_OPEN_EXTERNAL')[0].severity.should.equal(severity.HIGH);
    byId('RUNTIME_MARKER_OPEN_PATH').should.have.length(1);
    byId('RUNTIME_MARKER_NAVIGATION')[0].properties.blocked.should.equal(false);
    byId('RUNTIME_MARKER_NEW_WINDOW')[0].properties.blocked.should.equal(true);
    byId('RUNTIME_MARKER_IPC')[0].properties.channel.should.equal('files:open');
    byId('RUNTIME_MARKER_COMMAND')[0].properties.program.should.equal('cmd.exe');
  });

  it('confirms or rules out the static findings that need review', () => {
    const { issues: runtime } = analyzeWatchLog([...records, { kind: 'page', id: 1, type: 'window', url: 'https://srv.test/', prefs: {} }]);
    const issues = [
      staticIssue('XSS_SINK_JS_CHECK', 'https://srv.test/js/app.js', 1),
      staticIssue('XSS_SINK_JS_CHECK', 'https://srv.test/js/app.js', 30),
      staticIssue('OPEN_EXTERNAL_JS_CHECK', 'main.js', 9),
      staticIssue('OPEN_PATH_JS_CHECK', 'main.js', 12),
      staticIssue('LIMIT_NAVIGATION_JS_CHECK', 'main.js', 3),
      staticIssue('WINDOW_OPEN_HANDLER_JS_CHECK', 'main.js', 4),
      staticIssue('COMMAND_INJECTION_JS_CHECK', 'main.js', 40),
      staticIssue('IPC_SENDER_VALIDATION_JS_CHECK', 'main.js', 50, { properties: { channel: 'files:open' } }),
      staticIssue('IPC_SENDER_VALIDATION_JS_CHECK', 'main.js', 60, { properties: { channel: 'settings:get' } }),
      ...runtime,
    ];
    reconcileRuntime(issues, {});
    const status = issues.slice(0, 9).map(i => i.validation && i.validation.status);
    status.should.deep.equal(['confirmed', undefined, 'confirmed', 'confirmed', 'confirmed', 'safe', 'confirmed', 'observed', undefined]);
    issues[0].validation.text.should.match(/written with innerHTML from this line \(https:\/\/srv\.test\/js\/app\.js:1:50\)/);
  });

  it('maps a minified stack frame to the original source the scan reported on', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-frames-'));
    // one generated line whose column 40 comes from line 3 of src/viewer.js
    fs.writeFileSync(path.join(dir, 'app.js.map'), JSON.stringify({ version: 3, sources: ['webpack://app/./src/viewer.js'], names: [], mappings: 'AAAA,wCAEA' }));
    fs.writeFileSync(path.join(dir, MANIFEST), JSON.stringify({ kind: 'map', url: 'https://srv.test/app.js.map', of: 'https://srv.test/app.js', file: 'app.js.map' }) + '\n');
    const frames = mapFrames(dir, [{ url: 'https://srv.test/app.js', line: 1, column: 45 }, { url: 'https://srv.test/other.js', line: 1, column: 1 }]);
    frames[0].original.should.deep.equal({ file: 'https://srv.test/app.js (source: src/viewer.js)', line: 3, column: 1 });
    (frames[1].original === undefined).should.equal(true);
  });
});

describe('Marker request body', () => {
  it('puts the marker into the named JSON fields and leaves the others intact', () => {
    const out = fillMarkerBody(JSON.stringify({ title: 'hi', body: '<p>x</p>', keep: 'me', n: 5 }), M, [{ name: 'title', html: false }, { name: 'body', html: true }]);
    out.contentType.should.equal('application/json');
    const parsed = JSON.parse(out.body);
    parsed.title.should.equal(M);
    parsed.body.should.equal(markerForms(M).html);
    parsed.keep.should.equal('me');
    parsed.n.should.equal(5);
  });

  it('reaches nested and array fields by the names the body inspection reports', () => {
    const out = fillMarkerBody(JSON.stringify({ doc: { blocks: [{ text: 'a' }, { text: 'b' }] } }), M, [{ name: 'doc.blocks[].text', html: false }]);
    JSON.parse(out.body).doc.blocks.map(b => b.text).should.deep.equal([M, M]);
  });

  it('keeps large integer ids and number formatting byte-for-byte (no JSON round-trip)', () => {
    const original = '{"id":1234567890123456789,"count":10,"active":true,"ratio":1.50,"body":"<p>x</p>"}';
    const out = fillMarkerBody(original, M, [{ name: 'body', html: true }]);
    out.contentType.should.equal('application/json');
    // only body changed; the 19-digit id, the boolean and the 1.50 formatting are untouched (JSON.parse would break them)
    out.body.should.equal(`{"id":1234567890123456789,"count":10,"active":true,"ratio":1.50,"body":${JSON.stringify(markerForms(M).html)}}`);
  });

  it('preserves surrounding whitespace and only rewrites the target string', () => {
    const original = '{\n  "title": "hi",\n  "body": "old"\n}';
    const out = fillMarkerBody(original, M, [{ name: 'body', html: false }]);
    out.body.should.equal(`{\n  "title": "hi",\n  "body": ${JSON.stringify(M)}\n}`);
  });

  it('fills urlencoded fields', () => {
    const out = fillMarkerBody('title=hi&body=x', M, [{ name: 'body', html: false }]);
    out.contentType.should.equal('application/x-www-form-urlencoded');
    const parsed = new URLSearchParams(out.body);
    parsed.get('body').should.equal(M);
    parsed.get('title').should.equal('hi');
  });

  it('returns null for a multipart body, or when none of the named fields are present', () => {
    (fillMarkerBody('------x\r\nContent-Disposition: form-data; name="f"\r\n\r\nv\r\n------x--', M, [{ name: 'f', html: false }]) === null).should.equal(true);
    (fillMarkerBody(JSON.stringify({ a: 1 }), M, [{ name: 'missing', html: false }]) === null).should.equal(true);
    (fillMarkerBody('{"a":1}', M, []) === null).should.equal(true);
  });

  it('canReplayBody accepts JSON and urlencoded bodies, not multipart', () => {
    canReplayBody('{"title":"x"}').should.equal(true);
    canReplayBody('a=1&b=2').should.equal(true);
    canReplayBody('------x\r\nContent-Disposition: form-data; name="f"').should.equal(false);
  });
});

describe('Validation in the report', () => {
  const meta = { version: '2.0.0', input: '/app', electronVersion: '34.5.8', filesScanned: 1, atomicChecks: 1, globalChecks: 1, generatedAt: 'now', errors: [] };
  const issue = (overrides) => ({ id: 'XSS_SINK_JS_CHECK', file: 'app.js', location: { line: 3, column: 2 }, sample: 'el.innerHTML = x', description: 'd',
    severity: severity.MEDIUM, confidence: confidence.TENTATIVE, manualReview: true, shortenedURL: 'https://example.com', ...overrides });

  it('shows runtime results, or how to validate a finding that needs review', () => {
    const html = renderHtmlReport([
      issue({ validation: { status: 'confirmed', text: 'Confirmed at runtime: markup reached this line.' } }),
      issue({ id: 'IPC_SENDER_VALIDATION_JS_CHECK' }),
      issue({ id: 'DEVTOOLS_JS_CHECK' }),
    ], meta);
    html.should.include('<div class="validation v-confirmed"><b>Confirmed at runtime</b> markup reached this line.</div>');
    html.should.include('data-validation="confirmed"');
    html.should.include('data-validation="open"');
    html.should.include('<summary>How to validate</summary><div>Manual: read the handler and check that it verifies event.senderFrame');
    html.should.include('id="validation"');
  });

  it('has a validation hint for every check that commonly needs review', () => {
    for (const id of ['XSS_SINK_JS_CHECK', 'OPEN_EXTERNAL_JS_CHECK', 'OPEN_PATH_JS_CHECK', 'LIMIT_NAVIGATION_JS_CHECK', 'RUNTIME_NAVIGATION', 'IPC_SENDER_VALIDATION_JS_CHECK',
      'DEVTOOLS_JS_CHECK', 'WRITE_SHORTCUT_JS_CHECK', 'COMMAND_INJECTION_JS_CHECK', 'RICH_TEXT_EDITOR_JS_CHECK', 'RUNTIME_HTML_ENDPOINT', 'PACKAGED_FUSES'])
      validationHint(id).should.be.a('string', id);
  });
});

describe('Findings grouped by type', () => {
  const meta = { version: '2.0.0', input: '/app', electronVersion: '34.5.8', filesScanned: 1, atomicChecks: 1, globalChecks: 1, generatedAt: 'now', errors: [] };
  const finding = (overrides) => ({ id: 'XSS_SINK_JS_CHECK', file: 'app.js', location: { line: 3, column: 2 }, sample: '', description: 'HTML is built from dynamic data',
    severity: severity.MEDIUM, confidence: confidence.FIRM, manualReview: true, shortenedURL: 'https://example.com', ...overrides });

  it('shows each type once with what it is, its implication, its impact and where it was found', () => {
    const html = renderHtmlReport([
      finding(), finding({ file: 'b.js', validation: { status: 'confirmed', text: 'Confirmed at runtime: x' } }),
      finding({ id: 'DEVTOOLS_JS_CHECK', severity: severity.LOW, description: 'DevTools can be opened' }),
    ], meta);
    html.should.include('Findings by type (2)');
    const card = html.slice(html.indexOf('<details class="group"'), html.indexOf('</details>', html.indexOf('<details class="group"')));
    card.should.include('XSS_SINK_JS_CHECK').and.include('×2').and.include('1 confirmed at runtime').and.include('1 to review');
    card.should.include('<dt>What it is</dt>').and.include('<dt>Implication</dt>').and.include('<dt>Impact</dt>').and.include('Worst case:');
    card.should.include('Reachable without access to the device');
    card.should.include('data-check="XSS_SINK_JS_CHECK"');
    // the most severe, content-reachable types come first
    html.indexOf('<span class="gid">XSS_SINK_JS_CHECK</span>').should.be.below(html.indexOf('<span class="gid">DEVTOOLS_JS_CHECK</span>'));
  });
});
