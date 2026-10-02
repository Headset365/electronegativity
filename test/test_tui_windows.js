/* eslint-disable no-control-regex -- Assertions verify the exact VT protocol bytes. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { Dashboard, TerminalInput, cleanText, launchWorker, runDashboard } from '../src/tui/dashboard.js';
import { createAssistant } from '../src/watch/assistant.js';
import { pipeAppOutput } from '../src/watch/launch.js';
import { textWidth } from '../src/tui/surface.js';

const { inspectBody } = createRequire(import.meta.url)('../src/watch/capture.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const record = (overrides = {}) => ({ kind: 'api', method: 'PUT', url: 'https://app.test/notes/42?token=private', status: 200,
  replay: 7, bodyFormat: 'json', fields: inspectBody('{"id":42,"body":"Hello","password":"secret"}').fields, ...overrides });
const model = () => {
  const answers = [];
  const ui = new Dashboard({ send: answer => answers.push(answer), close: () => {} });
  return { ui, answers };
};
function click(ui, id) {
  ui.render();
  const button = ui.controls.find(control => control.id === id);
  assert.ok(button, `control ${id} is visible`);
  ui.handle({ key: 'mouse', button: 0, x: button.x + 1, y: button.y });
}

describe('Windows PowerShell TUI', function () {
  this.timeout(60000);
  before(() => assert.equal(process.platform, 'win32', 'Run TUI tests on Windows only'));

  it('does not apply early, repeated or old Enter presses to a new prompt', () => {
    const { ui, answers } = model();
    ui.handle({ key: 'enter' });
    ui.receive({ type: 'prompt', id: 10, kind: 'session', question: 'Next session?' });
    ui.render(); ui.handle({ key: 'enter' });
    assert.equal(answers.length, 0);
    const oldEpoch = ui.epoch;
    click(ui, 'session-start');
    ui.receive({ type: 'prompt', id: 11, kind: 'confirm', question: 'Run campaign?' });
    ui.render(); ui.handle({ key: 'enter' }, oldEpoch); ui.handle({ key: 'enter' });
    assert.deepEqual(answers, [{ type: 'answer', id: 10, answer: 'start' }]);
    ui.handle({ key: 'tab' }); ui.handle({ key: 'enter' });
    assert.equal(answers[1].answer, undefined, 'confirmation initially selects Cancel');
  });

  it('uses clickable buttons and blocks a second campaign while one is being reviewed', () => {
    const { ui, answers } = model();
    ui.receive({ type: 'session-start', number: 1 }); ui.receive({ type: 'session-live' });
    for (const id of [1, 2]) ui.receive({ type: 'prompt', id, kind: 'campaign', key: `PUT /notes/${id}`, cases: 28, fields: ['body'] });
    click(ui, 'campaign:1'); click(ui, 'campaign:2');
    assert.deepEqual(answers, [{ type: 'answer', id: 1, answer: 'run' }]);
    assert.match(ui.notice, /Wait|pending|active|finish/i);
    ui.receive({ type: 'campaign', key: 'PUT /notes/1', status: 'completed' });
    click(ui, 'campaign:2'); assert.equal(answers.length, 2);
  });

  it('ignores mouse hit targets from a previous frame until the new prompt has been drawn', () => {
    const { ui, answers } = model();
    ui.receive({ type: 'prompt', id: 1, kind: 'confirm', question: 'First?' }); ui.render();
    const oldButton = ui.controls.find(control => control.id === 'approve');
    click(ui, 'approve');
    ui.receive({ type: 'prompt', id: 2, kind: 'confirm', question: 'Second?' });
    ui.handle({ key: 'mouse', button: 0, x: oldButton.x + 1, y: oldButton.y });
    assert.equal(answers.length, 1);
    click(ui, 'approve'); assert.equal(answers.length, 2);
  });

  it('expires offers and clears text input when the session closes', () => {
    const { ui, answers } = model();
    ui.receive({ type: 'session-start', number: 1 }); ui.receive({ type: 'session-live' });
    ui.receive({ type: 'prompt', id: 1, kind: 'campaign', key: 'PUT /notes', cases: 28 });
    ui.receive({ type: 'prompt', id: 2, kind: 'text', question: 'Fields?' });
    ui.focus = 'input'; ui.handle({ key: 'paste', text: 'body' });
    ui.receive({ type: 'cancel-prompt', id: 1 }); ui.receive({ type: 'cancel-prompt', id: 2 });
    ui.receive({ type: 'session-ended' });
    ui.receive({ type: 'prompt', id: 3, kind: 'session', question: 'Start next?' });
    ui.render(); ui.handle({ key: 'enter' });
    assert.equal(ui.input, ''); assert.equal(answers.length, 0);
    assert.equal(ui.campaigns.get('1:PUT /notes').status, 'expired');
  });

  it('keeps debug and app output separate from tool logs and validation, with bounded history', () => {
    const { ui } = model();
    ui.receive({ type: 'app-output', stream: 'stderr', text: '\x1b[2JApp debug\x1b]0;bad-title\x07' });
    ui.output('[validate] Ready'); ui.output('Scan started');
    assert.match(ui.logs['App output'][0], /App debug/);
    assert.deepEqual(ui.logs.Validation, ['[validate] Ready']);
    assert.deepEqual(ui.logs['Tool logs'], ['Scan started']);
    assert.ok(!ui.logs['App output'][0].includes('\x1b'));
    for (let n = 0; n < 2500; n++) ui.output(`Line ${n}`);
    assert.equal(ui.logs['Tool logs'].length, 2000);
    ui.scrollLog(10); assert.equal(ui.scroll.Validation, 1);
    assert.equal(cleanText('\x1b[31mhello\x1b[0m'), 'hello');
  });

  it('renders narrow and resized Windows terminals without losing controls or workflow state', () => {
    const { ui } = model(); ui.phase = 'Session running';
    assert.equal(ui.render(60, 12).length, 12);
    assert.match(ui.render(60, 12).join('\n'), /Resize Windows Terminal/);
    const lines = ui.render(80, 24);
    assert.equal(lines.length, 24); assert.ok(lines.every(line => textWidth(line) <= 79));
    for (const tab of ['Validation', 'App output', 'Tool logs', 'Findings']) assert.ok(ui.controls.some(control => control.id === `tab:${tab}`));
    assert.equal(ui.phase, 'Session running');
  });

  it('uses the entire styled button surface, ignores mouse motion, and isolates modal controls', () => {
    const { ui, answers } = model();
    ui.receive({ type: 'prompt', id: 1, kind: 'session', question: 'Next?' }); ui.render();
    const button = ui.controls.find(control => control.id === 'session-start');
    ui.handle({ key: 'mouse', button: 35, x: button.x + 1, y: button.y + 2 });
    assert.equal(answers.length, 0); assert.equal(ui.hover, 'session-start');
    ui.handle({ key: 'mouse', button: 0, x: 2, y: 2 }); assert.equal(answers.length, 0);
    assert.ok(!ui.controls.some(control => control.id.startsWith('tab:')));
    ui.handle({ key: 'mouse', button: 0, x: button.x + 1, y: button.y + 2 });
    assert.equal(answers[0].answer, 'start');
  });

  it('keeps long prompts readable by scrolling and keeps compact modal buttons in bounds', () => {
    const { ui } = model();
    ui.receive({ type: 'prompt', id: 1, kind: 'confirm', question: Array.from({ length: 40 }, (_, n) => `Evidence line ${n}`).join('\n') });
    const before = cleanText(ui.render(80, 24).join('\n'));
    ui.handle({ key: 'pagedown' });
    assert.ok(ui.promptScroll > 0); assert.notEqual(cleanText(ui.render(80, 24).join('\n')), before);
    for (const kind of ['session', 'text', 'confirm']) {
      ui.prompts = [{ id: 2, kind, question: 'Choose a value' }]; ui.transition();
      ui.render(80, 20);
      assert.ok(ui.controls.every(control => control.x >= 1 && control.x + control.width - 1 <= 79
        && control.y >= 1 && control.y + control.height - 1 <= 20));
      assert.ok(ui.controls.some(control => control.id === (kind === 'session' ? 'session-start' : kind === 'text' ? 'input' : 'approve')));
    }
  });

  it('keeps Unicode text, mouse coordinates and input focus correct across theme changes', () => {
    const { ui } = model();
    ui.target = 'C:\\应用\\Café 👩🏽‍💻';
    const initial = ui.render(120, 32).join('\n');
    assert.match(initial, /\x1b\[0;.*38;2;/);
    ui.handle({ key: 'text', text: 't' }); assert.equal(ui.themeIndex, 1);
    assert.notEqual(ui.render().join('\n'), initial);
    ui.receive({ type: 'prompt', id: 1, kind: 'text', question: 'Fields?' });
    ui.focus = 'input'; ui.handle({ key: 'text', text: 't' });
    assert.equal(ui.input, 't'); assert.equal(ui.themeIndex, 1);
    ui.input = '应用👩🏽‍💻'.repeat(100);
    assert.ok(ui.render(80, 24).every(line => textWidth(line) <= 79));
  });

  it('preserves split UTF-8 app output and partial lines without mixing stdout and stderr', async () => {
    const child = { stdout: new PassThrough(), stderr: new PassThrough() }, output = [];
    pipeAppOutput(child, (stream, text) => output.push({ stream, text }));
    const bytes = Buffer.from('café\n');
    child.stdout.write(bytes.subarray(0, 4)); child.stderr.write('debug');
    assert.equal(output.length, 0);
    child.stdout.end(bytes.subarray(4)); child.stderr.end(' done'); await tick();
    assert.deepEqual(output, [{ stream: 'stdout', text: 'café' }, { stream: 'stderr', text: 'debug done' }]);
  });

  it('parses fragmented mouse input, arrows, CRLF and bracketed paste without running pasted commands', () => {
    const parser = new TerminalInput();
    assert.deepEqual(parser.feed('\x1b[<0;'), []);
    assert.deepEqual(parser.feed('10;12M'), [{ key: 'mouse', button: 0, x: 10, y: 12, release: false }]);
    assert.deepEqual(parser.feed('\r\n'), [{ key: 'enter' }]);
    assert.deepEqual(parser.feed('\x1b[200~body\r\n'), []);
    assert.deepEqual(parser.feed('q\x1b[201~'), [{ key: 'paste', text: 'body  q' }]);
    assert.deepEqual(parser.feed('\x1b[A\x1b[Z'), [{ key: 'up' }, { key: 'backtab' }]);
  });

  it('collects multiple campaign offers without opening prompts, then executes only the selected offer', async () => {
    const offers = [], updates = [], commands = [], questions = [];
    const assistant = createAssistant({ marker: 'ENG_TUI_TEST', autoCampaign: true, scope: ['app.test'], print: () => {} });
    assistant.useChannel({ offer: details => new Promise(resolve => offers.push({ details, resolve })),
      onCampaign: state => updates.push(state), ask: async question => { questions.push(question); return ''; },
      confirm: async () => true, send: command => commands.push(command), cancel: () => offers.forEach(offer => offer.resolve(false)) });
    assistant.handle(record()); assistant.handle(record({ url: 'https://app.test/comments/2', replay: 8 }));
    assert.equal(offers.length, 2); assert.equal(questions.length, 0); assert.equal(commands.length, 0);
    assert.ok(!JSON.stringify(offers.map(offer => offer.details)).includes('secret'));
    offers[1].resolve(true); await tick();
    assert.equal(commands.length, 1); assert.equal(commands[0].replay, 8);
    assistant.handle({ kind: 'campaign-send', case: 'img-onerror', status: 200 });
    assert.match(updates.at(-1).reason, /1\/28 cases sent/);
    assistant.handle({ kind: 'campaign-done', cases: 28 });
    assert.equal(updates.at(-1).status, 'completed');
    offers[0].resolve(true); await tick(); assert.equal(commands.length, 2);
    assistant.clearChannel();
  });

  it('explains failed captures and out-of-scope campaigns and rejects stale offers', async () => {
    const updates = [], commands = []; let approve;
    const assistant = createAssistant({ marker: 'ENG_TUI_TEST', autoCampaign: true, scope: ['app.test'], print: () => {} });
    assistant.useChannel({ offer: () => new Promise(resolve => { approve = resolve; }), onCampaign: state => updates.push(state),
      ask: async () => '', confirm: async () => true, send: command => commands.push(command) });
    assistant.handle(record({ status: 403 })); assert.match(updates.at(-1).reason, /HTTP 403/);
    assistant.handle(record({ url: 'https://outside.test/save' })); assert.match(updates.at(-1).reason, /outside --scope/);
    assistant.handle(record()); assistant.clearChannel(); approve(true); await tick();
    assert.equal(commands.length, 0); assert.equal(updates.at(-1).status, 'expired');
  });

  it('restores raw mode and mouse/cursor state after dashboard completion or launch failure', async () => {
    for (const failure of [false, true]) {
      const input = new PassThrough(), output = new PassThrough();
      input.isTTY = true; input.isRaw = false; input.setRawMode = value => { input.isRaw = value; };
      output.isTTY = true; output.columns = 120; output.rows = 32;
      let screen = ''; output.on('data', chunk => { screen += chunk; });
      const launch = () => {
        if (failure) throw new Error('Cannot launch worker');
        const worker = new EventEmitter(); worker.stdout = new PassThrough(); worker.stderr = new PassThrough(); worker.connected = false;
        setImmediate(() => { worker.emit('exit', 0); input.write('q'); }); return worker;
      };
      if (failure) await assert.rejects(runDashboard([], { input, output, launch }), /Cannot launch/);
      else assert.equal((await runDashboard([], { input, output, launch })).code, 0);
      assert.equal(input.isRaw, false); assert.match(screen, /\x1b\[\?1006l/); assert.match(screen, /\x1b\[\?25h/);
    }
  });

  it('passes the guided PowerShell-style arguments to the real CLI worker and rejects stale prompt IDs', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-tui-command-'));
    const app = path.join(root, 'My App'); fs.mkdirSync(app);
    fs.writeFileSync(path.join(app, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0', main: 'main.js' }));
    fs.writeFileSync(path.join(app, 'main.js'), 'new BrowserWindow({ webPreferences: { nodeIntegration: true } });');
    const args = ['--tui', '--app', app, '-o', 'report.html', 'report.json', '--all-files', '--auto-campaign',
      '--user-data', 'auto', '--watch-screenshots', 'screenshots', '--remote', 'app.test', '--remote-header', 'Authorization: demo value',
      '--redact', 'My App,private', '--show-secrets', '--share-code', '--watch-marker', 'ENG_TUI_TEST', '--prove', '--offline', '--out', path.join(root, 'results'), '-l', 'NodeIntegrationJsCheck'];
    const worker = launchWorker(args), messages = []; let errors = '', replied = false;
    worker.stdout.resume(); worker.stderr.on('data', chunk => { errors += chunk; });
    try {
      const exited = new Promise(resolve => worker.once('exit', code => resolve(code)));
      worker.on('message', message => {
        messages.push(message);
        if (message.type === 'prompt' && message.kind === 'session' && !replied) {
          replied = true; worker.send({ type: 'answer', id: message.id + 100, answer: 'start' });
          setTimeout(() => worker.send({ type: 'answer', id: message.id, answer: 'finish' }), 100);
        }
      });
      assert.equal(await exited, 0, errors);
      assert.ok(messages.some(message => message.type === 'configuration' && message.target === app));
      assert.ok(messages.some(message => message.kind === 'session'), '--prove still offers manual review before the first session');
      assert.ok(!messages.some(message => message.type === 'session-start'), 'stale answer did not start an app');
      assert.ok(fs.existsSync(path.join(root, 'results', 'report.html')));
      assert.ok(fs.existsSync(path.join(root, 'results', 'report.json')));
    } finally { if (worker.connected) worker.disconnect(); worker.kill(); fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); }
  });

  it('accepts the flag and unquoted report list through Windows PowerShell', async () => {
    const script = "& '" + process.execPath.replaceAll("'", "''") + "' 'src/index.js' --tui --help -o report.html,report.json";
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { cwd: path.join(import.meta.dirname, '..'), windowsHide: true });
    let text = ''; child.stdout.on('data', chunk => { text += chunk; }); child.stderr.on('data', chunk => { text += chunk; });
    assert.equal(await new Promise(resolve => child.once('exit', resolve)), 0, text);
    assert.match(text, /--tui/);
  });
});
