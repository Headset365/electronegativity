/* eslint-disable no-control-regex -- VT keyboard/mouse protocols and terminal sanitization require control bytes. */
import { fork, spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { stripVTControlCharacters } from 'node:util';
import { wrapText, THEMES } from './surface.js';
import { renderDashboard } from './view.js';

const ENTER_SCREEN = '\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1003h\x1b[?1006h\x1b[?2004h';
const LEAVE_SCREEN = '\x1b[0m\x1b[?2004l\x1b[?1006l\x1b[?1003l\x1b[?1000l\x1b[?25h\x1b[?1049l';
const MAX_LINES = 2000;
const TABS = ['Validation', 'App output', 'Tool logs', 'Findings'];
// Child output cannot move the cursor, set a title, or enable terminal modes in the dashboard.
export const cleanText = value => stripVTControlCharacters(String(value ?? '')).replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');
/** Incremental VT input parser: pasted newlines and fragmented mouse sequences never become actions. */
export class TerminalInput {
  buffer = '';
  skipLF = false;
  feed(text, escapeTimeout = false) {
    this.buffer += text;
    const events = [];
    while (this.buffer) {
      if (this.buffer.startsWith('\x1b[200~')) {
        const end = this.buffer.indexOf('\x1b[201~', 6);
        if (end < 0) { if (this.buffer.length > 16384) this.buffer = ''; break; }
        events.push({ key: 'paste', text: cleanText(this.buffer.slice(6, end)).slice(0, 4096) });
        this.buffer = this.buffer.slice(end + 6); continue;
      }
      if (this.buffer[0] === '\x1b') {
        const mouse = /^\x1b\[<(\d+);(\d+);(\d+)([Mm])/.exec(this.buffer);
        if (mouse) {
          events.push({ key: 'mouse', button: Number(mouse[1]), x: Number(mouse[2]), y: Number(mouse[3]), release: mouse[4] === 'm' });
          this.buffer = this.buffer.slice(mouse[0].length); continue;
        }
        const sequence = /^\x1b(?:\[[\d;?]*[A-Za-z~]|O[A-Z])/.exec(this.buffer);
        if (sequence) {
          const names = { '\x1b[A': 'up', '\x1b[B': 'down', '\x1b[C': 'right', '\x1b[D': 'left', '\x1b[Z': 'backtab', '\x1b[5~': 'pageup', '\x1b[6~': 'pagedown', '\x1b[H': 'home', '\x1b[F': 'end' };
          events.push({ key: names[sequence[0]] || 'ignored' });
          this.buffer = this.buffer.slice(sequence[0].length); continue;
        }
        if (!escapeTimeout && (this.buffer.length === 1 || /^\x1b\[/.test(this.buffer))) break;
        // Discard a whole incomplete escape sequence, never treat its tail as typed commands.
        events.push({ key: 'escape' }); this.buffer = ''; break;
      }
      const char = String.fromCodePoint(this.buffer.codePointAt(0));
      this.buffer = this.buffer.slice(char.length);
      if (char === '\n' && this.skipLF) { this.skipLF = false; continue; }
      this.skipLF = char === '\r';
      const names = { '\r': 'enter', '\n': 'enter', '\t': 'tab', '\x7f': 'backspace', '\b': 'backspace', '\x03': 'interrupt' };
      if (names[char]) events.push({ key: names[char] });
      else if (!/[\x00-\x1f\x7f-\x9f]/.test(char)) events.push({ key: 'text', text: char });
    }
    return events;
  }
}

export class Dashboard {
  constructor({ send, close, openFolder = () => {} }) {
    this.send = send; this.close = close; this.openFolder = openFolder;
    this.phase = 'Starting CLI worker…'; this.session = 0; this.live = false; this.finished = false;
    this.logs = Object.fromEntries(TABS.map(tab => [tab, []]));
    this.scroll = Object.fromEntries(TABS.map(tab => [tab, 0]));
    this.logWidths = {}; this.logCounts = {}; this.campaignScroll = 0;
    this.campaigns = new Map(); this.sessions = []; this.prompts = []; this.offers = new Map();
    this.activeCampaign = false; this.tab = TABS[0]; this.focus = undefined; this.epoch = 0;
    this.controls = []; this.input = ''; this.notice = 'Tab or click to select a control. Enter acts only on that control.';
    this.themeIndex = 0; this.promptScroll = 0; this.promptPage = 1; this.hover = undefined;
  }
  log(tab, text) {
    const lines = this.logs[tab];
    for (const line of String(text).split(/\r?\n|\r/)) if (line) {
      const value = cleanText(line).slice(0, 4096);
      lines.push(value);
      if (this.scroll[tab] > 0) this.scroll[tab] += wrapText(value, this.logWidths[tab] || 75).length;
    }
    if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
  }
  transition() { this.epoch++; this.focus = undefined; this.hover = undefined; this.input = ''; this.controls = []; this.promptScroll = 0; }
  get prompt() { return this.localPrompt || this.prompts[0]; }
  receive(message) {
    switch (message.type) {
      case 'configuration':
        this.target = message.target; this.mode = message.mode;
        this.campaignEnabled = message.autoCampaign || message.campaign;
        this.log('Validation', message.autoCampaign ? 'Save a disposable record in the app. Eligible saves appear under Campaigns; select one to review its fields and view.' : 'Session guidance and validation results appear here.');
        break;
      case 'phase': this.phase = message.text; break;
      case 'results-folder': this.folder = message.folder; break;
      case 'session-start':
        this.session = message.number || this.session + 1; this.phase = `Starting session ${this.session}…`;
        this.sessions.push({ number: this.session, state: 'Starting' }); break;
      case 'session-live':
        this.live = true; this.connection = 'waiting for observer'; this.phase = `Session ${this.session || 1}: app running; waiting for observer…`;
        if (this.sessions.length) this.sessions.at(-1).state = 'Observing'; break;
      case 'observer-ready':
        this.connection = 'connected'; this.phase = `Session ${this.session || 1}: observer connected${message.electron ? ` (Electron ${message.electron})` : ''}`; break;
      case 'session-ended':
        this.live = false; this.connection = 'disconnected'; this.activeCampaign = false; this.localPrompt = undefined;
        if (this.sessions.length) this.sessions.at(-1).state = 'Ended';
        for (const item of this.campaigns.values()) if (['ready', 'reviewing', 'running', 'waiting'].includes(item.status)) {
          item.status = item.status === 'running' ? 'incomplete' : 'expired'; item.reason = 'Session ended; its captured requests can no longer be run.';
        }
        this.transition(); break;
      case 'campaign': {
        const key = `${this.session}:${message.key}`;
        const previous = this.campaigns.get(key);
        this.campaigns.set(key, { ...this.campaigns.get(key), ...message, session: this.session });
        if (previous?.status !== message.status && ['ready', 'completed', 'error', 'unavailable', 'declined'].includes(message.status))
          this.log('Validation', `Campaign ${message.key}: ${message.status}. ${message.reason || `${message.cases || '?'} cases; fields: ${(message.fields || []).join(', ')}`}`);
        if (['reviewing', 'running'].includes(message.status)) this.activeCampaign = true;
        if (['completed', 'declined', 'error', 'incomplete'].includes(message.status)) this.activeCampaign = false;
        // Keep the visible history bounded during long sessions.
        if (this.campaigns.size > 100) this.campaigns.delete(this.campaigns.keys().next().value);
        break;
      }
      case 'prompt':
        if (message.kind === 'campaign') {
          this.offers.set(message.id, message);
          this.receive({ ...message, type: 'campaign', status: 'ready' });
        } else { this.prompts.push(message); if (this.prompts.length === 1) this.transition(); }
        break;
      case 'cancel-prompt':
        this.offers.delete(message.id);
        if (this.prompts[0]?.id === message.id) this.transition();
        this.prompts = this.prompts.filter(prompt => prompt.id !== message.id); break;
      case 'app-output': this.log('App output', `[${message.stream}] ${message.text}`); break;
      case 'findings':
        this.counts = message.counts;
        for (const issue of message.items || []) this.log('Findings', `${issue.severity} ${issue.id} | ${issue.file}${issue.line ? ':' + issue.line : ''} | ${issue.description}`);
        break;
      case 'exit':
        this.finished = true; this.live = false; this.exitCode = message.code ?? 1;
        this.phase = this.exitCode ? `Run ended with exit code ${this.exitCode}; review Tool logs` : 'Run complete. Review results, then close the dashboard.';
        this.prompts = []; this.offers.clear(); this.localPrompt = undefined;
        for (const item of this.campaigns.values()) if (['running', 'reviewing', 'ready', 'waiting'].includes(item.status)) {
          item.status = item.status === 'running' ? 'incomplete' : 'expired'; item.reason = 'CLI worker ended.';
        }
        this.activeCampaign = false; this.transition(); break;
      default:
    }
  }
  output(text, stream = 'stdout') {
    for (const line of String(text).split(/\r?\n|\r/)) if (line) this.log(/\[validate\]/.test(cleanText(line)) ? 'Validation' : 'Tool logs', `${stream === 'stderr' ? '[stderr] ' : ''}${line}`);
  }
  answer(answer) {
    const prompt = this.prompt;
    if (!prompt) return;
    if (this.localPrompt) {
      const action = this.localPrompt.action; this.localPrompt = undefined; this.transition();
      if (answer === 'y') action();
    } else {
      this.prompts.shift(); this.transition();
      this.send({ type: 'answer', id: prompt.id, answer });
    }
  }
  endSession() {
    if (!this.live) { this.notice = 'No live session to end. Wait for the current work to finish.'; return; }
    this.localPrompt = { kind: 'confirm', question: this.activeCampaign ? 'End this session? The campaign is still active; coverage and restoration may be incomplete.' : 'End this watch session and collect its results?',
      action: () => { this.live = false; this.send({ type: 'stop-session' }); this.phase = 'Ending session; collecting results…'; } };
    this.transition();
  }
  activate(id) {
    if (id === 'theme') { this.themeIndex = (this.themeIndex + 1) % THEMES.length; return; }
    if (id.startsWith('detail:')) {
      const key = id.slice(7), item = this.campaigns.get(key);
      if (!item || this.prompt) return;
      this.localPrompt = { kind: 'details', campaignKey: key,
        question: `${item.key}\n\nStatus: ${item.status}\nSession: ${item.session}\nCases: ${item.cases || 'Not yet available'}\nFields: ${(item.fields || []).join(', ') || 'Not yet available'}\n\n${item.reason || 'Review the captured content fields and view before approving execution.'}` };
      this.transition(); return;
    }
    if (id === 'detail-run') {
      const item = this.campaigns.get(this.localPrompt?.campaignKey);
      const offer = item && [...this.offers.values()].find(offer => offer.key === item.key && item.session === this.session);
      if (!offer || !this.live || this.activeCampaign) return;
      this.localPrompt = undefined; this.transition(); this.activate(`campaign:${offer.id}`); return;
    }
    if (id.startsWith('tab:')) { this.tab = id.slice(4); return; }
    if (id.startsWith('campaign:')) {
      const offer = this.offers.get(Number(id.slice(9)));
      if (!offer || this.prompt || this.activeCampaign || !this.live) { this.notice = 'This campaign cannot start while another action is pending or the session is inactive.'; return; }
      this.offers.delete(offer.id); this.activeCampaign = true;
      this.receive({ type: 'campaign', key: offer.key, status: 'reviewing' });
      this.transition(); this.send({ type: 'answer', id: offer.id, answer: 'run' });
      this.notice = `Reviewing ${offer.key}. Choose its fields and view, then explicitly approve execution.`;
    }
    if (id === 'cancel') this.answer(undefined);
    if (id === 'approve') this.answer('y');
    if (id === 'submit') this.answer(this.input);
    if (id === 'session-start') this.answer('start');
    if (id === 'session-finish') this.answer('finish');
    if (id === 'end-session') this.endSession();
    if (id === 'quit' && this.finished) this.close();
    if (id === 'folder' && this.folder) this.openFolder(this.folder);
  }
  handle(event, epoch = this.epoch) {
    // A key batch cannot cross a prompt/session transition, including pasted or repeated Enter presses.
    if (epoch !== this.epoch) return;
    const modalIds = this.prompt?.kind === 'session' ? ['session-start', 'session-finish'] : ['input', 'cancel', 'approve', 'submit', 'detail-run'];
    const enabled = this.controls.filter(control => control.enabled !== false && control.id !== 'prompt-scroll' && (!this.prompt || modalIds.includes(control.id)));
    if (event.key === 'mouse') {
      if (event.release) return;
      if ((event.button & 64) !== 0) {
        if (this.prompt) this.scrollPrompt((event.button & 1) ? 3 : -3);
        else if (event.x <= (this.leftWidth || 40)) this.campaignScroll = Math.max(0, Math.min(this.campaigns.size - 1, this.campaignScroll + ((event.button & 1) ? -1 : 1)));
        else this.scrollLog((event.button & 1) ? -3 : 3);
        return;
      }
      const hit = this.controls.findLast(control => event.x >= control.x && event.x < control.x + control.width
        && event.y >= control.y && event.y < control.y + (control.height || 1));
      if ((event.button & 32) !== 0) { this.hover = hit?.id; return; }
      if ((event.button & 3) !== 0) return;
      if (!hit) return;
      if (hit.enabled === false) { this.notice = hit.reason || 'Action is not available yet.'; return; }
      this.focus = hit.id; if (!['input', 'log', 'campaign-list', 'prompt-scroll'].includes(hit.id)) this.activate(hit.id); return;
    }
    if (event.key === 'interrupt') { if (this.finished) this.close(); else this.endSession(); return; }
    if (event.key === 'escape') { if (this.prompt && this.prompt.kind !== 'session') this.answer(undefined); else this.focus = undefined; return; }
    if (['tab', 'backtab', 'left', 'right'].includes(event.key)) {
      const current = enabled.findIndex(control => control.id === this.focus);
      const direction = ['backtab', 'left'].includes(event.key) ? -1 : 1;
      this.focus = enabled[current < 0 ? (direction > 0 ? 0 : enabled.length - 1) : (current + direction + enabled.length) % enabled.length]?.id; return;
    }
    if (event.key === 'enter') {
      if (this.focus === 'input') this.answer(this.input);
      else if (this.focus) this.activate(this.focus);
      else this.notice = 'Choose a button with Tab or the mouse first. No action was started.';
      return;
    }
    if (event.key === 'pageup' || event.key === 'pagedown') {
      if (this.prompt) this.scrollPrompt(event.key === 'pageup' ? -this.promptPage : this.promptPage);
      else this.scrollLog(event.key === 'pageup' ? 10 : -10);
      return;
    }
    if (event.key === 'home' && this.focus === 'log') { this.scroll[this.tab] = Math.max(0, (this.logCounts[this.tab] || this.logs[this.tab].length) - 1); return; }
    if (event.key === 'end' && this.focus === 'log') { this.scroll[this.tab] = 0; return; }
    if (['up', 'down'].includes(event.key)) {
      if (this.focus === 'prompt-scroll') this.scrollPrompt(event.key === 'up' ? -1 : 1);
      else if (this.focus === 'log') this.scrollLog(event.key === 'up' ? 1 : -1);
      else if (this.focus === 'campaign-list') this.campaignScroll = Math.max(0, Math.min(this.campaigns.size - 1, this.campaignScroll + (event.key === 'up' ? 1 : -1)));
      else {
        const current = enabled.findIndex(control => control.id === this.focus);
        this.focus = enabled[(current + (event.key === 'up' ? -1 : 1) + enabled.length) % enabled.length]?.id;
      }
      return;
    }
    if (this.focus === 'input' && event.key === 'backspace') this.input = [...this.input].slice(0, -1).join('');
    if (this.focus === 'input' && ['text', 'paste'].includes(event.key)) this.input = (this.input + event.text).slice(0, 4096);
    if (event.key === 'text' && event.text.toLowerCase() === 't' && this.focus !== 'input' && !this.prompt) this.activate('theme');
    if (event.key === 'text' && event.text.toLowerCase() === 'q' && this.finished && this.focus !== 'input') this.close();
  }
  scrollLog(change) { this.scroll[this.tab] = Math.max(0, Math.min(this.logCounts[this.tab] || this.logs[this.tab].length, this.scroll[this.tab] + change)); }
  scrollPrompt(change) { this.promptScroll = Math.max(0, Math.min(Math.max(0, (this.promptLines || 0) - this.promptPage), this.promptScroll + change)); }
  render(columns = 120, rows = 32, options) { return renderDashboard(this, columns, rows, options); }

}

function attachLines(stream, receive) {
  const decoder = new StringDecoder('utf8');
  let rest = '';
  stream?.on('data', chunk => {
    const lines = (rest + decoder.write(chunk)).split(/\r?\n|\r/); rest = lines.pop();
    for (const line of lines) receive(line);
    if (rest.length > 4096) { receive(rest.slice(0, 4096)); rest = ''; }
  });
  stream?.on('end', () => { const tail = rest + decoder.end(); if (tail) receive(tail); });
}

export function launchWorker(args) {
  // Array arguments survive PowerShell paths, comma lists and header values without shell interpretation.
  return fork(new URL('../index.js', import.meta.url), args, {
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true,
    env: { ...process.env, ELECTRONEGATIVITY_TUI_WORKER: '1', FORCE_COLOR: '0' },
  });
}

export async function runDashboard(args, { input = process.stdin, output = process.stdout, launch = launchWorker } = {}) {
  if (process.platform !== 'win32') throw new Error('--tui currently supports Windows PowerShell; run it in Windows Terminal.');
  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function') throw new Error('--tui needs an interactive Windows terminal; remove output/input redirection.');
  let worker, timer, escapeTimer, stopped = false, resolveClosed;
  const closed = new Promise(resolve => { resolveClosed = resolve; });
  const rawBefore = !!input.isRaw;
  const dashboard = new Dashboard({
    send: message => { if (worker?.connected) worker.send(message, () => {}); },
    close: () => { stopped = true; resolveClosed(); },
    openFolder: folder => {
      const child = spawn('explorer.exe', [folder], { detached: true, stdio: 'ignore', windowsHide: false });
      child.on('error', error => { dashboard.notice = `Cannot open results: ${error.message}`; schedule(); }); child.unref();
    },
  });
  const render = () => {
    timer = undefined;
    if (stopped) return;
    const lines = dashboard.render(output.columns || 120, output.rows || 32);
    output.write(lines.map((line, index) => `\x1b[${index + 1};1H\x1b[2K${line}`).join(''));
  };
  const schedule = () => { if (!timer && !stopped) timer = setTimeout(render, 40); };
  const parser = new TerminalInput(), decoder = new StringDecoder('utf8');
  const handle = events => { const epoch = dashboard.epoch; for (const event of events) dashboard.handle(event, epoch); schedule(); };
  const data = chunk => {
    clearTimeout(escapeTimer);
    handle(parser.feed(typeof chunk === 'string' ? chunk : decoder.write(chunk)));
    if (parser.buffer.startsWith('\x1b') && !parser.buffer.startsWith('\x1b[200~')) escapeTimer = setTimeout(() => handle(parser.feed('', true)), 60);
  };
  const interrupt = () => { dashboard.handle({ key: 'interrupt' }); schedule(); };
  const restore = () => { try { input.setRawMode(rawBefore); output.write(LEAVE_SCREEN); } catch { /* terminal disconnected */ } };
  try {
    input.setRawMode(true); output.write(ENTER_SCREEN);
    input.on('data', data); input.resume(); output.on('resize', schedule);
    process.on('SIGINT', interrupt); process.once('exit', restore);
    render();
    worker = launch(args);
    worker.on('message', message => { dashboard.receive(message); schedule(); });
    attachLines(worker.stdout, line => { dashboard.output(line); schedule(); });
    attachLines(worker.stderr, line => { dashboard.output(line, 'stderr'); schedule(); });
    worker.once('error', error => { dashboard.output(error.message, 'stderr'); dashboard.receive({ type: 'exit', code: 1 }); schedule(); });
    worker.once('exit', (code, signal) => { dashboard.receive({ type: 'exit', code: code ?? (signal ? 1 : 0) }); schedule(); });
    await closed;
    return { code: dashboard.exitCode ?? 1, folder: dashboard.folder };
  } finally {
    stopped = true; clearTimeout(timer); clearTimeout(escapeTimer);
    input.removeListener('data', data); input.pause(); output.removeListener('resize', schedule);
    process.removeListener('SIGINT', interrupt); process.removeListener('exit', restore); restore();
    if (worker?.connected) worker.disconnect();
  }
}
